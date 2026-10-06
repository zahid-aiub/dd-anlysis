"""Rules on the device state and the test flow: disturbed GFM-A, preconditions, cascades, aborts, manual actions."""

from trace_analyzer.model import (
    AnalysisContext,
    Belegung,
    Direction,
    EventKind,
    FailureCategory,
    Finding,
    Severity,
    TestCaseResult,
    TraceEvent,
    Verdict,
)

from .base import BaseRule
from .common import (
    COMMANDS,
    finding,
    gfma_status,
    main_part_start,
    spec_target_state,
    state,
    status_at,
    target_state,
    telegrams,
)

C = FailureCategory
PRECURSOR_WINDOW_S = 1.0     # an anomalous report this close before the disturbance counts as its precursor
EFFECT_WINDOW_S = 2.0        # a manual command without a status change in this window had no effect
PANEL_BAN = "Kein AZG/AZGH am Panel senden"


def _cleanup_failed(tc: TestCaseResult) -> bool:
    return any(s.verdict is Verdict.FAIL and s.section == "Completion" for s in tc.steps)


def _in_case(statuses: list[TraceEvent], tc: TestCaseResult) -> list[TraceEvent]:
    return [s for s in statuses if tc.start <= s.time < tc.end]


class DeviceStateRule(BaseRule):
    """GFM-A reports Belegungszustand 'gestört': on the transition, and once per test case if inherited."""

    name = "device_state"
    categories = (C.DEVICE_DISTURBED,)

    def applies_to(self, tc: TestCaseResult, ctx: AnalysisContext) -> bool:
        return bool(_in_case(gfma_status(ctx), tc))

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        by_element: dict[str | None, list[TraceEvent]] = {}
        for s in gfma_status(ctx):
            by_element.setdefault(s.sender, []).append(s)
        findings = []
        for element, statuses in by_element.items():
            reported, previous = set(), None
            for i, s in enumerate(statuses):
                disturbed = s.fields["belegung"] == Belegung.GESTOERT
                transition = disturbed and (previous is None or previous.fields["belegung"] != Belegung.GESTOERT)
                tc = ctx.test_case_at(s.time)
                key = tc.name if tc else None
                if disturbed and (transition or key not in reported):
                    findings.append(self._finding(ctx, statuses, i, previous, transition))
                    reported.add(key)
                previous = s
        return sorted(findings, key=lambda f: f.time)

    def _finding(self, ctx: AnalysisContext, statuses: list[TraceEvent], i: int,
                 previous: TraceEvent | None, transition: bool) -> Finding:
        s = statuses[i]
        element = s.sender or "GFM-A"
        evidence, details = [s], {"element": element, "inherited": not transition}

        precursor = None
        if transition and previous and s.time - previous.time <= PRECURSOR_WINDOW_S:
            bel, _, fill = state(previous)
            if bel == Belegung.BELEGT and fill == 0:
                precursor = previous
                details["precursor"] = {"time": previous.time, "state": list(state(previous))}
                evidence.insert(0, previous)

        # periods while still disturbed in which a reset was possible (Grundstellbarkeit = 1)
        windows, start = [], None
        for later in statuses[i:]:
            if later.fields["belegung"] != Belegung.GESTOERT:
                if start is not None:
                    windows.append((start, later.time))
                break
            if later.fields["grundstellbar"] == 1 and start is None:
                start = later.time
            elif later.fields["grundstellbar"] == 0 and start is not None:
                windows.append((start, later.time))
                start = None
        resets = [c for a, b in windows for c in telegrams(ctx, COMMANDS, Direction.TX, a, b)]
        details["reset_windows"] = windows
        details["resets_in_window"] = [c.time for c in resets]

        if not transition:
            summary = f"{element} still disturbed (Belegungszustand 3) at {s.time:.3f} s, inherited from earlier"
        elif precursor:
            summary = (f"{element} became disturbed (Belegungszustand 3) {1000 * (s.time - precursor.time):.0f} ms "
                       f"after an occupied report with Achszählfüllstand 0x0000")
        else:
            summary = f"{element} became disturbed (Belegungszustand 3)"
        if windows and not resets:
            summary += f"; reset possible for {sum(b - a for a, b in windows):.0f} s but no AZG/AZGH sent"
        return finding(ctx, C.DEVICE_DISTURBED, Severity.ERROR, summary, s.time, evidence, 0.95, **details)


class PreconditionRule(BaseRule):
    """The GFM-A was not in the state the test requires.

    Target state: the Test_Description precondition, else the report's "Sollzustand". Two cases:
    a preparation step failed (the test never reached its main part), or the main part started although the
    actual state differs from the Test_Description precondition.
    """

    name = "precondition"
    categories = (C.PRECONDITION_NOT_REACHED,)

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        statuses = gfma_status(ctx)
        findings = []
        for tc in ctx.test_cases:
            spec = ctx.specs.get(tc.test_id)
            spec_target, report_target = spec_target_state(spec), target_state(tc)
            target = spec_target or report_target
            source = "Test_Description" if spec_target else "report"
            failed = [s for s in tc.steps if s.verdict is Verdict.FAIL and s.section == "Preparation"]
            if failed:
                step = failed[0]
                actual = status_at(statuses, step.time)
                summary = f"Precondition not reached: {step.title}"
                if target and actual:
                    summary = (f"Precondition not reached: target Belegung/Grundstellbarkeit {target[0]}/{target[1]} "
                               f"({source}), actual {actual.fields['belegung']}/{actual.fields['grundstellbar']}")
                findings.append(self._finding(ctx, tc, summary, step.time, [step.ref], actual, target, source,
                                              step=step.title, cleanup_failed=_cleanup_failed(tc)))
                continue
            start = main_part_start(tc)
            if spec_target is None or start is None:
                continue
            actual = status_at(statuses, start)
            if actual is not None and state(actual)[:2] != spec_target:
                findings.append(self._finding(
                    ctx, tc, f"Main part started in state {actual.fields['belegung']}/"
                             f"{actual.fields['grundstellbar']}, the Test_Description precondition requires "
                             f"{spec_target[0]}/{spec_target[1]} (\"{spec.precondition}\")",
                    start, [spec.ref], actual, spec_target, source, precondition=spec.precondition))
        return findings

    @staticmethod
    def _finding(ctx: AnalysisContext, tc: TestCaseResult, summary: str, t: float, refs, actual: TraceEvent | None,
                 target: tuple[int, int] | None, source: str, **details) -> Finding:
        evidence = [r for r in (*refs, actual.ref if actual else None) if r]
        return finding(ctx, C.PRECONDITION_NOT_REACHED, Severity.ERROR, summary, t, evidence, test_case=tc.name,
                       target=list(target) if target else None, target_source=source,
                       actual=list(state(actual)) if actual else None, **details)


class TestStepRule(BaseRule):
    """A main-part step failed (the symptom; protocol rules may explain it)."""

    __test__ = False
    name = "test_step"
    categories = (C.TEST_STEP_FAILED,)

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        findings = []
        for tc in ctx.test_cases:
            failed = [s for s in tc.steps if s.verdict is Verdict.FAIL and s.section == "Main Part"]
            if failed:
                step = failed[0]
                findings.append(finding(ctx, C.TEST_STEP_FAILED, Severity.ERROR,
                                        f"Step {step.step} failed: {step.title}", step.time,
                                        [step.ref] if step.ref else [], test_case=tc.name,
                                        spec_step=int(step.step) if step.step.isdigit() else None,
                                        cleanup_failed=_cleanup_failed(tc)))
        return findings


class CascadeRule(BaseRule):
    """A test case starts in the bad state the previous test case's failed cleanup left behind."""

    name = "cascade"
    categories = (C.CASCADE_FAILURE,)

    def applies_to(self, tc: TestCaseResult, ctx: AnalysisContext) -> bool:
        return bool(ctx.test_cases) and tc is not ctx.test_cases[0]

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        statuses = gfma_status(ctx)
        findings = []
        for previous, tc in zip(ctx.test_cases, ctx.test_cases[1:]):
            cleanup_failed = _cleanup_failed(previous)
            first = next(iter(_in_case(statuses, tc)), None)
            bad_start = first is not None and first.fields["belegung"] in (Belegung.GESTOERT, Belegung.UNGUELTIG)
            if cleanup_failed and bad_start:
                severity, confidence = Severity.ERROR, 0.9
            elif bad_start and previous.verdict is Verdict.FAIL:
                severity, confidence = Severity.ERROR, 0.7
            elif cleanup_failed and tc.verdict is not Verdict.PASS:
                severity, confidence = Severity.WARNING, 0.5
            else:
                continue
            start_state = f"{first.fields['belegung']}/{first.fields['grundstellbar']}" if first else "unknown"
            summary = (f"Started in state {start_state} left by {previous.name}"
                       + (" (its cleanup failed)" if cleanup_failed else ""))
            evidence = [first] if first else []
            evidence += [s.ref for s in previous.steps if s.verdict is Verdict.FAIL and s.section == "Completion" and s.ref][:1]
            findings.append(finding(ctx, C.CASCADE_FAILURE, severity, summary, tc.start, evidence, confidence,
                                    test_case=tc.name, caused_by=previous.name, cleanup_failed=cleanup_failed,
                                    state_at_start=list(state(first)) if first else None))
        return findings


class AbortRule(BaseRule):
    """Test execution stopped (test unit stopped by the user, measurement stopped)."""

    name = "abort"
    categories = (C.TEST_ABORTED,)
    MARKERS = ("stop of the test unit", "Execution stop forced", "Measurement stop forced")

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        findings = []
        for tc in ctx.test_cases:
            evidence: list[tuple[float, object, str]] = []
            for e in ctx.events:
                if not tc.start <= e.time <= tc.end + 0.01:
                    continue
                text = str(e.fields.get("text", ""))
                if e.kind is EventKind.TEST and e.fields.get("action") == "abort":
                    evidence.append((e.time, e, text))
                elif e.kind is EventKind.LOG and any(m in text for m in self.MARKERS):
                    evidence.append((e.time, e, text))
            evidence += [(s.time, s.ref, s.title) for s in tc.steps if any(m in s.title for m in self.MARKERS) and s.ref]
            if not evidence:
                continue
            evidence.sort(key=lambda x: x[0])
            user_stop = any(m in text for _, _, text in evidence for m in self.MARKERS[:2])
            findings.append(finding(
                ctx, C.TEST_ABORTED, Severity.ERROR,
                "Test execution stopped: test unit stopped by the user" if user_stop else "Test execution aborted",
                evidence[0][0], [x for _, x, _ in evidence], test_case=tc.name,
                detail="test_unit_stopped_by_user" if user_stop else "aborted"))
        return findings


class ManualInterventionRule(BaseRule):
    """Operator actions on the CANoe panel, flagged when the test instruction forbids them."""

    name = "manual_intervention"
    categories = (C.MANUAL_INTERVENTION,)

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        statuses = gfma_status(ctx)
        findings = []
        for e in ctx.events:
            if e.kind is not EventKind.OPERATOR_ACTION or not e.fields.get("value"):
                continue
            tc = ctx.test_case_at(e.time)
            command = e.fields.get("command")
            forbidden = bool(tc and command and any(PANEL_BAN in s.title for s in tc.steps if s.time <= e.time))
            sent = telegrams(ctx, COMMANDS, Direction.TX, e.time, e.time + 0.1)
            changed = [s for s in statuses if e.time < s.time <= e.time + EFFECT_WINDOW_S]
            label = command or e.name
            summary = f"Manual {label} from the CANoe panel"
            if forbidden:
                summary += " although the test instruction says not to use the panel"
            if command:
                summary += "; no GFM-A status change followed" if not changed else "; GFM-A status changed"
            findings.append(finding(
                ctx, C.MANUAL_INTERVENTION, Severity.WARNING if forbidden else Severity.INFO, summary, e.time,
                [e, *sent], action=e.name, command=command, forbidden=forbidden, effect=bool(changed)))
        return findings

