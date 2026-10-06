"""Turn an analysis result into what the report shows: one section per test case, plus run information."""

from dataclasses import dataclass, field
from datetime import datetime

from trace_analyzer.model import (
    Diagnosis,
    Direction,
    EventKind,
    EvidenceRef,
    FailureCategory,
    Finding,
    RastaType,
    Severity,
    Source,
    TestCaseResult,
    TraceEvent,
    Verdict,
)
from trace_analyzer.pipeline import AnalysisResult
from trace_analyzer.rules.common import STATUS_FIELDS

C = FailureCategory

# What kind of problem a cause category points to (the "Category" line of the report)
AREA = {
    C.DEVICE_DISTURBED: "Field element / test bench state",
    C.PRECONDITION_NOT_REACHED: "Field element / test bench state",
    C.CASCADE_FAILURE: "Test sequence: state left by the previous test case",
    C.TEST_ABORTED: "Test execution",
    C.MANUAL_INTERVENTION: "Test execution: operator",
    C.CONNECTION_INTERRUPTION: "Communication: RaSTA connection",
    C.SEQUENCE_ERROR: "Communication: RaSTA connection",
    C.CONFIGURATION_MISMATCH: "Configuration / test specification",
    C.TIME_ALIGNMENT: "Data quality: source alignment",
    C.TEST_STEP_FAILED: "Test step (no explanation found)",
}
PROTOCOL = (C.TIMEOUT, C.MISSING_MESSAGE, C.UNEXPECTED_RESPONSE, C.WRONG_ORDER, C.INVALID_PAYLOAD,
            C.INCORRECT_LENGTH, C.COMMAND_REJECTED)
SOURCE_NAMES = {Source.PCAPNG: "pcapng", Source.BLF: "BLF", Source.PDF_REPORT: "PDF report",
                Source.CANOE_LOG: "CANoe log", Source.TEST_SPEC: "Test_Description"}
STEP_NOISE = ("Resumed on value",)
# run metadata shown in the report (user and computer names are left out)
REPORT_METADATA = ("configuration", "canoe_version")


def area(category: FailureCategory) -> str:
    return "SCI-TDS protocol" if category in PROTOCOL else AREA.get(category, category.value)


def confidence_label(value: float) -> str:
    return "high" if value >= 0.85 else "medium" if value >= 0.6 else "low"


@dataclass(frozen=True, slots=True)
class EvidenceLine:
    ref: EvidenceRef
    time: float | None = None
    clock: str | None = None          # wall-clock time of the test bench

    def __str__(self) -> str:
        when = f" at {self.time:.3f} s" + (f" ({self.clock})" if self.clock else "") if self.time is not None else ""
        return f"{SOURCE_NAMES.get(self.ref.source, self.ref.source.value)}: {self.ref.file} {self.ref.locator}{when}"


@dataclass(frozen=True, slots=True)
class FindingView:
    finding: Finding
    role: str                          # "cause", "symptom", "contributing"
    evidence: tuple[EvidenceLine, ...]

    @property
    def category(self) -> str:
        return self.finding.category.value

    @property
    def time(self) -> float | None:
        return self.finding.time


@dataclass(frozen=True, slots=True)
class EventRow:
    time: float
    lane: str                          # "tx", "rx", "step", "operator", "rasta", "log", "test"
    text: str
    evidence: str
    status: str = ""                   # "pass", "fail", "" — for test steps


@dataclass(slots=True)
class CaseReport:
    test_case: TestCaseResult
    diagnosis: Diagnosis
    symptom: FindingView | None
    cause: FindingView | None
    contributing: list[FindingView]
    ruled_out: list[str]
    events: list[EventRow]
    consequence: str | None = None
    precondition: str | None = None
    target_state: str | None = None
    sources: list[str] = field(default_factory=list)   # sources that support the cause
    timeline_svg: str = ""

    @property
    def name(self) -> str:
        return self.test_case.name

    @property
    def report_verdict(self) -> Verdict:
        return self.test_case.verdict

    @property
    def verdict(self) -> Verdict:
        return self.diagnosis.verdict

    @property
    def headline(self) -> str:
        labels = {Verdict.PASS: "PASSED", Verdict.FAIL: "FAILED", Verdict.INCONCLUSIVE: "INCONCLUSIVE",
                  Verdict.ERROR: "ERROR", Verdict.NONE: "NO VERDICT"}
        text = labels[self.verdict]
        if self.verdict is not self.report_verdict:
            text += f" (report: {labels[self.report_verdict].lower()})"
        return text

    @property
    def separate_cause(self) -> bool:
        """The cause is a finding of its own, not the symptom explaining itself."""
        return self.cause is not None and (self.symptom is None or self.cause.finding is not self.symptom.finding)

    @property
    def evidence_views(self) -> list[FindingView]:
        views = [v for v in (self.cause, self.symptom) if v is not None]
        return views if self.separate_cause else views[:1]

    @property
    def timeline_file(self) -> str:
        return f"timeline_{self.anchor}.svg"

    @property
    def anchor(self) -> str:
        return self.test_case.test_id.replace(".", "-").lower()


@dataclass(slots=True)
class RunReport:
    title: str
    generated: datetime
    measurement_start: datetime | None
    metadata: dict
    sources: list[tuple[str, str, str]]          # (source, file, alignment)
    checks: list[str]
    cases: list[CaseReport]
    run_findings: list[FindingView]              # findings outside any test case


def _clock(result: AnalysisResult, t: float | None) -> str | None:
    if t is None:
        return None
    absolute = result.timeline.absolute(t)
    return absolute.strftime("%H:%M:%S.%f")[:-3] if absolute else None


def _evidence(result: AnalysisResult, f: Finding) -> tuple[EvidenceLine, ...]:
    """Evidence references with the time of the event each one points to, where the timeline has it."""
    by_ref = {}
    for e in result.context.events:
        by_ref.setdefault((e.ref.file, e.ref.locator), e.time)
    lines = []
    for ref in f.evidence:
        if ref.source in (Source.PDF_REPORT, Source.TEST_SPEC):
            t = f.time    # a page or row holds many steps: only the finding knows which instant it means
        else:
            # a frame missing from the timeline is a dropped duplicate of a frame at the finding's time
            t = by_ref.get((ref.file, ref.locator), f.time if ref.source in (Source.PCAPNG, Source.BLF) else None)
        lines.append(EvidenceLine(ref, t, _clock(result, t)))
    return tuple(lines)


def _view(result: AnalysisResult, f: Finding | None, role: str) -> FindingView | None:
    return FindingView(f, role, _evidence(result, f)) if f is not None else None


def _status_text(e: TraceEvent) -> str:
    if not all(k in e.fields for k in STATUS_FIELDS):
        return ""
    return (f" {e.fields['belegung']}/{e.fields['grundstellbar']}/0x{e.fields['achszaehlfuellstand']:04X}"
            f" (Belegung/Grundstellbarkeit/Achszählfüllstand)")


def _fields_text(e: TraceEvent) -> str:
    if all(k in e.fields for k in STATUS_FIELDS):
        return _status_text(e)
    shown = {k: v for k, v in e.fields.items()
             if k not in ("protocol_type", "duplicate_ref", "differs_from", "checksum", "decode_error")}
    return " " + ", ".join(f"{k}={v}" for k, v in shown.items()) if shown else ""


def key_events(result: AnalysisResult, tc: TestCaseResult) -> list[EventRow]:
    """What happened in the test case window: telegrams, connection, steps, operator actions, stop messages."""
    rows = []
    for e in result.context.window(tc.start, tc.end + 1e-9):
        where = str(e.ref)
        if e.kind is EventKind.SCI_TELEGRAM:
            arrow = "ZE → AZ" if e.direction is Direction.TX else "AZ → ZE"
            rows.append(EventRow(e.time, e.direction.value, f"{arrow} {e.name} ({e.length} bytes){_fields_text(e)}",
                                 where))
        elif e.kind is EventKind.RASTA and e.msg_type in (RastaType.CONNECTION_REQUEST, RastaType.CONNECTION_RESPONSE,
                                                          RastaType.DISCONNECTION_REQUEST):
            reason = f", reason {e.fields['reason']}" if "reason" in e.fields else ""
            rows.append(EventRow(e.time, "rasta", f"RaSTA {e.name.lower().replace('_', ' ')} "
                                                  f"({e.direction.value.upper()}){reason}", where))
        elif e.kind is EventKind.OPERATOR_ACTION:
            what = e.fields.get("command") or f"{e.name} = {e.fields.get('value')}"
            rows.append(EventRow(e.time, "operator", f"Manual action on the CANoe panel: {what}", where))
        elif e.kind is EventKind.LOG and "text" in e.fields:
            rows.append(EventRow(e.time, "log", f"CANoe log ({e.fields.get('level', '')}): {e.fields['text']}", where))
    for s in tc.steps:
        if s.title.startswith(STEP_NOISE):
            continue
        status = s.verdict.value if s.verdict in (Verdict.PASS, Verdict.FAIL, Verdict.INCONCLUSIVE) else ""
        label = f"{s.section}{' ' + s.step if s.step else ''}: {s.title}"
        rows.append(EventRow(s.time, "step", label, str(s.ref) if s.ref else "", status))
    return sorted(rows, key=lambda r: (r.time, r.lane != "step"))


def _consequence(result: AnalysisResult, tc: TestCaseResult) -> str | None:
    later = [f for f in result.findings
             if f.category is C.CASCADE_FAILURE and f.details.get("caused_by") == tc.name]
    if later:
        return f"Cleanup failed, so {later[0].test_case} started in the state this test case left (cascade failure)."
    return None


def case_report(result: AnalysisResult, d: Diagnosis) -> CaseReport:
    from trace_analyzer.rules.common import spec_target_state, target_state

    tc = d.test_case
    symptom, cause = _view(result, d.symptom, "symptom"), _view(result, d.cause, "cause")
    contributing = [FindingView(f, "contributing", _evidence(result, f)) for f in d.contributing]
    contributing.sort(key=lambda v: ({Severity.ERROR: 0, Severity.WARNING: 1}.get(v.finding.severity, 2),
                                     v.time if v.time is not None else tc.start))
    spec = result.context.specs.get(tc.test_id)
    target = spec_target_state(spec) or target_state(tc)
    sources = sorted({SOURCE_NAMES[r.source] for r in (d.cause.evidence if d.cause else ())})
    if d.cause is not None and d.cause.category is C.DEVICE_DISTURBED:
        # the same status reports are in the BLF variables and the CANoe log (consistency checks)
        sources = sorted(set(sources) | {SOURCE_NAMES[s] for c in result.context.checks
                                         if c.name == "gfma_status" and c.unmatched == 0 for s in c.sources})
    return CaseReport(
        test_case=tc, diagnosis=d, symptom=symptom, cause=cause, contributing=contributing,
        ruled_out=[c.value for c in d.ruled_out], events=key_events(result, tc),
        consequence=_consequence(result, tc),
        precondition=spec.precondition if spec else None,
        target_state=f"{target[0]}/{target[1]}" if target else None,
        sources=sources,
    )


def build_report(result: AnalysisResult, test_ids: list[str] | None = None) -> RunReport:
    ctx = result.context
    cases = [case_report(result, d) for d in result.diagnoses
             if not test_ids or any(t in d.test_case.name for t in test_ids)]
    files = {}
    for e in ctx.events:
        files.setdefault(e.source, e.ref.file)
    for tc in ctx.test_cases:
        if tc.ref:
            files.setdefault(tc.ref.source, tc.ref.file)
    for spec in ctx.specs.values():
        if spec.ref:
            files.setdefault(Source.TEST_SPEC, "Test_Description/")
    sources = []
    for source, alignment in ctx.alignments.items():
        how = "native measurement time" if alignment.method == "native" else (
            f"{alignment.method}, offset {alignment.offset:.6f} s, spread {alignment.spread * 1000:.3f} ms, "
            f"{alignment.samples} samples")
        sources.append((SOURCE_NAMES.get(source, source.value), files.get(source, "-"), how))
    checks = [f"{c.name}: {c.sources[0].value} vs. {c.sources[1].value}, {c.matched} matched, "
              f"max difference {c.max_difference * 1000:.3f} ms, {c.unmatched} unmatched" for c in ctx.checks]
    if ctx.merge is not None:
        m = ctx.merge
        checks.append(f"network merge: {m.matched_frames} identical frames in {m.primary.value} and "
                      f"{m.secondary.value if m.secondary else '-'}, {len(m.differing)} recorded differently, "
                      f"{len(m.only_in_primary)} only in {m.primary.value}, {len(m.only_in_secondary)} only in "
                      f"{m.secondary.value if m.secondary else '-'}")
    run_findings = [FindingView(f, "run", _evidence(result, f)) for f in result.findings if f.test_case is None]
    metadata = {k: ctx.metadata[k] for k in REPORT_METADATA if ctx.metadata.get(k)}
    return RunReport("Trace failure analysis", datetime.now().astimezone(), ctx.metadata.get("measurement_start"),
                     metadata, sources, checks, cases, run_findings)
