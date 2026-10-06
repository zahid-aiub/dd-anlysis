"""Rules on SCI-TDS telegram content, order and request/response timing."""

import re

from trace_analyzer.model import (
    Abweisungsgrund,
    AnalysisContext,
    Direction,
    EventKind,
    FailureCategory,
    Finding,
    SciMessage,
    Severity,
    TestCaseResult,
    TraceEvent,
)

from trace_analyzer.readers.decode import bl5_length

from .base import BaseRule, NetworkRule
from .common import COMMANDS, FIELD_RANGES, expected_length, finding, is_known_message, message_name, telegrams

C = FailureCategory


def _timeout(ctx: AnalysisContext) -> float:
    return ctx.config.get("timing", {}).get("response_timeout_ms", 500) / 1000


class ProtocolResponseRule(NetworkRule):
    """Connection start-up requests must be answered: version check, Aufrüstung."""

    name = "protocol_response"
    categories = (C.TIMEOUT, C.MISSING_MESSAGE)
    PAIRS = {
        SciMessage.KOMMANDO_BTP_VERSIONSABGLEICH: SciMessage.MELDUNG_BTP_VERSIONSABGLEICH,
        SciMessage.KOMMANDO_AUFRUESTANFORDERUNG: SciMessage.MELDUNG_AUFRUESTBEGINN,
        SciMessage.MELDUNG_AUFRUESTBEGINN: SciMessage.MELDUNG_AUFRUESTENDE,
    }

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        limit = _timeout(ctx)
        findings = []
        for session in ctx.sessions:
            end = session.end + 1e-9
            for request in telegrams(ctx, self.PAIRS, start=session.start, end=end):
                expected = self.PAIRS[request.msg_type]
                response = next(iter(telegrams(ctx, expected, Direction.RX, request.time, end)), None)
                if response is None:
                    findings.append(finding(
                        ctx, C.MISSING_MESSAGE, Severity.ERROR,
                        f"No {message_name(expected)} after {message_name(request.msg_type)}", request.time, [request],
                        expected=message_name(expected), session=session.index))
                elif (delay := response.time - request.time) > limit:
                    findings.append(finding(
                        ctx, C.TIMEOUT, Severity.ERROR,
                        f"{message_name(expected)} after {delay * 1000:.0f} ms (limit {limit * 1000:.0f} ms)",
                        request.time, [request, response], delay_s=delay, limit_s=limit, session=session.index))
        return findings


_HEX = re.compile(r"^0x[0-9A-Fa-f]+$")


def byte_mismatches(raw: bytes, expected_bytes: dict[str, str]) -> list[str]:
    """Compare literal 'BTP[i]' / 'BTP[i..j]' expectations (little-endian) with a telegram."""
    problems = []
    for key, value in expected_bytes.items():
        if not _HEX.match(value):
            continue   # placeholders such as <ANY> or <<<P_GF_BEZ>>>
        first, _, last = key.partition("..")
        start, stop = int(first), int(last or first)
        if stop >= len(raw):
            problems.append(f"BTP[{key}] expected {value}, telegram has only {len(raw)} bytes")
            continue
        actual = int.from_bytes(raw[start:stop + 1], "little")
        if actual != int(value, 16):
            problems.append(f"BTP[{key}] expected {value}, got 0x{actual:0{2 * (stop - start + 1)}X}")
    return problems


class SpecExpectationRule(BaseRule):
    """Expected and forbidden telegrams of the Test_Description after the test's trigger command."""

    name = "spec_expectation"
    categories = (C.TIMEOUT, C.MISSING_MESSAGE, C.UNEXPECTED_RESPONSE)

    def _trigger(self, tc: TestCaseResult, ctx: AnalysisContext):
        spec = ctx.specs.get(tc.test_id)
        if spec is None:
            return None, None
        send = next((s for s in spec.steps if s.interface == "BTP" and s.direction.startswith("ZE")
                     and s.message_type is not None and not s.expect_absent), None)
        if send is None:
            return spec, None
        step = next((s for s in tc.steps if s.section == "Main Part" and s.step == str(send.number)
                     and s.title.startswith("Sende")), None)
        if step is None:
            return spec, None
        sent = telegrams(ctx, send.message_type, Direction.TX, step.time - 0.01, step.time + 0.1)
        return spec, (send, sent[0]) if sent else None

    def applies_to(self, tc: TestCaseResult, ctx: AnalysisContext) -> bool:
        return self._trigger(tc, ctx)[1] is not None

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        findings = []
        for tc in ctx.test_cases:
            spec, trigger = self._trigger(tc, ctx)
            if trigger is None:
                continue
            send, t1 = trigger
            next_command = next(iter(telegrams(ctx, COMMANDS, Direction.TX, t1.time + 1e-6, tc.end)), None)
            horizon = next_command.time if next_command else tc.end
            for step in spec.steps:
                if step.number <= send.number or step.message_type is None or step.interface != "BTP":
                    continue
                limit = step.max_delay_s or _timeout(ctx)
                candidates = telegrams(ctx, step.message_type, Direction.RX, t1.time, horizon)
                in_time = [c for c in candidates if c.time - t1.time <= limit]
                common = dict(test_case=tc.name, spec_step=step.number, limit_s=limit)
                if step.expect_absent:
                    if in_time:
                        findings.append(finding(
                            ctx, C.UNEXPECTED_RESPONSE, Severity.ERROR,
                            f"{message_name(step.message_type)} received {(in_time[0].time - t1.time) * 1000:.0f} ms after "
                            f"{message_name(send.message_type)}; step {step.number} requires it NOT to be sent",
                            in_time[0].time, [t1, *in_time], 0.9, **common))
                elif in_time:
                    problems = byte_mismatches(in_time[0].raw or b"", step.expected_bytes)
                    if problems:
                        findings.append(finding(
                            ctx, C.INVALID_PAYLOAD, Severity.ERROR,
                            f"{message_name(step.message_type)} differs from step {step.number}: {problems[0]}",
                            in_time[0].time, [t1, in_time[0]], 0.8, problems=problems, **common))
                elif candidates:
                    delay = candidates[0].time - t1.time
                    findings.append(finding(
                        ctx, C.TIMEOUT, Severity.ERROR,
                        f"{message_name(step.message_type)} after {delay * 1000:.0f} ms, step {step.number} allows "
                        f"{limit * 1000:.0f} ms", t1.time, [t1, candidates[0]], 0.9, delay_s=delay, **common))
                else:
                    findings.append(finding(
                        ctx, C.MISSING_MESSAGE, Severity.ERROR,
                        f"No {message_name(step.message_type)} after {message_name(send.message_type)} (step {step.number})",
                        t1.time, [t1], 0.9, **common))
        return findings


class OrderRule(NetworkRule):
    """Connection start-up order: version check → Aufrüstanforderung → Aufrüstbeginn → reports → Aufrüstende."""

    name = "order"
    categories = (C.WRONG_ORDER,)
    STARTUP = [(Direction.TX, SciMessage.KOMMANDO_BTP_VERSIONSABGLEICH),
               (Direction.RX, SciMessage.MELDUNG_BTP_VERSIONSABGLEICH),
               (Direction.TX, SciMessage.KOMMANDO_AUFRUESTANFORDERUNG),
               (Direction.RX, SciMessage.MELDUNG_AUFRUESTBEGINN)]
    END = (Direction.RX, SciMessage.MELDUNG_AUFRUESTENDE)

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        findings = []
        for session in ctx.sessions:
            problem = self._first_violation(telegrams(ctx, start=session.start, end=session.end + 1e-9))
            if problem:
                event, text = problem
                findings.append(finding(ctx, C.WRONG_ORDER, Severity.ERROR, text, event.time, [event],
                                        session=session.index))
        return findings

    def _first_violation(self, events: list[TraceEvent]) -> tuple[TraceEvent, str] | None:
        position, done = 0, False
        startup_keys = set(self.STARTUP) | {self.END}
        for e in events:
            key = (e.direction, e.msg_type)
            if done:
                if key in startup_keys:
                    return e, f"{message_name(e.msg_type)} after the start-up had completed"
                continue
            if position < len(self.STARTUP):
                if key == self.STARTUP[position]:
                    position += 1
                elif key in startup_keys or e.msg_type in COMMANDS:
                    return e, f"{message_name(e.msg_type)} before {message_name(self.STARTUP[position][1])}"
            elif key == self.END:
                done = True
            elif e.direction is Direction.TX and e.msg_type in COMMANDS:
                return e, f"{message_name(e.msg_type)} sent before {message_name(self.END[1])}"
        return None


class PayloadRule(NetworkRule):
    """Field values outside their BL5 value range, wrong protocol type, unknown type, wrong identifiers."""

    name = "payload"
    categories = (C.INVALID_PAYLOAD,)

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        own_id = str(ctx.config.get("nodes", {}).get("test_system", {}).get("id", "")) or None
        findings = []
        for e in telegrams(ctx):
            problems = []
            if e.fields.get("protocol_type") != 0x20:
                problems.append(f"protocol type 0x{e.fields.get('protocol_type', 0):02x} instead of 0x20 (TDS)")
            if not is_known_message(e.msg_type):
                problems.append(f"unknown message type 0x{e.msg_type:04x}")
            problems += [f"{field}={e.fields[field]} outside {sorted(allowed)}"
                         for field, allowed in FIELD_RANGES.items() if field in e.fields and e.fields[field] not in allowed]
            if own_id and e.direction is Direction.TX and e.sender != own_id:
                problems.append(f"sender '{e.sender}' is not the test system '{own_id}'")
            if own_id and e.direction is Direction.RX and e.receiver != own_id:
                problems.append(f"receiver '{e.receiver}' is not the test system '{own_id}'")
            if problems:
                findings.append(finding(ctx, C.INVALID_PAYLOAD, Severity.ERROR,
                                        f"{e.name}: {problems[0]}", e.time, [e], problems=problems))
        for tc in ctx.test_cases:
            for step in tc.steps:
                failed = [c for c in step.checks if not c.passed and c.index != "Laenge"]
                if failed:
                    c = failed[0]
                    findings.append(finding(
                        ctx, C.INVALID_PAYLOAD, Severity.ERROR,
                        f"Report validation failed: {c.field} [{c.index}] actual {c.actual}, expected {c.expected}",
                        step.time, [step.ref] if step.ref else [], test_case=tc.name,
                        checks=[(x.field, x.index, x.actual, x.expected) for x in failed]))
        if ctx.merge is not None:
            for d in ctx.merge.differing:
                if d.primary_length == d.secondary_length:
                    findings.append(finding(
                        ctx, C.INVALID_PAYLOAD, Severity.ERROR,
                        f"{d.name or 'Frame'} differs between {d.primary.file} {d.primary.locator} and "
                        f"{d.secondary.file} {d.secondary.locator} from byte {d.first_difference} on",
                        d.time, [d.primary, d.secondary], 0.9, first_difference=d.first_difference))
        return findings


class LengthRule(NetworkRule):
    """Length differs between sender and receiver side.

    - a telegram is not as long as the BL5 layout of its type (what the receiver decodes),
    - the Test_Description expects bytes beyond the telegram the device sends (e.g. BL6/BL7 48-byte status vs.
      BL5 47 bytes): the test step cannot pass,
    - the two captures recorded the same frame with different lengths,
    - truncated RaSTA messages, failed length checks in the report.
    """

    name = "length"
    categories = (C.INCORRECT_LENGTH,)

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        findings = []
        for e in telegrams(ctx):
            expected = expected_length(e.msg_type, e.fields)
            if expected is not None and e.length != expected:
                findings.append(finding(ctx, C.INCORRECT_LENGTH, Severity.ERROR,
                                        f"{e.name}: {e.length} bytes, BL5 layout has {expected}", e.time, [e],
                                        actual=e.length, expected=expected))
        for e in ctx.events:
            if e.kind is EventKind.RASTA and "decode_error" in e.fields:
                findings.append(finding(ctx, C.INCORRECT_LENGTH, Severity.ERROR,
                                        f"RaSTA {e.name}: {e.fields['decode_error']}", e.time, [e]))
        findings += self._spec_lengths(ctx)
        if ctx.merge is not None:
            for d in ctx.merge.differing:
                if d.primary_length != d.secondary_length:
                    findings.append(finding(
                        ctx, C.INCORRECT_LENGTH, Severity.ERROR,
                        f"{d.name or 'Frame'} recorded with {d.primary_length} bytes in {d.primary.file} "
                        f"{d.primary.locator}, {d.secondary_length} bytes in {d.secondary.file} {d.secondary.locator}",
                        d.time, [d.primary, d.secondary], 0.9, actual=d.secondary_length, expected=d.primary_length,
                        first_difference=d.first_difference))
        for tc in ctx.test_cases:
            for step in tc.steps:
                for c in step.checks:
                    if not c.passed and c.index == "Laenge":
                        findings.append(finding(
                            ctx, C.INCORRECT_LENGTH, Severity.ERROR,
                            f"Report validation failed: length {c.actual}, expected {c.expected}", step.time,
                            [step.ref] if step.ref else [], test_case=tc.name, actual=c.actual, expected=c.expected))
        return findings

    @staticmethod
    def _spec_lengths(ctx: AnalysisContext) -> list[Finding]:
        """Telegram length the Test_Description expects (highest BTP index + 1) vs. what the device sends."""
        findings = []
        for tc in ctx.test_cases:
            spec = ctx.specs.get(tc.test_id)
            if spec is None:
                continue
            for step in spec.steps:
                if step.message_type is None or step.expect_absent or not step.expected_bytes:
                    continue
                needed = max(int(k.split("..")[-1]) for k in step.expected_bytes) + 1
                direction = Direction.RX if step.direction.startswith("TDS") else Direction.TX
                sent = telegrams(ctx, step.message_type, direction, tc.start, tc.end)
                actual = sent[0].length if sent else bl5_length(step.message_type)
                if needed <= actual:
                    continue   # the spec only checks a prefix; longer telegrams are covered by the BL5 check
                who = "the device sends" if direction is Direction.RX else "the test system sends"
                seen = f"{who} {actual} bytes" if sent else f"BL5 has {actual} bytes"
                findings.append(finding(
                    ctx, C.INCORRECT_LENGTH, Severity.ERROR,
                    f"Test_Description step {step.number} expects a {needed}-byte {message_name(step.message_type)}, "
                    f"{seen}: the step cannot pass", sent[0].time if sent else None,
                    [r for r in (spec.ref, sent[0].ref if sent else None) if r], 0.9, test_case=tc.name,
                    spec_step=step.number, expected=needed, actual=actual,
                    bytes_beyond=sorted(k for k in step.expected_bytes if int(k.split("..")[-1]) >= actual)))
        return findings


class CommandRejectedRule(NetworkRule):
    """Meldung Kommando abgewiesen with its reason and the command it answers.

    An error when the test relied on the command (preparation, cleanup, or a test step that expects a response);
    a warning when it answers the trigger of a negative test whose Test_Description only forbids telegrams,
    where a rejection is an allowed answer (e.g. AZGH in state frei / nicht grundstellbar, xlsx use case 4).
    """

    name = "command_rejected"
    categories = (C.COMMAND_REJECTED,)

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        findings = []
        for e in telegrams(ctx, SciMessage.MELDUNG_KOMMANDO_ABGEWIESEN, Direction.RX):
            reason = e.fields.get("abweisungsgrund")
            try:
                reason_name = Abweisungsgrund(reason).name.lower()
            except ValueError:
                reason_name = f"unknown ({reason})"
            commands = telegrams(ctx, COMMANDS, Direction.TX, e.time - 1.0, e.time)
            command = commands[-1] if commands else None
            text = f"{message_name(command.msg_type)} rejected ({reason_name})" if command else f"Command rejected ({reason_name})"
            allowed = command is not None and self._negative_test_trigger(ctx, command)
            if allowed:
                text += "; allowed answer, the test only forbids telegrams after this command"
            findings.append(finding(ctx, C.COMMAND_REJECTED, Severity.WARNING if allowed else Severity.ERROR, text,
                                    e.time, [x for x in (command, e) if x], reason=reason_name,
                                    negative_test=allowed))
        return findings

    @staticmethod
    def _negative_test_trigger(ctx: AnalysisContext, command: TraceEvent) -> bool:
        tc = ctx.test_case_at(command.time)
        spec = ctx.specs.get(tc.test_id) if tc else None
        if spec is None:
            return False
        at_step = any(s.section == "Main Part" and s.title.startswith("Sende") and abs(s.time - command.time) < 0.1
                      for s in tc.steps)
        responses = [s for s in spec.steps
                     if s.interface == "BTP" and s.message_type is not None and s.direction.startswith(("TDS", "NOT"))]
        return at_step and bool(responses) and all(s.expect_absent for s in responses)
