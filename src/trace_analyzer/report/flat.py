"""The analysis as one flat JSON response (data-anlysis-report.json), in the structure the frontend asked for:

    analysis_id, device_id, timestamp, analysis_type, result_status, summary,
    trace_messages[], failure_findings[], data_comparisons[]

Timestamps are UTC ISO 8601. `report.json` (export.py) stays the complete format; this one is a summary of the
real run that a dashboard can show without knowing the analyzer's data model.
"""

import json
from datetime import timezone
from pathlib import Path

from trace_analyzer.model import (
    Direction,
    EventKind,
    FailureCategory,
    Finding,
    Severity,
    TraceEvent,
    Verdict,
    split_test_name,
)
from trace_analyzer.pipeline import AnalysisResult

from .timeline import STATE_NAMES

C = FailureCategory
FILE_NAME = "data-anlysis-report.json"

REASON = {
    C.MISSING_MESSAGE: "Missing Message", C.WRONG_ORDER: "Wrong Message Order", C.INVALID_PAYLOAD: "Invalid Payload",
    C.INCORRECT_LENGTH: "Message Length Error", C.TIMEOUT: "Response Timeout",
    C.CONNECTION_INTERRUPTION: "Connection Interruption", C.UNEXPECTED_RESPONSE: "Unexpected Response",
    C.CONFIGURATION_MISMATCH: "Configuration Mismatch", C.SEQUENCE_ERROR: "Sequence Error",
    C.COMMAND_REJECTED: "Command Rejected", C.PRECONDITION_NOT_REACHED: "Precondition Not Reached",
    C.TEST_STEP_FAILED: "Test Step Failed", C.DEVICE_DISTURBED: "Device Disturbed",
    C.CASCADE_FAILURE: "Cascade Failure", C.TEST_ABORTED: "Test Aborted", C.MANUAL_INTERVENTION: "Manual Intervention",
    C.TIME_ALIGNMENT: "Time Alignment",
}
STATUS = {Verdict.PASS: "PASSED", Verdict.FAIL: "FAILED", Verdict.INCONCLUSIVE: "INCONCLUSIVE",
          Verdict.ERROR: "ERROR", Verdict.NONE: "NONE"}


def _short(name: str | None) -> str | None:
    """'TC_NPRO.295.02288.01(O)' → 'TC_NPRO.295.02288.01'."""
    return split_test_name(name)[0] if name else None


def _state(belegung: int, grundstellbar: int) -> str:
    name = STATE_NAMES.get(belegung, f"unknown {belegung}")
    return f"{belegung}/{grundstellbar} ({name}, {'grundstellbar' if grundstellbar else 'nicht grundstellbar'})"


class _Flat:
    def __init__(self, result: AnalysisResult):
        self.result, self.ctx = result, result.context
        start = self.ctx.metadata.get("measurement_start")
        self.start_utc = start.astimezone(timezone.utc) if start else None
        self.by_locator = {e.ref.locator: e for e in self.ctx.events if e.kind is EventKind.SCI_TELEGRAM}

    def telegram_name(self, f: Finding) -> str | None:
        return next((self.by_locator[r.locator].name for r in f.evidence if r.locator in self.by_locator), None)

    def utc(self, t: float | None) -> str | None:
        absolute = self.result.timeline.absolute(t) if t is not None else None
        return absolute.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z") \
            if absolute else None

    @staticmethod
    def message_id(locator: str) -> str:
        """'frame 425 telegram 1' → 'frame-425-1'."""
        parts = locator.split()
        return "frame-" + "-".join(parts[1::2]) if parts and parts[0] == "frame" else locator.replace(" ", "-")

    def telegram_findings(self) -> dict[str, list[Finding]]:
        by_locator: dict[str, list[Finding]] = {}
        for f in self.result.findings:
            for ref in f.evidence:
                if ref.source.value == "pcapng" and "telegram" in ref.locator:
                    by_locator.setdefault(ref.locator, []).append(f)
        return by_locator

    def trace_message(self, e: TraceEvent, linked: list[Finding]) -> dict:
        errors = [f for f in linked if f.severity is Severity.ERROR]
        warnings = [f for f in linked if f.severity is Severity.WARNING]
        status = "FAILED" if errors else "WARNING" if warnings else "OK"
        reasons = list(dict.fromkeys(REASON[f.category] for f in errors or warnings))
        fields = {k: v for k, v in e.fields.items() if k not in ("protocol_type", "duplicate_ref", "differs_from")}
        return {
            "message_id": self.message_id(e.ref.locator),
            "timestamp": self.utc(e.time),
            "time_s": round(e.time, 6),
            "sender": e.sender,
            "receiver": e.receiver,
            "protocol": "SCI-TDS BL5 over RaSTA",
            "message_type": e.name,
            "message_code": f"0x{e.msg_type:04X}" if isinstance(e.msg_type, int) else e.msg_type,
            "direction": "ZE→AZ" if e.direction is Direction.TX else "AZ→ZE",
            "length": e.length,
            "fields": fields,
            "test_case": _short(self.ctx.test_case_at(e.time).name) if self.ctx.test_case_at(e.time) else None,
            "status": status,
            "error_reason": "; ".join(reasons) if reasons else None,
        }

    def failure(self, f: Finding) -> dict:
        telegram = next((r for r in f.evidence if r.source.value == "pcapng" and "telegram" in r.locator), None)
        length = f.category is C.INCORRECT_LENGTH
        return {
            "message_id": self.message_id(telegram.locator) if telegram else None,
            "expected_length": f.details.get("expected") if length else None,
            "actual_length": f.details.get("actual") if length else None,
            "result": REASON[f.category],
            "test_case": _short(f.test_case),
            "timestamp": self.utc(f.time),
            "time_s": round(f.time, 6) if f.time is not None else None,
            "category": f.category.value,
            "description": f.summary,
            "confidence": round(f.confidence, 2),
            "evidence": [str(r) for r in f.evidence],
        }

    def comparisons(self) -> list[dict]:
        rows = []

        def row(field, expected, actual, ok, test_case=None, severity=None):
            rows.append({"field": field, "expected": str(expected), "actual": str(actual),
                         "result": "OK" if ok else "Warning" if severity is Severity.WARNING else "Error",
                         "test_case": test_case})

        for d in self.result.diagnoses:
            tc = _short(d.test_case.name)
            row("Test verdict", STATUS[Verdict.PASS], STATUS[d.verdict], d.verdict is Verdict.PASS, tc,
                Severity.WARNING if d.verdict is Verdict.INCONCLUSIVE else None)
        for f in self.result.findings:
            tc, det = _short(f.test_case), f.details
            if f.category is C.INCORRECT_LENGTH:
                step = f" (Test_Description step {det['spec_step']})" if "spec_step" in det else ""
                row(f"Length {self.telegram_name(f) or 'telegram'}{step}", det.get("expected"), det.get("actual"),
                    False, tc)
            elif f.category is C.PRECONDITION_NOT_REACHED and det.get("target") and det.get("actual"):
                row("GFM-A state for the precondition", _state(*det["target"]), _state(*det["actual"][:2]), False, tc)
            elif f.category is C.DEVICE_DISTURBED and not det.get("inherited"):
                row(f"GFM-A {det.get('element', '')} Belegungszustand", "not 3 (gestört)",
                    f"3 (gestört) at {f.time:.3f} s", False, tc)
            elif f.category is C.CASCADE_FAILURE and f.severity is Severity.ERROR:
                row("State at test start", "defined start state", f"left by {_short(det.get('caused_by'))}", False, tc)
            elif f.category is C.TEST_ABORTED:
                row("Test execution", "completed", "stopped by the user", False, tc)
            elif f.category is C.CONFIGURATION_MISMATCH and "report_version" in det:
                row("Test case version", det["spec_version"], det["report_version"], False, tc, Severity.WARNING)
            elif f.category is C.CONFIGURATION_MISMATCH and det.get("problems"):
                row("Test_Description value vs. BL5", "valid BL5 value", det["problems"][0], False, tc, Severity.WARNING)
            elif f.category is C.MANUAL_INTERVENTION and f.severity is Severity.WARNING:
                row("Manual panel commands", "none (test instruction)", f.summary.split(" from the")[0], False, tc,
                    Severity.WARNING)
            elif f.category is C.COMMAND_REJECTED:
                row("Command result", "executed", f.summary, False, tc, f.severity)
        rows += self.protocol_checks()
        return rows

    def protocol_checks(self) -> list[dict]:
        """Run-wide checks with the measured value, OK when no rule found a problem."""
        ctx, found = self.ctx, {f.category for f in self.result.findings}
        rows = []

        def row(field, expected, actual, category):
            rows.append({"field": field, "expected": expected, "actual": actual,
                         "result": "Error" if category in found else "OK", "test_case": None})

        gaps = []
        for s in ctx.sessions:
            for d in (Direction.TX, Direction.RX):
                times = [e.time for e in ctx.events if e.kind is EventKind.RASTA and e.direction is d
                         and s.start <= e.time <= s.end]
                gaps += [b - a for a, b in zip(times, times[1:])]
        limit = ctx.config.get("rasta", {}).get("max_message_gap_ms", 750)
        row("RaSTA message gap", f"<= {limit} ms", f"max {max(gaps, default=0) * 1000:.0f} ms", C.CONNECTION_INTERRUPTION)
        reasons = sorted({s.disconnect_reason for s in ctx.sessions if s.disconnect_reason is not None})
        row("RaSTA disconnect reason", "0 (user request)", ", ".join(map(str, reasons)) or "-", C.CONNECTION_INTERRUPTION)
        row("RaSTA sequence numbers", "no gaps or repeats",
            f"{sum(f.category is C.SEQUENCE_ERROR for f in self.result.findings)} problems", C.SEQUENCE_ERROR)
        telegrams = [e for e in ctx.events if e.kind is EventKind.SCI_TELEGRAM]
        bad = [f for f in self.result.findings if f.category is C.INCORRECT_LENGTH and "spec_step" not in f.details]
        row("Telegram length vs. BL5 layout", "all telegrams", f"{len(telegrams) - len(bad)}/{len(telegrams)} match",
            C.INCORRECT_LENGTH if bad else None)
        row("Field values vs. BL5 ranges", "all in range",
            f"{sum(f.category is C.INVALID_PAYLOAD for f in self.result.findings)} out of range", C.INVALID_PAYLOAD)
        timeout = ctx.config.get("timing", {}).get("response_timeout_ms", 500)
        row("Start-up responses", f"within {timeout} ms",
            f"{sum(f.category in (C.TIMEOUT, C.MISSING_MESSAGE) for f in self.result.findings)} late or missing",
            C.TIMEOUT if C.TIMEOUT in found else C.MISSING_MESSAGE)
        row("Start-up message order", "version check → Aufrüstung",
            f"{sum(f.category is C.WRONG_ORDER for f in self.result.findings)} violations", C.WRONG_ORDER)
        a = next((a for source, a in ctx.alignments.items() if source.value == "pcapng"), None)
        if a is not None:
            spread_limit = ctx.config.get("alignment", {}).get("max_spread_ms", 5)
            row("Time alignment pcapng → CANoe", f"spread <= {spread_limit} ms",
                f"{a.method}, spread {a.spread * 1000:.3f} ms", C.TIME_ALIGNMENT)
        return rows

    def response(self) -> dict:
        diagnoses = self.result.diagnoses
        verdicts = [d.verdict for d in diagnoses]
        status = ("FAILED" if Verdict.FAIL in verdicts else "INCONCLUSIVE" if Verdict.INCONCLUSIVE in verdicts
                  else "PASSED")
        failed = [d for d in diagnoses if d.verdict is Verdict.FAIL]
        inconclusive = [d for d in diagnoses if d.verdict is Verdict.INCONCLUSIVE]
        parts = [f"{len(failed)} of {len(diagnoses)} test cases failed"]
        parts += [f"{_short(d.test_case.name)}: {d.cause.summary}" for d in failed if d.cause]
        parts += [f"{_short(d.test_case.name)} inconclusive: {d.cause.summary}" for d in inconclusive if d.cause]
        linked = self.telegram_findings()
        telegrams = [e for e in self.ctx.events if e.kind is EventKind.SCI_TELEGRAM]
        start = self.start_utc
        return {
            "analysis_id": f"TRACE-RUN-{start:%Y%m%d-%H%M%S}" if start else "TRACE-RUN",
            "device_id": str(self.ctx.config.get("nodes", {}).get("dut", {}).get("id", "")) or None,
            "timestamp": start.isoformat(timespec="milliseconds").replace("+00:00", "Z") if start else None,
            "analysis_type": "TRACE_COMMUNICATION",
            "result_status": status,
            "summary": ". ".join(parts) + ".",
            "trace_messages": [self.trace_message(e, linked.get(e.ref.locator, [])) for e in telegrams],
            "failure_findings": [self.failure(f) for f in self.result.findings if f.severity is Severity.ERROR],
            "data_comparisons": self.comparisons(),
        }


def to_flat_json(result: AnalysisResult) -> dict:
    return _Flat(result).response()


def write_flat_json(result: AnalysisResult, path: Path) -> Path:
    path = Path(path)
    path.write_text(json.dumps(to_flat_json(result), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path
