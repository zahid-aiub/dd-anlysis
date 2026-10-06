"""Helpers shared by the rules."""

import re
from collections.abc import Iterable

from trace_analyzer.model import (
    AnalysisContext,
    Direction,
    EventKind,
    EvidenceRef,
    FailureCategory,
    Finding,
    SciMessage,
    Severity,
    TestCaseResult,
    TestSpec,
    TraceEvent,
)
from trace_analyzer.readers.decode import bl5_length

STATUS_FIELDS = ("belegung", "grundstellbar", "achszaehlfuellstand")
COMMANDS = (SciMessage.KOMMANDO_AZG, SciMessage.KOMMANDO_ACHSZAEHLFUELLSTAND_AKTUALISIERUNG,
            SciMessage.KOMMANDO_AZGH, SciMessage.KOMMANDO_ZDP_AKTIVIERUNG)
# Valid BL5 values per payload field (0 is "ungültig" for every enumerated field except Grundstellbarkeit)
FIELD_RANGES = {
    "belegung": {1, 2, 3, 4, 5},
    "grundstellbar": {0, 1},
    "grundstellungsart": {1, 2, 3, 4},
    "abweisungsgrund": {1, 2},
    "befahrung": {1, 2, 3, 4},
    "richtung": {1, 2},
}
_TARGET = re.compile(r"Sollzustand:\s*Belegungszustand=(\d+),\s*Grundstellbarkeit=(\d+)")
_SPEC_STATE = re.compile(r"(?:state|Zustand)\s+\"+([^\"]+)\"", re.IGNORECASE)
_SPEC_BELEGUNG = ((("disturbed", "gestört", "gestoert"), 3), (("occupied", "belegt"), 2), (("free", "frei"), 1))


def is_known_message(msg_type: int) -> bool:
    try:
        SciMessage(msg_type)
    except ValueError:
        return False
    return True


def message_name(msg_type: int) -> str:
    return SciMessage(msg_type).name if is_known_message(msg_type) else f"0x{msg_type:04x}"


def telegrams(ctx: AnalysisContext, msg_type: int | Iterable[int] | None = None,
              direction: Direction | None = None, start: float = float("-inf"),
              end: float = float("inf")) -> list[TraceEvent]:
    types = {msg_type} if isinstance(msg_type, int) else set(msg_type) if msg_type is not None else None
    return [e for e in ctx.events
            if e.kind is EventKind.SCI_TELEGRAM and start <= e.time < end
            and (types is None or e.msg_type in types) and (direction is None or e.direction is direction)]


def gfma_status(ctx: AnalysisContext) -> list[TraceEvent]:
    """GFM-A status reports: network telegrams if captured, else BLF variables, else CANoe log lines."""
    for kind in (EventKind.SCI_TELEGRAM, EventKind.VARIABLE, EventKind.LOG):
        found = [e for e in ctx.events if e.kind is kind and all(f in e.fields for f in STATUS_FIELDS)]
        if found:
            return found
    return []


def state(event: TraceEvent) -> tuple[int, int, int]:
    return tuple(event.fields[f] for f in STATUS_FIELDS)


def status_at(statuses: list[TraceEvent], t: float) -> TraceEvent | None:
    """Last status report at or before t."""
    before = [s for s in statuses if s.time <= t]
    return before[-1] if before else None


def target_state(tc: TestCaseResult) -> tuple[int, int] | None:
    """(Belegungszustand, Grundstellbarkeit) the test case prepares, from the report's "Sollzustand" line."""
    for step in tc.steps:
        if m := _TARGET.search(step.title):
            return int(m.group(1)), int(m.group(2))
    return None


def spec_target_state(spec: TestSpec | None) -> tuple[int, int] | None:
    """(Belegungszustand, Grundstellbarkeit) required by the Test_Description precondition.

    Parses the quoted GFM-A state, e.g. 'GFM-A is in the state "GFM-A occupied and cannot be primed"' → (2, 0)
    or 'GFM-A ist im Zustand "GFM-A belegt und grundstellbar"' → (2, 1).
    """
    if spec is None or not spec.precondition:
        return None
    m = _SPEC_STATE.search(spec.precondition)
    if m is None:
        return None
    text = m.group(1).lower()
    belegung = next((value for words, value in _SPEC_BELEGUNG if any(w in text for w in words)), None)
    if belegung is None:
        return None
    negated = any(re.search(rf"\b{w}\b", text) for w in ("not", "cannot", "nicht", "non"))
    resettable = any(w in text for w in ("primeable", "primed", "ready", "grundstellbar", "resettable"))
    return belegung, int(resettable and not negated)


def main_part_start(tc: TestCaseResult) -> float | None:
    """Time of the first step of the test's main part, None if the test never got there."""
    return next((s.time for s in tc.steps if s.section == "Main Part"), None)


def expected_length(msg_type: int, fields: dict) -> int | None:
    """BL5 telegram length for a known message type, None if the type is unknown."""
    if not is_known_message(msg_type):
        return None
    if msg_type == SciMessage.MELDUNG_BTP_VERSIONSABGLEICH and "checksum_length" not in fields:
        return None
    return bl5_length(msg_type, fields)


def case_name_at(ctx: AnalysisContext, t: float | None) -> str | None:
    tc = ctx.test_case_at(t) if t is not None else None
    return tc.name if tc else None


def finding(ctx: AnalysisContext, category: FailureCategory, severity: Severity, summary: str,
            time: float | None, events: Iterable[TraceEvent | EvidenceRef] = (), confidence: float = 1.0,
            test_case: str | None = None, **details) -> Finding:
    evidence = tuple(e.ref if isinstance(e, TraceEvent) else e for e in events)
    return Finding(category, severity, summary, time, test_case or case_name_at(ctx, time), confidence,
                   evidence, details)
