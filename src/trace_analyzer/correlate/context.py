"""Correlate the timeline: merged test cases, RaSTA sessions, and the AnalysisContext for the rules."""

from dataclasses import replace

from trace_analyzer.model import (
    AnalysisContext,
    Direction,
    EventKind,
    RastaType,
    Session,
    Source,
    TestCaseResult,
    TraceEvent,
)

from .timeline import Timeline


def merge_test_cases(by_source: dict[Source, list[TestCaseResult]]) -> list[TestCaseResult]:
    """Windows and verdicts from the BLF test structure, steps and version from the PDF report."""
    blf = by_source.get(Source.BLF, [])
    pdf = {tc.name: tc for tc in by_source.get(Source.PDF_REPORT, [])}
    merged = []
    for tc in blf:
        report = pdf.pop(tc.name, None)
        if report is not None:
            tc = replace(tc, version=report.version, steps=report.steps, ref=report.ref)
        merged.append(tc)
    merged += pdf.values()   # test cases only the report knows
    return sorted(merged, key=lambda tc: tc.start)


def build_sessions(events: list[TraceEvent], test_cases: list[TestCaseResult]) -> list[Session]:
    """RaSTA connections: test-system connection request up to the next disconnection request."""
    sessions: list[Session] = []
    current: dict | None = None

    def close(end: float, closed_by: Direction | None = None, reason: int | None = None) -> None:
        nonlocal current
        if current is None:
            return
        tc = next((t for t in test_cases if t.contains(current["start"])), None)
        sessions.append(Session(len(sessions) + 1, current["start"], end, tc.name if tc else None,
                                current["established"], closed_by, reason))
        current = None

    last_time = 0.0
    for e in events:
        if e.kind is not EventKind.RASTA:
            continue
        if e.msg_type == RastaType.CONNECTION_REQUEST and e.direction is Direction.TX:
            close(last_time)
            current = {"start": e.time, "established": False}
        elif current is not None and e.msg_type == RastaType.CONNECTION_RESPONSE:
            current["established"] = True
        elif current is not None and e.msg_type == RastaType.DISCONNECTION_REQUEST:
            close(e.time, e.direction, e.fields.get("reason"))
        last_time = e.time
    close(last_time)
    return sessions


def build_context(timeline: Timeline, cfg: dict) -> AnalysisContext:
    test_cases = merge_test_cases(timeline.test_cases)
    return AnalysisContext(
        events=timeline.events,
        test_cases=test_cases,
        specs={spec.test_id: spec for spec in timeline.specs},
        sessions=build_sessions(timeline.events, test_cases),
        config=cfg,
        alignments=timeline.alignments,
        checks=timeline.checks,
        merge=timeline.merge,
        metadata={**timeline.metadata, "measurement_start": timeline.measurement_start},
    )
