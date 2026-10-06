"""Put every source on the master timeline: CANoe measurement time.

Sources that already use measurement time (BLF, PDF report, CANoe log) keep their times. Epoch sources
(PCAPNG) get an offset estimated, in order of preference, from:

1. frame_match: identical frames in the BLF (µs accurate, also gives drift),
2. rasta_timestamp: the test system's RaSTA timestamps, which CANoe fills with measurement time in µs
   (observed on the RealOC run; ~1 ms accurate because of the send delay),
3. measurement_start: measurement start clock (BLF header or CANoe log) + date and UTC offset (PDF),
4. first_frame: no measurement-time source at all; time counts from the first frame.
"""

import statistics
from collections import defaultdict, deque
from collections.abc import Iterable, Sequence
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from trace_analyzer.model import (
    Alignment,
    ConsistencyCheck,
    Direction,
    EventKind,
    Source,
    SourceData,
    TestCaseResult,
    TimeReference,
    TraceEvent,
)

FRAME_KINDS = (EventKind.RASTA, EventKind.NETWORK)   # one event per captured frame
DEFAULTS = {"max_spread_ms": 5.0, "rasta_timestamp_resolution_s": 1e-6}


def frame_events(events: Iterable[TraceEvent]) -> list[TraceEvent]:
    return [e for e in events if e.kind in FRAME_KINDS and e.raw is not None]


def match_frames(a: Sequence[TraceEvent], b: Sequence[TraceEvent]) -> list[tuple[TraceEvent, TraceEvent]]:
    """Pair identical frames of two captures, in capture order."""
    queues: dict[tuple, deque[TraceEvent]] = defaultdict(deque)
    for e in frame_events(b):
        queues[(e.kind, e.raw)].append(e)
    pairs = []
    for e in frame_events(a):
        queue = queues.get((e.kind, e.raw))
        if queue:
            pairs.append((e, queue.popleft()))
    return pairs


def pair_differing(a: Sequence[TraceEvent], b: Sequence[TraceEvent],
                   tolerance: float) -> list[tuple[TraceEvent, TraceEvent]]:
    """Pair frames that `match_frames` left over: same kind, direction and RaSTA message, within `tolerance` s.

    Such a pair is one frame that the two captures recorded with different bytes (e.g. sender vs. receiver side).
    Times must already be on the same timeline. A second pass pairs by direction only, for frames one capture
    could not decode as RaSTA at all.
    """
    def strict(e: TraceEvent) -> tuple:
        return e.kind, e.direction, e.msg_type, e.fields.get("seq") if e.kind is EventKind.RASTA else None

    pairs: list[tuple[TraceEvent, TraceEvent]] = []
    left_a, left_b = frame_events(a), frame_events(b)
    for key in (strict, lambda e: (e.direction,)):
        candidates: dict[tuple, list[TraceEvent]] = defaultdict(list)
        for e in left_b:
            candidates[key(e)].append(e)
        paired = set()
        for e in left_a:
            options = [c for c in candidates.get(key(e), []) if abs(c.time - e.time) <= tolerance]
            if options:
                best = min(options, key=lambda c: abs(c.time - e.time))
                candidates[key(e)].remove(best)
                pairs.append((e, best))
                paired.update((id(e), id(best)))
        left_a = [e for e in left_a if id(e) not in paired]
        left_b = [e for e in left_b if id(e) not in paired]
    return sorted(pairs, key=lambda p: p[0].time)


def fit_offset(samples: Sequence[tuple[float, float]]) -> tuple[float, float, float]:
    """(time, offset) samples → (median offset, max deviation, drift in ppm)."""
    offsets = [o for _, o in samples]
    median = statistics.median(offsets)
    spread = max(abs(o - median) for o in offsets)
    times = [t for t, _ in samples]
    mean_t, mean_o = statistics.fmean(times), statistics.fmean(offsets)
    var = sum((t - mean_t) ** 2 for t in times)
    slope = sum((t - mean_t) * (o - mean_o) for t, o in samples) / var if var > 0 else 0.0
    return median, spread, slope * 1e6


def by_frame_match(epoch: SourceData, reference: SourceData) -> Alignment | None:
    pairs = match_frames(epoch.events, reference.events)
    if not pairs:
        return None
    offset, spread, drift = fit_offset([(a.time, b.time - a.time) for a, b in pairs])
    return Alignment(epoch.source, offset, "frame_match", len(pairs), spread, drift,
                     f"matched against {reference.source.value}")


def by_rasta_timestamp(epoch: SourceData, resolution: float) -> Alignment | None:
    samples = [(e.time, e.fields["timestamp"] * resolution - e.time) for e in epoch.events
               if e.kind is EventKind.RASTA and e.direction is Direction.TX and "timestamp" in e.fields]
    if len(samples) < 10:
        return None
    offset, _max_spread, drift = fit_offset(samples)
    deviations = sorted(abs(o - offset) for _, o in samples)
    if statistics.median(deviations) > 0.005:   # timestamps do not track measurement time
        return None
    # Single messages leave late (send delay up to ~7 ms on the RealOC run), which says nothing about the
    # clocks; the 95th percentile is the spread of the estimate.
    spread = deviations[int(0.95 * (len(deviations) - 1))]
    return Alignment(epoch.source, offset, "rasta_timestamp", len(samples), spread, drift,
                     "test-system RaSTA timestamps; biased early by the send delay (~1 ms); "
                     "spread = 95th percentile")


def measurement_start(sources: dict[Source, SourceData]) -> datetime | None:
    """Aware datetime of the measurement start, from BLF header or CANoe log clock plus the PDF's date and offset."""
    pdf = sources.get(Source.PDF_REPORT)
    report_begin = pdf.metadata.get("test_begin") if pdf else None
    tz = report_begin.tzinfo if report_begin else None

    blf = sources.get(Source.BLF)
    local = blf.metadata.get("measurement_start_local") if blf else None
    if local is None and report_begin is not None and Source.CANOE_LOG in sources:
        clock = sources[Source.CANOE_LOG].metadata.get("measurement_start_clock")
        if clock is not None:
            local = datetime.combine(report_begin.date(), clock)
            if local > report_begin.replace(tzinfo=None):   # measurement started the day before
                local -= timedelta(days=1)
    if local is None or tz is None:
        return None
    return local.replace(tzinfo=tz)


def align(sources: dict[Source, SourceData], settings: dict | None = None) -> dict[Source, Alignment]:
    settings = {**DEFAULTS, **(settings or {})}
    alignments = {}
    for source, data in sources.items():
        if data.time_base.reference is TimeReference.MEASUREMENT:
            alignments[source] = Alignment(source, 0.0, "native")
            continue
        alignment = None
        if Source.BLF in sources:
            alignment = by_frame_match(data, sources[Source.BLF])
        if alignment is None:
            alignment = by_rasta_timestamp(data, settings["rasta_timestamp_resolution_s"])
        if alignment is None and (start := measurement_start(sources)) is not None:
            alignment = Alignment(source, -start.timestamp(), "measurement_start",
                                  note="millisecond start clock; assumes the capture clock is the CANoe PC clock")
        if alignment is None:
            first = min((e.time for e in data.events), default=0.0)
            alignment = Alignment(source, -first, "first_frame",
                                  note="no measurement-time source; times count from the first frame")
        alignments[source] = alignment
    return alignments


def shift_test_case(tc: TestCaseResult, offset: float) -> TestCaseResult:
    if offset == 0.0:
        return tc
    steps = [replace(s, time=s.time + offset) for s in tc.steps]
    return replace(tc, start=tc.start + offset, end=tc.end + offset, steps=steps)


def apply(data: SourceData, alignment: Alignment) -> SourceData:
    """Copy of the source data on the master timeline."""
    if alignment.offset == 0.0 and alignment.method == "native":
        return data
    return replace(
        data,
        events=[e.shifted(alignment.offset) for e in data.events],
        test_cases=[shift_test_case(tc, alignment.offset) for tc in data.test_cases],
    )


def measurement_start_utc(sources: dict[Source, SourceData], alignments: dict[Source, Alignment]) -> datetime | None:
    """Measurement start in UTC, derived from an aligned epoch source (exact) or from the start clock."""
    for alignment in alignments.values():
        if alignment.method in ("frame_match", "rasta_timestamp"):
            return datetime.fromtimestamp(-alignment.offset, timezone.utc)
    start = measurement_start(sources)
    return start.astimezone(timezone.utc) if start else None


def utc_offset(local_start: datetime | None, start_utc: datetime | None) -> timezone | None:
    """Test bench UTC offset from its local start clock and the UTC start, rounded to 15 min."""
    if local_start is None or start_utc is None:
        return None
    delta = local_start.replace(tzinfo=None) - start_utc.replace(tzinfo=None)
    quarter_hours = round(delta.total_seconds() / 900)
    return timezone(timedelta(minutes=15 * quarter_hours))


def _status_key(e: TraceEvent) -> tuple | None:
    if all(k in e.fields for k in ("belegung", "grundstellbar", "achszaehlfuellstand")):
        return e.fields["belegung"], e.fields["grundstellbar"], e.fields["achszaehlfuellstand"]
    return None


def _compare(name: str, a_source: Source, a: list[tuple[object, float]],
             b_source: Source, b: list[tuple[object, float]]) -> ConsistencyCheck | None:
    """Pair equal keys in order and report the largest time difference."""
    if not a or not b:
        return None
    queues: dict[object, deque[float]] = defaultdict(deque)
    for key, t in b:
        queues[key].append(t)
    diffs = [abs(queues[key].popleft() - t) for key, t in a if queues[key]]
    return ConsistencyCheck(name, (a_source, b_source), len(diffs), max(diffs, default=0.0),
                            len(a) + len(b) - 2 * len(diffs))


def cross_check(aligned: dict[Source, SourceData]) -> list[ConsistencyCheck]:
    """Compare observations that appear in more than one source after alignment."""
    checks = []

    def status_events(source: Source, kind: EventKind) -> list[tuple[object, float]]:
        data = aligned.get(source)
        if data is None:
            return []
        return [(k, e.time) for e in data.events if e.kind is kind and (k := _status_key(e)) is not None]

    network = Source.PCAPNG if Source.PCAPNG in aligned else Source.BLF
    pairs = [
        ("gfma_status", network, status_events(network, EventKind.SCI_TELEGRAM),
         Source.CANOE_LOG, status_events(Source.CANOE_LOG, EventKind.LOG)),
        ("gfma_status", network, status_events(network, EventKind.SCI_TELEGRAM),
         Source.BLF, status_events(Source.BLF, EventKind.VARIABLE)),
    ]
    if Source.PDF_REPORT in aligned and Source.BLF in aligned:
        pairs.append(("test_case_start",
                      Source.PDF_REPORT, [(tc.name, tc.start) for tc in aligned[Source.PDF_REPORT].test_cases],
                      Source.BLF, [(tc.name, tc.start) for tc in aligned[Source.BLF].test_cases]))
    for name, a_source, a, b_source, b in pairs:
        if (check := _compare(name, a_source, a, b_source, b)) is not None:
            checks.append(check)
    return checks
