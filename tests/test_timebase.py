"""Time alignment and network merge on synthetic sources."""

from datetime import datetime, time, timedelta, timezone

import pytest

from trace_analyzer.correlate import align, match_frames, merge_network
from trace_analyzer.correlate.timebase import (
    by_rasta_timestamp,
    fit_offset,
    shift_test_case,
    utc_offset,
)
from trace_analyzer.model import (
    Direction,
    EventKind,
    EvidenceRef,
    Source,
    SourceData,
    TestCaseResult,
    TestStep,
    TimeBase,
    TimeReference,
    TraceEvent,
    Verdict,
)

EPOCH = TimeBase(TimeReference.EPOCH)
MEASUREMENT = TimeBase(TimeReference.MEASUREMENT)
START = 1_790_936_639.9538   # measurement start as epoch


def frame(t, raw, source=Source.PCAPNG, locator="frame 1", kind=EventKind.RASTA, **kw):
    return TraceEvent(t, kind, EvidenceRef(source, f"x.{source.value}", locator), raw=raw, **kw)


def capture(source, times_raws, offset=0.0, prefix="frame", base=MEASUREMENT, **kw):
    events = [frame(t + offset, raw, source, f"{prefix} {i}", **kw) for i, (t, raw) in enumerate(times_raws, 1)]
    return SourceData(source, None, base, events)


def test_match_frames_pairs_duplicates_in_order():
    a = [frame(1.0, b"x", locator="frame 1"), frame(2.0, b"x", locator="frame 2"), frame(3.0, b"y", locator="frame 3")]
    b = [frame(11.0, b"x", Source.BLF, "object 1"), frame(12.0, b"x", Source.BLF, "object 2")]
    assert [(p.ref.locator, q.ref.locator) for p, q in match_frames(a, b)] == [("frame 1", "object 1"), ("frame 2", "object 2")]


def test_fit_offset_constant_and_drift():
    assert fit_offset([(t, 5.0) for t in range(10)]) == (5.0, 0.0, 0.0)
    _, _, drift = fit_offset([(t, 5.0 + t * 10e-6) for t in range(100)])
    assert drift == pytest.approx(10.0)


def test_align_by_frame_match():
    frames = [(t, bytes([i])) for i, t in enumerate([1.0, 2.0, 3.5])]
    sources = {Source.PCAPNG: capture(Source.PCAPNG, frames, offset=START, base=EPOCH),
               Source.BLF: capture(Source.BLF, frames, prefix="object")}
    alignment = align(sources)[Source.PCAPNG]
    assert alignment.method == "frame_match" and alignment.samples == 3
    assert alignment.offset == pytest.approx(-START)


def _tx_with_timestamps(times, bias=0.0008):
    return [frame(t + START, bytes([i]), direction=Direction.TX,
                  fields={"timestamp": round((t - bias) / 1e-6)}) for i, t in enumerate(times)]


def test_align_by_rasta_timestamp_without_blf():
    pcap = SourceData(Source.PCAPNG, None, EPOCH, _tx_with_timestamps([0.1 * i for i in range(1, 50)]))
    alignment = align({Source.PCAPNG: pcap})[Source.PCAPNG]
    assert alignment.method == "rasta_timestamp"
    assert alignment.offset == pytest.approx(-START, abs=0.002)


def test_rasta_timestamps_from_another_clock_are_rejected():
    events = [frame(t + START, bytes([i]), direction=Direction.TX, fields={"timestamp": (i * 7919) % 1000 * 1000})
              for i, t in enumerate(range(1, 30))]
    assert by_rasta_timestamp(SourceData(Source.PCAPNG, None, EPOCH, events), 1e-6) is None


def test_align_by_measurement_start():
    tz = timezone(timedelta(hours=2))
    pcap = capture(Source.PCAPNG, [(1.0, b"a")], offset=START, base=EPOCH)
    log = SourceData(Source.CANOE_LOG, None, MEASUREMENT, metadata={"measurement_start_clock": time(12, 23, 59, 953800)})
    pdf = SourceData(Source.PDF_REPORT, None, MEASUREMENT,
                     metadata={"test_begin": datetime(2026, 10, 2, 12, 24, 11, tzinfo=tz)})
    alignment = align({Source.PCAPNG: pcap, Source.CANOE_LOG: log, Source.PDF_REPORT: pdf})[Source.PCAPNG]
    assert alignment.method == "measurement_start"
    assert alignment.offset == pytest.approx(-START, abs=0.001)


def test_align_falls_back_to_first_frame():
    pcap = capture(Source.PCAPNG, [(1.0, b"a"), (2.0, b"b")], offset=START, base=EPOCH)
    alignment = align({Source.PCAPNG: pcap})[Source.PCAPNG]
    assert alignment.method == "first_frame" and alignment.offset == pytest.approx(-(START + 1.0))


def test_measurement_sources_keep_their_time():
    blf = capture(Source.BLF, [(1.0, b"a")], prefix="object")
    assert align({Source.BLF: blf})[Source.BLF].method == "native"


def test_merge_network_keeps_frames_missing_in_primary():
    pcap = capture(Source.PCAPNG, [(1.0, b"1"), (2.0, b"2"), (3.0, b"3")])
    pcap.events.append(TraceEvent(2.0, EventKind.SCI_TELEGRAM, EvidenceRef(Source.PCAPNG, "x.pcapng", "frame 2 telegram 1"), raw=b"t"))
    blf = capture(Source.BLF, [(2.0, b"2"), (3.0, b"3"), (4.0, b"4")], prefix="object")

    merged, stats = merge_network(pcap, blf)
    assert [(e.source, e.ref.locator) for e in merged] == [
        (Source.PCAPNG, "frame 1"), (Source.PCAPNG, "frame 2"), (Source.PCAPNG, "frame 3"),
        (Source.PCAPNG, "frame 2 telegram 1"), (Source.BLF, "object 3")]
    refs = {e.ref.locator: e.fields.get("duplicate_ref") for e in merged}
    assert refs["frame 2"] == "x.blf object 1" and refs["frame 2 telegram 1"] == "x.blf object 1 telegram 1"
    assert refs["frame 1"] is None
    assert (stats.matched_frames, stats.only_in_primary, stats.only_in_secondary) == (2, ("frame 1",), ("object 3",))


def test_utc_offset_rounds_to_quarter_hours():
    assert utc_offset(datetime(2026, 10, 2, 12, 0), datetime(2026, 10, 2, 10, 0, 0, 400_000, tzinfo=timezone.utc)) \
        == timezone(timedelta(hours=2))


def test_shift_test_case_moves_steps():
    tc = TestCaseResult("TC_X(O)", Verdict.PASS, 1.0, 2.0, steps=[TestStep(1.5, "1", "step")])
    shifted = shift_test_case(tc, 10.0)
    assert (shifted.start, shifted.end, shifted.steps[0].time) == (11.0, 12.0, 11.5)
