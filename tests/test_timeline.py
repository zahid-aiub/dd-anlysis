"""Timeline of the RealOC run, checked against the Phase 1 ground truth."""

from datetime import datetime
from pathlib import Path

import pytest
import yaml

from trace_analyzer.config import load_config
from trace_analyzer.correlate import align, build_timeline
from trace_analyzer.correlate.timebase import measurement_start
from trace_analyzer.model import EventKind, Source
from trace_analyzer.readers import load_sources

CFG = load_config()
GT = yaml.safe_load((Path(__file__).parent / "fixtures" / "ground_truth.yaml").read_text(encoding="utf-8"))

pytestmark = pytest.mark.skipif(not CFG["data"]["pcapng"].exists(), reason="RealOC data not available")


@pytest.fixture(scope="module")
def sources():
    return load_sources(CFG)


@pytest.fixture(scope="module")
def timeline(sources):
    return build_timeline(sources, CFG)


def test_pcapng_aligned_by_frame_match(timeline):
    a = timeline.alignments[Source.PCAPNG]
    assert a.method == "frame_match" and a.samples == GT["counts"]["pcapng_frames"]
    assert a.spread < 1e-5 and abs(a.drift_ppm) < 1.0
    assert all(timeline.alignments[s].method == "native" for s in (Source.BLF, Source.PDF_REPORT, Source.CANOE_LOG))


def test_measurement_start(timeline):
    expected = datetime.fromisoformat(GT["run"]["measurement_start"])
    assert abs((timeline.measurement_start - expected).total_seconds()) < 0.002
    assert timeline.measurement_start.utcoffset() == expected.utcoffset()


def test_network_frames_deduplicated(timeline):
    merge = timeline.merge
    assert (merge.primary, merge.secondary, merge.matched_frames) == (Source.PCAPNG, Source.BLF, 2159)
    assert merge.only_in_primary == () and merge.only_in_secondary == ()
    network = [e for e in timeline.events if e.kind in (EventKind.RASTA, EventKind.SCI_TELEGRAM, EventKind.NETWORK)]
    assert {e.source for e in network} == {Source.PCAPNG}
    assert all("duplicate_ref" in e.fields for e in network)
    assert sum(e.kind is EventKind.SCI_TELEGRAM for e in network) == 45


def test_events_on_master_timeline(timeline):
    times = [e.time for e in timeline.events]
    assert times == sorted(times)
    status = [e for e in timeline.events if e.kind is EventKind.SCI_TELEGRAM and e.msg_type == 0x0007]
    assert [round(e.time, 3) for e in status] == pytest.approx([row[0] for row in GT["gfma_status"]], abs=0.001)
    # ground-truth command times are CANoe's send log; the frame is on the wire up to ~3 ms later
    commands = [e for e in timeline.events if e.kind is EventKind.SCI_TELEGRAM and e.msg_type in (0x0001, 0x0003)]
    assert [e.time for e in commands] == pytest.approx([row[0] for row in GT["commands"]], abs=0.003)


def test_sources_agree_after_alignment(timeline):
    checks = {(c.name, c.sources): c for c in timeline.checks}
    assert {(name, a.value, b.value) for name, (a, b) in checks} == {
        ("gfma_status", "pcapng", "canoe_log"), ("gfma_status", "pcapng", "blf"), ("test_case_start", "pdf_report", "blf")}
    for check in checks.values():
        assert check.unmatched == 0 and check.max_difference < 0.001


def test_fallbacks_agree_with_frame_match(sources):
    exact = align(sources)[Source.PCAPNG].offset
    without_blf = {s: d for s, d in sources.items() if s is not Source.BLF}
    by_timestamp = align(without_blf)[Source.PCAPNG]
    assert by_timestamp.method == "rasta_timestamp"
    assert by_timestamp.offset == pytest.approx(exact, abs=0.002)
    start = measurement_start(without_blf)   # CANoe log clock + PDF date/offset
    assert -start.timestamp() == pytest.approx(exact, abs=0.002)


def test_timeline_metadata(timeline):
    assert timeline.metadata["configuration"] == "ZE_RealOC_Stimulation.cfg"
    assert timeline.absolute(186.953).strftime("%H:%M:%S") == "12:27:06"
