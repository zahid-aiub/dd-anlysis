"""Synthetic captures: the capture editor keeps the file consistent, and every scenario gives the expected result."""

from pathlib import Path

import pytest

from trace_analyzer.config import load_config
from trace_analyzer.model import Direction, RastaType, SciMessage, Source
from trace_analyzer.pipeline import analyze
from trace_analyzer.readers import PcapngReader
from trace_analyzer.readers.decode import decode_ethernet
from trace_analyzer.synthetic import Capture, telegram
from trace_analyzer.synthetic.capture import rasta_payload, with_udp_payload
from trace_analyzer.synthetic.runner import run_scenario
from trace_analyzer.synthetic.scenarios import SCENARIOS

CFG = load_config()

pytestmark = pytest.mark.skipif(not CFG["data"]["pcapng"].exists(), reason="RealOC data not available")


@pytest.fixture(scope="module")
def base():
    return analyze(CFG)


@pytest.fixture()
def capture(base):
    return Capture.load(CFG["data"]["pcapng"], CFG["nodes"], base.context.alignments[Source.PCAPNG].offset)


def test_unchanged_capture_is_byte_identical(capture, tmp_path):
    path = capture.save(tmp_path / "copy.pcapng")
    assert path.read_bytes() == CFG["data"]["pcapng"].read_bytes()


def test_rebuilding_every_frame_reproduces_it(capture):
    for f in capture.frames:
        if f.rasta is not None:
            payload = decode_ethernet(f.data).payload
            assert with_udp_payload(f.data, rasta_payload(payload, f.rasta.type, f.rasta.app_data)) == f.data, f.number


def test_frame_times_are_master_times(capture, base):
    status = capture.find(sci=SciMessage.MELDUNG_GFMA_BELEGUNGSZUSTAND)
    network = [e.time for e in base.context.events if e.kind.value == "sci_telegram" and e.msg_type == 0x0007]
    assert [f.time for f in status] == pytest.approx(network, abs=1e-6)


def test_edits_stay_decodable(capture, tmp_path):
    heartbeat = capture.heartbeat_after(60.0, Direction.RX)
    status = telegram(b"\x20" + bytes(42), SciMessage.MELDUNG_GFMA_BELEGUNGSZUSTAND, belegung=2, grundstellbar=1,
                      achszaehlfuellstand=1)
    capture.set_app_data(heartbeat, [status], "status instead of heartbeat")
    report = capture.first(sci=SciMessage.MELDUNG_AUFRUESTBEGINN)
    capture.set_app_data(report, [], "start-up report removed")
    capture.drop([capture.heartbeat_after(70.0, Direction.TX)])

    events = PcapngReader(CFG["nodes"]).read(capture.save(tmp_path / "edited.pcapng")).events
    rasta = {e.ref.locator: e for e in events if e.kind.value == "rasta"}
    edited = rasta[f"frame {heartbeat.number}"]
    assert edited.msg_type == RastaType.DATA and edited.fields["seq"] == heartbeat.rasta.seq
    assert "decode_error" not in edited.fields
    assert rasta[f"frame {report.number}"].msg_type == RastaType.HEARTBEAT
    assert len(rasta) == len([f for f in capture.frames if f.rasta is not None])
    sci = [e for e in events if e.kind.value == "sci_telegram" and e.ref.locator.startswith(f"frame {heartbeat.number} ")]
    assert [(e.fields["belegung"], e.fields["grundstellbar"], e.length) for e in sci] == [(2, 1, 47)]
    assert capture.changes == ["status instead of heartbeat", "start-up report removed"]


def test_clock_step_moves_timestamps(capture, tmp_path):
    later = capture.find(start=200.0)
    capture.shift(later, 0.020)
    events = PcapngReader(CFG["nodes"]).read(capture.save(tmp_path / "shifted.pcapng")).events
    frames = [e for e in events if e.kind.value == "rasta"]
    before = [f for f in capture.frames if f.rasta is not None]
    assert [e.time for e in frames][-1] - [e.time for e in frames][0] == pytest.approx(
        before[-1].time - before[0].time, abs=1e-6)


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: f"S{s.number}_{s.key}")
def test_scenario(scenario, base, tmp_path):
    result = run_scenario(scenario, CFG, base, tmp_path)
    assert result.problems == []
    if scenario.synthetic:
        assert result.changes and Path(result.capture).exists()
