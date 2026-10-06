"""Readers on the RealOC run, checked against the Phase 1 ground truth and the NeuPro Lua dissectors."""

import subprocess
from collections import Counter, defaultdict
from pathlib import Path

import pytest
import yaml

from trace_analyzer.config import load_config
from trace_analyzer.model import EventKind, Source, Verdict
from trace_analyzer.readers import load_sources

CFG = load_config()
GT = yaml.safe_load((Path(__file__).parent / "fixtures" / "ground_truth.yaml").read_text(encoding="utf-8"))
OFFSET = GT["run"]["pcapng_to_canoe_offset_s"]

pytestmark = pytest.mark.skipif(not CFG["data"]["pcapng"].exists(), reason="RealOC data not available")


@pytest.fixture(scope="module")
def sources():
    return load_sources(CFG)


def of_kind(data, kind):
    return [e for e in data.events if e.kind is kind]


def status_tuples(events, t0=0.0):
    return [(round(e.time - t0, 3), e.fields["belegung"], e.fields["grundstellbar"], e.fields["achszaehlfuellstand"])
            for e in events]


GT_STATUS = [(t, b, g, z) for t, b, g, z, _frame in GT["gfma_status"]]


def assert_status_matches(actual):
    assert len(actual) == len(GT_STATUS)
    for (t, *values), (gt_t, *gt_values) in zip(actual, GT_STATUS):
        assert t == pytest.approx(gt_t, abs=0.002)
        assert values == gt_values


# --- PCAPNG ------------------------------------------------------------------------------------------------

def test_pcapng_counts(sources):
    data = sources[Source.PCAPNG]
    assert data.metadata["frames"] == 2162          # Wireshark numbering incl. 3 custom blocks
    rasta = Counter(e.name for e in of_kind(data, EventKind.RASTA))
    expected = GT["counts"]["rasta"]
    assert rasta == {"HEARTBEAT": expected["heartbeat"], "DATA": expected["data"],
                     "CONNECTION_REQUEST": 5, "CONNECTION_RESPONSE": 5, "DISCONNECTION_REQUEST": 5}
    sci = Counter(f"0x{e.msg_type:04x}" for e in of_kind(data, EventKind.SCI_TELEGRAM))
    for code, n in GT["counts"]["sci_telegrams"].items():
        assert sci[code] == n, code
    assert not [e for e in data.events if "decode_error" in e.fields]


def test_pcapng_gfma_status(sources):
    data = sources[Source.PCAPNG]
    events = [e for e in of_kind(data, EventKind.SCI_TELEGRAM) if e.msg_type == 0x0007]
    # pcapng times are epoch; CANoe time = time since first frame + offset
    assert_status_matches(status_tuples(events, data.events[0].time - OFFSET))
    assert [int(e.ref.locator.split()[1]) for e in events] == [f for *_, f in GT["gfma_status"]]


def test_pcapng_disconnect_reasons(sources):
    reasons = [e.fields["reason"] for e in of_kind(sources[Source.PCAPNG], EventKind.RASTA)
               if e.name == "DISCONNECTION_REQUEST"]
    assert reasons == [0] * 5


def test_pcapng_decoder_matches_lua_dissector(sources):
    """Every SCI telegram decoded in Python equals the NeuPro BL5 Lua dissector output (tshark)."""
    cmd = [CFG["wireshark"]["tshark"], "-r", str(CFG["data"]["pcapng"]), "-o", "sci.tds_bl:5", "-Y", "sci",
           "-T", "fields", "-E", "separator=|", "-e", "frame.number", "-e", "sci.messageType",
           "-e", "scitds5.belegung", "-e", "scitds5.grundstell", "-e", "scitds5.zaehlstand"]
    rows = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=120).stdout.splitlines()
    lua = {}
    for row in rows:
        frame, types, bel, grund, zaehl = row.split("|")
        lua[f"frame {frame}"] = ([int(t, 16) for t in types.split(",")],
                                 (int(bel, 16), int(grund, 16), int(zaehl, 16)) if bel else None)

    ours = defaultdict(lambda: ([], None))
    for e in of_kind(sources[Source.PCAPNG], EventKind.SCI_TELEGRAM):
        frame = e.ref.locator.rsplit(" telegram", 1)[0]
        types, status = ours[frame]
        types.append(e.msg_type)
        if e.msg_type == 0x0007:
            status = (e.fields["belegung"], e.fields["grundstellbar"], e.fields["achszaehlfuellstand"])
        ours[frame] = (types, status)

    assert set(ours) == set(lua)
    for frame, (types, status) in lua.items():
        assert sorted(ours[frame][0]) == sorted(types), frame   # Lua column order differs for mixed frames
        assert ours[frame][1] == status, frame


# --- BLF ---------------------------------------------------------------------------------------------------

def test_blf_test_cases(sources):
    cases = sources[Source.BLF].test_cases
    assert [(c.name, c.verdict.value.upper()) for c in cases] == [(c["name"], c["verdict"]) for c in GT["test_cases"]]
    for case, gt in zip(cases, GT["test_cases"]):
        assert case.start == pytest.approx(gt["start"], abs=0.001)
        assert case.end == pytest.approx(gt["end"], abs=0.001)


def test_blf_operator_actions(sources):
    actions = [(round(e.time, 3), e.name, e.fields.get("command")) for e in of_kind(sources[Source.BLF], EventKind.OPERATOR_ACTION)
               if e.fields.get("value")]
    assert actions == [(3.461, "connectButton", None), (8.51, "disconnectButton", None),
                       (381.611, "kdSelection", "KOMMANDO_AZGH"), (391.386, "kdSelection", "KOMMANDO_AZG")]


def test_blf_gfma_variable(sources):
    events = [e for e in of_kind(sources[Source.BLF], EventKind.VARIABLE) if e.name == "meldungGFMABelegungszustand"]
    assert_status_matches(status_tuples(events))


def test_blf_ethernet_matches_pcapng(sources):
    blf = of_kind(sources[Source.BLF], EventKind.SCI_TELEGRAM)
    pcap = of_kind(sources[Source.PCAPNG], EventKind.SCI_TELEGRAM)
    assert [e.raw for e in blf] == [e.raw for e in pcap]
    assert_status_matches(status_tuples([e for e in blf if e.msg_type == 0x0007]))


def test_blf_metadata(sources):
    meta = sources[Source.BLF].metadata
    assert str(meta["measurement_start_local"]) == "2026-10-02 12:23:59.953000"
    assert (meta["configuration"], meta["user"], meta["computer"]) == ("ZE_RealOC_Stimulation.cfg", "shakil", "DBLTAS-20")


# --- PDF report --------------------------------------------------------------------------------------------

def test_pdf_test_cases(sources):
    cases = sources[Source.PDF_REPORT].test_cases
    assert [(c.name, c.verdict.value.upper()) for c in cases] == [(c["name"], c["verdict"]) for c in GT["test_cases"]]
    assert [c.start for c in cases] == pytest.approx([c["start"] for c in GT["test_cases"]], abs=0.001)
    assert [c.version for c in cases] == ["5", "5", "5", None, None]


def test_pdf_failed_steps(sources):
    by_name = {c.test_id: c for c in sources[Source.PDF_REPORT].test_cases}
    tc3 = by_name["TC_NPRO.295.02288.01"]
    assert [(round(s.time, 3), s.section) for s in tc3.failed_steps] == [
        (300.288, "Preparation"), (313.289, "Completion"), (313.289, "Completion")]
    assert "Vorbereitung frei -> belegt nicht abgeschlossen" in tc3.failed_steps[0].title
    tc4 = by_name["TC_NPRO.295.00525.01"]
    assert tc4.failed_steps[0].time == pytest.approx(474.303, abs=0.001)
    assert "Belegungszustand=3" in tc4.failed_steps[0].title


def test_pdf_validation_tables(sources):
    tc1 = sources[Source.PDF_REPORT].test_cases[0]
    checks = [c for s in tc1.steps for c in s.checks]
    assert checks and all(c.passed for c in checks)
    length = next(c for c in checks if c.index == "Laenge")
    assert (length.actual, length.expected) == ("43", "43")


def test_pdf_metadata(sources):
    meta = sources[Source.PDF_REPORT].metadata
    assert meta["tester"] == "shakil"
    assert meta["test_begin"].isoformat() == "2026-10-02T12:24:11+02:00"


# --- CANoe log ---------------------------------------------------------------------------------------------

def test_canoe_log(sources):
    events = sources[Source.CANOE_LOG].events
    assert_status_matches(status_tuples([e for e in events if e.name == "GFM-A status"]))
    errors = [(e.time, e.fields["text"]) for e in events if e.fields.get("level") == "error"]
    assert errors == [(488.321, "[Help 09-0013] Test unit 'SCI-TDS': Execution stop forced. Test is incomplete!")]


# --- Test descriptions -------------------------------------------------------------------------------------

def test_test_specs(sources):
    specs = {s.test_id: s for s in sources[Source.TEST_SPEC].specs}
    assert set(specs) == {"TC_NPRO.295.00525.01", "TC_NPRO.295.02283.01", "TC_NPRO.295.02284.01", "TC_NPRO.295.02288.01"}
    assert {k: s.version for k, s in specs.items()} == {
        "TC_NPRO.295.00525.01": "5", "TC_NPRO.295.02283.01": "7", "TC_NPRO.295.02284.01": "5", "TC_NPRO.295.02288.01": "4"}

    step2 = specs["TC_NPRO.295.02288.01"].steps[1]
    assert (step2.message_type, step2.expect_absent, step2.max_delay_s) == (0x0007, False, 0.5)
    assert step2.expected_bytes["44"] == "0x02" and step2.expected_bytes["47"] == "0xFF"
    assert specs["TC_NPRO.295.02283.01"].steps[1].expect_absent
    assert specs["TC_NPRO.295.00525.01"].steps[0].interface == "AZ6"
