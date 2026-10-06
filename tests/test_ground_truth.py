"""Cross-check the Phase 1 ground truth against the raw pcapng via tshark."""

import subprocess
from collections import Counter
from pathlib import Path

import pytest
import yaml

from trace_analyzer.config import load_config

CFG = load_config()
GT = yaml.safe_load((Path(__file__).parent / "fixtures" / "ground_truth.yaml").read_text(encoding="utf-8"))
OFFSET = GT["run"]["pcapng_to_canoe_offset_s"]


def tshark_fields(display_filter: str, *fields: str) -> list[list[str]]:
    cmd = [
        CFG["wireshark"]["tshark"], "-r", str(CFG["data"]["pcapng"]),
        "-o", f"sci.tds_bl:{CFG['protocol']['sci_tds_baseline']}",
        "-Y", display_filter, "-T", "fields", "-E", "separator=|",
    ]
    for field in fields:
        cmd += ["-e", field]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=True).stdout
    return [line.split("|") for line in out.splitlines()]


def test_rasta_message_counts():
    counts = Counter(t for (types,) in tshark_fields("rasta_saf", "rasta.type") for t in types.split(","))
    expected = GT["counts"]["rasta"]
    assert counts["0x1838"] == expected["connection_request"]
    assert counts["0x1839"] == expected["connection_response"]
    assert counts["0x1848"] == expected["disconnection_request"]
    assert counts["0x184c"] == expected["heartbeat"]
    assert counts["0x1860"] == expected["data"]


def test_sci_telegram_counts():
    counts = Counter(t for (types,) in tshark_fields("sci", "sci.messageType") for t in types.split(","))
    for code, expected in GT["counts"]["sci_telegrams"].items():
        assert counts[code] == expected, code


def test_gfma_status_timeline():
    rows = tshark_fields(
        "sci.messageType == 0x0007",
        "frame.number", "frame.time_relative", "scitds5.belegung", "scitds5.grundstell", "scitds5.zaehlstand",
    )
    assert len(rows) == len(GT["gfma_status"])
    for (frame, t, bel, grund, zaehl), (gt_t, gt_bel, gt_grund, gt_zaehl, gt_frame) in zip(rows, GT["gfma_status"]):
        assert int(frame) == gt_frame
        assert float(t) + OFFSET == pytest.approx(gt_t, abs=0.002)
        assert (int(bel, 16), int(grund, 16), int(zaehl, 16)) == (gt_bel, gt_grund, gt_zaehl)


def test_command_times():
    rows = tshark_fields("sci.messageType in {0x0001, 0x0003}", "frame.time_relative", "sci.messageType")
    assert len(rows) == len(GT["commands"])
    for (t, code), (gt_t, gt_code, _origin) in zip(rows, GT["commands"]):
        assert code == gt_code
        assert float(t) + OFFSET == pytest.approx(gt_t, abs=0.003)
