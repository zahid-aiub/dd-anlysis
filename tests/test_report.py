"""Reports: content of the 02288 example, timeline SVG, both formats, and the command line."""

import re
import xml.etree.ElementTree as ET

import pytest

from trace_analyzer.cli import main
from trace_analyzer.config import load_config
from trace_analyzer.pipeline import analyze
from trace_analyzer.report import build_report, render, write_reports
from trace_analyzer.report.timeline import nice_step

CFG = load_config()

pytestmark = pytest.mark.skipif(not CFG["data"]["pcapng"].exists(), reason="RealOC data not available")


@pytest.fixture(scope="module")
def result():
    return analyze(CFG)


def test_report_of_02288(result):
    (case,) = build_report(result, ["02288"]).cases
    assert case.headline == "FAILED"
    assert case.symptom.category == "precondition_not_reached" and case.cause.category == "device_disturbed"
    assert case.target_state == "2/0" and "occupied and cannot be primed" in case.precondition
    assert "TC_NPRO.295.00525.01(F-ReZE)" in case.consequence
    assert {"pcapng", "BLF", "CANoe log"} <= set(case.sources)
    assert [str(e.ref) for e in case.cause.evidence] == ["RealOCWorking_TDS_21026.pcapng frame 423 telegram 1",
                                                         "RealOCWorking_TDS_21026.pcapng frame 425 telegram 1"]
    assert case.cause.evidence[1].clock == "12:27:06.906"
    assert [v.category for v in case.contributing][0] == "incorrect_length"
    lanes = {e.lane for e in case.events}
    assert {"tx", "rx", "step", "rasta"} <= lanes
    assert any(e.status == "fail" and "nicht abgeschlossen" in e.text for e in case.events)


def test_markdown_and_html(result, tmp_path):
    paths = write_reports(result, tmp_path)
    names = sorted(p.name for p in paths)
    assert "report.md" in names and "report.html" in names and "timeline_legend.svg" in names
    assert len([n for n in names if n.startswith("timeline_tc_")]) == 5
    md = (tmp_path / "report.md").read_text(encoding="utf-8")
    assert "Test Result:       FAILED (TC_NPRO.295.02288.01)" in md
    assert "Root cause:        186.953 s  34W1 became disturbed" in md
    assert "Category:          Field element / test bench state (device_disturbed)" in md
    assert "Test Result:       INCONCLUSIVE (TC_NPRO.295.00522.01)" in md
    assert "![Timeline of TC_NPRO.295.02288.01(O)](timeline_tc_npro-295-02288-01.svg)" in md
    html = (tmp_path / "report.html").read_text(encoding="utf-8")
    assert html.count('<svg class="tl"') == 10            # five timelines, five legends
    assert "<script" not in html and "http" not in re.sub(r'xmlns="http[^"]+"', "", html)   # self-contained


def test_timeline_svg_is_valid_xml(result):
    report = build_report(result)
    render(result, report, "html")
    for case in report.cases:
        root = ET.fromstring(case.timeline_svg)
        assert root.tag.endswith("svg")
    svg = next(c for c in report.cases if "02288" in c.name).timeline_svg
    assert "cause · device_disturbed · 186.953 s" in svg and "symptom · precondition_not_reached · 300.288 s" in svg
    assert svg.count("<title>") > 20                       # every mark has a tooltip


def test_nice_ticks():
    assert nice_step(174.0) == 50 and nice_step(80.0) == 10 and nice_step(0.8) == 0.1


def test_cli_single_test_case(tmp_path, capsys):
    assert main(["--out", str(tmp_path), "--format", "md", "--test-case", "02288", "--name", "tc"]) == 0
    out = capsys.readouterr().out
    assert "TC_NPRO.295.02288.01(O)" in out and "device_disturbed" in out
    md = (tmp_path / "tc.md").read_text(encoding="utf-8")
    assert "TC_NPRO.295.02288.01(O)" in md and "## TC_NPRO.295.02283.01" not in md
    assert not (tmp_path / "tc.html").exists()


def test_cli_errors(tmp_path, capsys):
    assert main(["--config", str(tmp_path / "missing.yaml")]) == 2
    assert main(["--out", str(tmp_path), "--test-case", "99999"]) == 2
    assert "no test case matches" in capsys.readouterr().err


def test_cli_on_a_synthetic_capture(tmp_path, capsys):
    from trace_analyzer.synthetic.runner import build_capture
    from trace_analyzer.synthetic.scenarios import SCENARIOS

    scenario = next(s for s in SCENARIOS if s.key == "unexpected_response")
    path, _ = build_capture(scenario, CFG, analyze(CFG), tmp_path)
    assert main(["--pcapng", str(path), "--no-blf-ethernet", "--out", str(tmp_path), "--format", "md",
                 "--test-case", "02284"]) == 0
    md = (tmp_path / "report.md").read_text(encoding="utf-8")
    assert "Test Result:       FAILED (report: passed) (TC_NPRO.295.02284.01)" in md
    assert "unexpected_response" in md and path.name in md


def test_json_export(result, tmp_path):
    import json

    from trace_analyzer.report import write_json
    from trace_analyzer.synthetic.runner import run_all
    from trace_analyzer.synthetic.scenarios import SCENARIOS

    scenarios = run_all(CFG, tmp_path, [s for s in SCENARIOS if s.number in ("3s", "7", "10", "14n")])
    doc = json.loads(write_json(result, tmp_path / "report.json", scenarios=scenarios).read_text(encoding="utf-8"))
    assert (doc["schema"], doc["schema_version"]) == ("trace-analyzer.report", 1)
    assert "test_cases" not in doc
    assert doc["summary"]["verdicts"] == {"pass": 2, "fail": 2, "inconclusive": 1}

    ids = {"TC_NPRO.295.02283.01", "TC_NPRO.295.02284.01", "TC_NPRO.295.02288.01", "TC_NPRO.295.00525.01",
           "TC_NPRO.295.00522.01"}
    for item in (*doc["findings"], *(x for v in doc["timeline"].values() for x in v)):
        assert item["test_case"] in ids | {None}
    cause = next(f for f in doc["findings"] if f["role"] == "cause" and f["test_case"] == "TC_NPRO.295.02288.01")
    assert cause["category"] == "device_disturbed" and cause["t"] == pytest.approx(186.953, abs=1e-3)
    assert cause["evidence"][1]["clock"].startswith("2026-10-02T12:27:06.906")

    states = [(s["t"], s["belegung"]) for s in doc["timeline"]["gfma_states"]]
    assert len(states) == 12 and (pytest.approx(186.953, abs=1e-3), 3) in states
    assert len(doc["timeline"]["telegrams"]) == 45 and len(doc["timeline"]["sessions"]) == 5

    by_number = {s["number"]: s for s in doc["scenarios"]}
    assert {n: s["outcome"] for n, s in by_number.items()} == {"3s": "failure", "7": "ruled_out", "10": "failure",
                                                               "14n": "warning"}
    assert all(s["check"]["as_expected"] for s in doc["scenarios"])
    s3 = by_number["3s"]
    assert s3["failure"]["category"] == "unexpected_response" and s3["failure"]["evidence"][1]["locator"] == \
        "frame 326 telegram 1"
    (r,) = s3["results"]
    assert (r["report_verdict"], r["verdict"], r["verdict_differs"]) == ("pass", "fail", True)
    assert r["cause"]["category"] == "unexpected_response"
    assert [f["category"] for f in r["findings"] if f["introduced"]] == ["unexpected_response"]
    assert by_number["7"]["failure"] is None
    assert doc["summary"]["scenarios"]["outcome"] == {"failure": 2, "warning": 1, "ruled_out": 1, "check": 0}


def test_cli_json(tmp_path):
    assert main(["--out", str(tmp_path), "--format", "json", "--test-case", "02288"]) == 0
    import json
    doc = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert {f["test_case"] for f in doc["findings"]} <= {"TC_NPRO.295.02288.01", None} and "scenarios" not in doc


def test_flat_json(result, tmp_path):
    import json

    from trace_analyzer.report import write_flat_json

    doc = json.loads(write_flat_json(result, tmp_path / "data-anlysis-report.json").read_text(encoding="utf-8"))
    assert list(doc)[:9] == ["analysis_id", "device_id", "timestamp", "analysis_type", "result_status", "summary",
                             "trace_messages", "failure_findings", "data_comparisons"]
    assert (doc["device_id"], doc["timestamp"], doc["result_status"]) == (
        "DETHMM AZA34##0001", "2026-10-02T10:23:59.953Z", "FAILED")
    assert doc["summary"].startswith("2 of 5 test cases failed.")

    messages = {m["message_id"]: m for m in doc["trace_messages"]}
    assert len(messages) == 45
    assert (messages["frame-425-1"]["status"], messages["frame-425-1"]["error_reason"]) == ("FAILED", "Device Disturbed")
    assert messages["frame-380-2"]["error_reason"] == "Message Length Error"
    assert messages["frame-11-1"]["status"] == "OK"

    length = next(f for f in doc["failure_findings"] if f["result"] == "Message Length Error")
    assert (length["message_id"], length["expected_length"], length["actual_length"]) == ("frame-380-2", 48, 47)
    assert all(f["message_id"] is None or f["message_id"] in messages for f in doc["failure_findings"])

    rows = {(c["field"], c["test_case"]): c for c in doc["data_comparisons"]}
    state = rows[("GFM-A state for the precondition", "TC_NPRO.295.02288.01")]
    assert (state["expected"], state["actual"], state["result"]) == (
        "2/0 (belegt, nicht grundstellbar)", "3/0 (gestört, nicht grundstellbar)", "Error")
    assert rows[("RaSTA message gap", None)]["result"] == "OK"
    assert {c["result"] for c in doc["data_comparisons"]} == {"OK", "Error", "Warning"}
