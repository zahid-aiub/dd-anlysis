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
