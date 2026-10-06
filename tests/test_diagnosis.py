"""End-to-end analysis of the RealOC run against the Phase 1 ground truth."""

from pathlib import Path

import pytest
import yaml

from trace_analyzer.config import load_config
from trace_analyzer.model import FailureCategory as C
from trace_analyzer.model import Verdict
from trace_analyzer.pipeline import analyze

CFG = load_config()
GT = yaml.safe_load((Path(__file__).parent / "fixtures" / "ground_truth.yaml").read_text(encoding="utf-8"))
EXPECTED = {tc["name"]: tc for tc in GT["test_cases"]}

pytestmark = pytest.mark.skipif(not CFG["data"]["pcapng"].exists(), reason="RealOC data not available")


@pytest.fixture(scope="module")
def result():
    return analyze(CFG)


def by_name(result):
    return {d.test_case.name: d for d in result.diagnoses}


def test_all_test_cases_diagnosed(result):
    assert [(d.test_case.name, d.test_case.verdict.value.upper()) for d in result.diagnoses] == \
        [(tc["name"], tc["verdict"]) for tc in GT["test_cases"]]


@pytest.mark.parametrize("name", [n for n, tc in EXPECTED.items() if "expected_diagnosis" in tc])
def test_diagnosis_matches_ground_truth(result, name):
    expected = EXPECTED[name]["expected_diagnosis"]
    d = by_name(result)[name]

    assert d.symptom.category.value == expected["symptom"]["category"]
    assert d.symptom.time == pytest.approx(expected["symptom"]["time"], abs=0.002)
    assert d.cause.category.value == expected["cause"]["category"]
    if "time" in expected["cause"]:
        assert d.cause.time == pytest.approx(expected["cause"]["time"], abs=0.002)
    if "caused_by" in expected["cause"]:
        assert d.cause.details["caused_by"] == expected["cause"]["caused_by"]
    if "detail" in expected["cause"]:
        assert d.cause.details["detail"] == expected["cause"]["detail"]

    for item in expected.get("contributing", []):
        found = [f for f in d.contributing if f.category.value == item["category"]]
        for t in item.get("times", [item.get("time")]):
            assert any(abs(f.time - t) < 0.002 for f in found), (item["category"], t)
        for key in ("spec_step", "expected", "actual"):
            if key in item:
                assert any(f.details.get(key) == item[key] for f in found), (item["category"], key)
    assert {c.value for c in d.ruled_out} >= set(expected.get("ruled_out", []))
    if expected.get("cleanup_failed"):
        assert any(s.verdict is Verdict.FAIL and s.section == "Completion" for s in d.test_case.steps)


def test_precursor_of_the_disturbance(result):
    cause = by_name(result)["TC_NPRO.295.02288.01(O)"].cause
    precursor = EXPECTED["TC_NPRO.295.02288.01(O)"]["expected_diagnosis"]["precursor"]
    assert cause.details["precursor"]["time"] == pytest.approx(precursor["time"], abs=0.002)
    assert cause.details["precursor"]["state"] == [precursor["belegung"], 0, precursor["achszaehlfuellstand"]]
    assert cause.details["resets_in_window"] == []
    assert [round(b - a, 1) for a, b in cause.details["reset_windows"]] == [50.0]


def test_passed_test_cases_have_no_errors(result):
    for d in result.diagnoses:
        if d.test_case.verdict is Verdict.PASS:
            assert d.symptom is None and d.cause is None
            assert all(f.severity.value != "error" for f in d.contributing)


def test_no_protocol_or_connection_findings(result):
    """The RealOC run has no telegram or connection faults; these rules must stay silent."""
    silent = {C.TIMEOUT, C.MISSING_MESSAGE, C.UNEXPECTED_RESPONSE, C.WRONG_ORDER, C.INVALID_PAYLOAD,
              C.CONNECTION_INTERRUPTION, C.SEQUENCE_ERROR, C.COMMAND_REJECTED, C.TIME_ALIGNMENT}
    assert [f for f in result.findings if f.category in silent] == []
    # every captured telegram has its BL5 length; the only length failure is the spec layout of 02288 step 2
    lengths = [f for f in result.findings if f.category is C.INCORRECT_LENGTH]
    assert [(f.test_case, f.details["spec_step"]) for f in lengths] == [("TC_NPRO.295.02288.01(O)", 2)]


def test_preconditions_from_the_test_description(result):
    """Step 1 of the analysis: the .txt precondition is the target state; passed tests started in it."""
    targets = {f.test_case: (f.details["target"], f.details["target_source"]) for f in result.findings
               if f.category is C.PRECONDITION_NOT_REACHED}
    assert targets == {"TC_NPRO.295.02288.01(O)": ([2, 0], "Test_Description"),
                       "TC_NPRO.295.00525.01(F-ReZE)": ([1, 0], "Test_Description")}


def test_analyzer_verdicts(result):
    assert [d.verdict.value for d in result.diagnoses] == ["pass", "pass", "fail", "fail", "inconclusive"]


def test_findings_carry_evidence(result):
    for f in result.findings:
        if f.category not in (C.CONFIGURATION_MISMATCH,):
            assert f.evidence, f.summary
