from pathlib import Path

import pytest
import yaml

from trace_analyzer.model import (
    AnalysisContext,
    EventKind,
    EvidenceRef,
    FailureCategory,
    RastaType,
    SciMessage,
    Source,
    TestCaseResult,
    TestStep,
    TraceEvent,
    Verdict,
    split_test_name,
)
from trace_analyzer.model.protocol import BL5_TELEGRAM_LENGTH, BTP_HEADER_LENGTH

REF = EvidenceRef(Source.PCAPNG, "RealOCWorking_TDS_21026.pcapng", "frame 425")


def event(t: float, **kw) -> TraceEvent:
    return TraceEvent(time=t, kind=EventKind.SCI_TELEGRAM, ref=REF, **kw)


def test_shifted_keeps_native_time():
    ev = event(183.490774, fields={"belegung": 3})
    aligned = ev.shifted(3.4623)
    assert aligned.time == pytest.approx(186.953074)
    assert aligned.source_time == 183.490774
    # shifting again starts from the native time, not from the already aligned one
    assert aligned.shifted(3.4623).time == pytest.approx(aligned.time)


def test_event_is_hashable_despite_dict_fields():
    assert len({event(1.0, fields={"a": 1}), event(1.0, fields={"a": 1})}) == 1


def test_evidence_ref_str():
    assert str(REF) == "RealOCWorking_TDS_21026.pcapng frame 425"


@pytest.mark.parametrize(
    "name, expected",
    [
        ("TC_NPRO.295.02288.01(O)", ("TC_NPRO.295.02288.01", "O")),
        ("TC_NPRO.295.00525.01(F-ReZE)", ("TC_NPRO.295.00525.01", "F-ReZE")),
        ("TC_NPRO.295.02284.01", ("TC_NPRO.295.02284.01", None)),
    ],
)
def test_split_test_name(name, expected):
    assert split_test_name(name) == expected


def test_test_case_result_helpers():
    tc = TestCaseResult(
        name="TC_NPRO.295.02288.01(O)",
        verdict=Verdict.FAIL,
        start=139.515,
        end=313.489,
        steps=[
            TestStep(180.287, "Init", "BTP-Verbindung wurde erfolgreich aufgebaut", Verdict.PASS),
            TestStep(300.288, "Init", "Vorbereitung frei -> belegt nicht abgeschlossen", Verdict.FAIL),
        ],
    )
    assert tc.test_id == "TC_NPRO.295.02288.01"
    assert tc.variant == "O"
    assert [s.time for s in tc.failed_steps] == [300.288]
    assert tc.contains(186.953) and not tc.contains(313.489)


def test_sci_message_vocabulary():
    assert SciMessage.KOMMANDO_AZGH.is_command
    assert not SciMessage.MELDUNG_GFMA_BELEGUNGSZUSTAND.is_command
    assert SciMessage.MELDUNG_GFMA_BELEGUNGSZUSTAND.spec_section == "3.4.11"
    assert BL5_TELEGRAM_LENGTH[SciMessage.KOMMANDO_AZGH] == BTP_HEADER_LENGTH
    assert BL5_TELEGRAM_LENGTH[SciMessage.MELDUNG_GFMA_BELEGUNGSZUSTAND] == BTP_HEADER_LENGTH + 4


def test_rasta_codes_match_wireshark_hex():
    assert RastaType.CONNECTION_REQUEST == 0x1838
    assert RastaType.DISCONNECTION_REQUEST == 0x1848
    assert RastaType.HEARTBEAT == 0x184C
    assert RastaType.DATA == 0x1860


def test_context_window():
    ctx = AnalysisContext(events=[event(1.0), event(2.0), event(3.0)], test_cases=[], specs={}, sessions=[], config={})
    assert [e.time for e in ctx.window(1.5, 3.0)] == [2.0]


def test_ground_truth_uses_known_categories():
    gt = yaml.safe_load((Path(__file__).parent / "fixtures" / "ground_truth.yaml").read_text(encoding="utf-8"))
    names = set()
    for tc in gt["test_cases"]:
        diag = tc.get("expected_diagnosis")
        if not diag:
            continue
        names |= {diag["symptom"]["category"], diag["cause"]["category"]}
        names |= {c["category"] for c in diag.get("contributing", [])}
        names |= set(diag.get("ruled_out", []))
    assert names <= {c.value for c in FailureCategory}
