"""Each rule on small synthetic contexts: it fires on the failure and stays silent on normal traffic."""

from dataclasses import replace

from builders import CONFIG, ZE_ID, case, context, rasta, session, spec, status, step, tel

from trace_analyzer.model import (
    Alignment,
    ConsistencyCheck,
    Direction,
    EventKind,
    EvidenceRef,
    FailureCategory as C,
    FrameDifference,
    MergeStats,
    RastaType,
    Severity,
    Source,
    SpecStep,
    TraceEvent,
    ValueCheck,
    Verdict,
)
from trace_analyzer.rules import DEFAULT_RULES, diagnose, run_rules
from trace_analyzer.rules.config import ConfigurationRule, TimeAlignmentRule
from trace_analyzer.rules.connection import ConnectionRule, SequenceRule
from trace_analyzer.rules.protocol import (
    CommandRejectedRule,
    LengthRule,
    OrderRule,
    PayloadRule,
    ProtocolResponseRule,
    SpecExpectationRule,
)
from trace_analyzer.rules.state import (
    AbortRule,
    CascadeRule,
    DeviceStateRule,
    ManualInterventionRule,
    PreconditionRule,
    TestStepRule,
)

TX, RX = Direction.TX, Direction.RX
TC = "TC_NPRO.295.00001.01(O)"


def categories(findings):
    return [f.category for f in findings]


def test_normal_session_produces_no_findings():
    ctx = context(session(0.0, 10.0), [case(TC, 0.0, 20.0)])
    assert run_rules(ctx) == []


# --- protocol ----------------------------------------------------------------------------------------------

def test_missing_version_report():
    events = [e for e in session(0.0, 5.0) if e.msg_type != 0x0025]
    findings = ProtocolResponseRule().evaluate(context(events))
    assert categories(findings) == [C.MISSING_MESSAGE] and "MELDUNG_BTP_VERSIONSABGLEICH" in findings[0].summary


def test_late_aufruestbeginn_is_a_timeout():
    late = (0x0022, 0x0007, 0x0023)
    events = [e for e in session(0.0, 5.0) if e.msg_type not in late or e.kind is not EventKind.SCI_TELEGRAM]
    events += [tel(1.4, 0x0022, RX), status(1.4, 1), tel(1.4, 0x0023, RX)]
    findings = ProtocolResponseRule().evaluate(context(events))
    assert categories(findings) == [C.TIMEOUT] and findings[0].details["delay_s"] > 0.5


SEND_AZGH = SpecStep(1, "BTP", "ZE:O", "Kd_AZGH", "", message_type=0x0003)
NOT_STATUS = SpecStep(2, "BTP", "NOT", "NOT (Md_GFM_A_Belegungszustand)", "", 0x0007, True, 0.5)
EXPECT_STATUS = SpecStep(2, "BTP", "TDS:O", "Md_GFM_A_Belegungszustand", "", 0x0007, False, 0.5,
                         {"43": "0x02", "44": "0x01"})


def spec_context(*extra, spec_step=NOT_STATUS):
    steps = [step(2.0, "Main Part", "1", "Sende 'Kommando AchszaehlgrundstellungHilfsbedienung'")]
    events = session(0.0, 9.0) + [tel(2.002, 0x0003, TX), *extra]
    return context(events, [case("TC_X(O)", 0.0, 10.0, Verdict.FAIL, steps)], [spec("TC_X", SEND_AZGH, spec_step)])


def test_forbidden_status_after_command():
    findings = SpecExpectationRule().evaluate(spec_context(status(2.1, 2, 1, 1)))
    assert categories(findings) == [C.UNEXPECTED_RESPONSE] and findings[0].details["spec_step"] == 2


def test_no_forbidden_status():
    assert SpecExpectationRule().evaluate(spec_context()) == []


def test_expected_status_too_late():
    findings = SpecExpectationRule().evaluate(spec_context(status(2.9, 2, 1, 1), spec_step=EXPECT_STATUS))
    assert categories(findings) == [C.TIMEOUT]


def test_expected_status_missing():
    findings = SpecExpectationRule().evaluate(spec_context(spec_step=EXPECT_STATUS))
    assert categories(findings) == [C.MISSING_MESSAGE]


def test_expected_status_with_wrong_bytes():
    raw = bytes(43) + bytes([0x02, 0x00, 0x01, 0x00])
    findings = SpecExpectationRule().evaluate(spec_context(status(2.1, 2, 0, 1, raw=raw), spec_step=EXPECT_STATUS))
    assert categories(findings) == [C.INVALID_PAYLOAD] and "BTP[44]" in findings[0].summary


def test_spec_rule_does_not_apply_without_main_part():
    ctx = context(session(0.0, 9.0), [case("TC_X(O)", 0.0, 10.0, Verdict.FAIL)], [spec("TC_X", SEND_AZGH, NOT_STATUS)])
    assert not SpecExpectationRule().applies_to(ctx.test_cases[0], ctx)


def test_aufruestanforderung_before_version_check():
    events = [e for e in session(0.0, 5.0) if e.msg_type != 0x0021] + [tel(0.1, 0x0021, TX)]
    findings = OrderRule().evaluate(context(events))
    assert categories(findings) == [C.WRONG_ORDER] and "before KOMMANDO_BTP_VERSIONSABGLEICH" in findings[0].summary


def test_command_before_aufruestende():
    events = [e for e in session(0.0, 5.0) if e.msg_type != 0x0023] + [tel(0.85, 0x0003, TX), tel(0.9, 0x0023, RX)]
    assert categories(OrderRule().evaluate(context(events))) == [C.WRONG_ORDER]


def test_invalid_payload_values_and_identifiers():
    events = session(0.0, 5.0) + [status(2.0, 7), tel(3.0, 0x0003, TX, sender="SOMEONE ELSE"),
                                  tel(4.0, 0x0021, TX, protocol_type=0x30)]
    findings = PayloadRule().evaluate(context(events))
    assert categories(findings) == [C.INVALID_PAYLOAD] * 3
    assert "belegung=7" in findings[0].summary and ZE_ID in findings[1].summary and "0x30" in findings[2].summary


def test_wrong_telegram_length():
    events = session(0.0, 5.0) + [status(2.0, 1, 0, 0, length=46)]
    findings = LengthRule().evaluate(context(events))
    assert categories(findings) == [C.INCORRECT_LENGTH] and findings[0].details == {"actual": 46, "expected": 47}


def test_failed_length_check_in_report():
    s = replace(step(2.0, "Main Part", "1", "Validiere BTP-Nachricht", Verdict.FAIL),
                checks=(ValueCheck("Validiere Laenge", "Laenge", "44", "43", False),))
    findings = LengthRule().evaluate(context(session(0.0, 5.0), [case(TC, 0.0, 6.0, Verdict.FAIL, [s])]))
    assert categories(findings) == [C.INCORRECT_LENGTH]


def test_command_rejected():
    events = session(0.0, 5.0) + [tel(2.0, 0x0003, TX), tel(2.3, 0x0006, RX, abweisungsgrund=1)]
    findings = CommandRejectedRule().evaluate(context(events))
    assert [f.summary for f in findings] == ["KOMMANDO_AZGH rejected (betrieblich)"]


# --- connection --------------------------------------------------------------------------------------------

def test_heartbeat_gap():
    events = [e for e in session(0.0, 10.0) if not (4.0 < e.time < 6.0 and e.kind is EventKind.RASTA)]
    findings = ConnectionRule().evaluate(context(events))
    assert categories(findings) == [C.CONNECTION_INTERRUPTION, C.CONNECTION_INTERRUPTION]   # both directions
    assert findings[0].details["gap_s"] > 1.5


def test_disconnect_by_device_with_timeout_reason():
    findings = ConnectionRule().evaluate(context(session(0.0, 3.0, closed_by=RX, reason=4)))
    assert sorted(f.summary for f in findings) == ["Connection closed with reason timeout",
                                                   "Device under test closed the connection"]


def test_unanswered_connection_request():
    events = [rasta(0.0, RastaType.CONNECTION_REQUEST, TX)]
    assert categories(ConnectionRule().evaluate(context(events))) == [C.CONNECTION_INTERRUPTION]


def test_sequence_gap_and_retransmission():
    events = session(0.0, 3.0)
    heartbeats = [e for e in events if e.msg_type == RastaType.HEARTBEAT and e.direction is RX]
    events.remove(heartbeats[2])
    events.append(rasta(2.0, RastaType.RETRANSMISSION_REQUEST, TX, 99))
    findings = SequenceRule().evaluate(context(events))
    assert {(f.category, f.severity) for f in findings} == {(C.SEQUENCE_ERROR, Severity.ERROR),
                                                           (C.SEQUENCE_ERROR, Severity.WARNING)}


# --- state and test flow -----------------------------------------------------------------------------------

def disturbed_run():
    """Two test cases; GFM-A turns disturbed in the first, the second starts disturbed."""
    tc1 = case("TC_A(O)", 0.0, 30.0, Verdict.FAIL, [
        step(1.0, "Preparation", "Init", "Sollzustand: Belegungszustand=2, Grundstellbarkeit=0."),
        step(20.0, "Preparation", "Init", "Vorbereitung nicht abgeschlossen", Verdict.FAIL),
        step(25.0, "Completion", "Cleanup", "Cleanup fehlgeschlagen", Verdict.FAIL)])
    tc2 = case("TC_B(F)", 30.0, 60.0, Verdict.FAIL, [
        step(31.0, "Preparation", "Init", "Kein AZG/AZGH am Panel senden."),
        step(50.0, "Preparation", "Init", "Zeitlimit abgelaufen", Verdict.FAIL)])
    events = session(0.0, 26.0) + session(30.0, 55.0, state=(3, 0, 0)) + [
        status(5.0, 2, 0, 0), status(5.1, 3, 0, 0), status(8.0, 3, 1, 0), status(12.0, 3, 0, 0),
        TraceEvent(40.0, EventKind.OPERATOR_ACTION, EvidenceRef(Source.BLF, "x.blf", "object 1"), name="kdSelection",
                   fields={"value": 3, "command": "KOMMANDO_AZGH"}),
        tel(40.001, 0x0003, TX)]
    return context(events, [tc1, tc2])


def test_device_disturbed_with_precursor_and_inherited():
    findings = DeviceStateRule().evaluate(disturbed_run())
    first, inherited = findings
    assert (first.time, first.details["inherited"], first.details["precursor"]["state"]) == (5.1, False, [2, 0, 0])
    assert first.details["reset_windows"] == [(8.0, 12.0)] and "no AZG/AZGH sent" in first.summary
    assert (inherited.time, inherited.test_case, inherited.details["inherited"]) == (30.8, "TC_B(F)", True)


def test_precondition_target_vs_actual():
    findings = PreconditionRule().evaluate(disturbed_run())
    assert [(f.time, f.details["target"], f.details["actual"]) for f in findings] == [
        (20.0, [2, 0], [3, 0, 0]), (50.0, None, [3, 0, 0])]


def test_cascade_from_failed_cleanup():
    findings = CascadeRule().evaluate(disturbed_run())
    assert [(f.test_case, f.severity, f.details["caused_by"]) for f in findings] == [("TC_B(F)", Severity.ERROR, "TC_A(O)")]


def test_manual_command_against_instruction():
    (f,) = ManualInterventionRule().evaluate(disturbed_run())
    assert f.severity is Severity.WARNING and f.details["forbidden"] and not f.details["effect"]


def test_failed_main_part_step():
    tc = case(TC, 0.0, 10.0, Verdict.FAIL, [step(5.0, "Main Part", "2", "Antwort fehlt", Verdict.FAIL)])
    (f,) = TestStepRule().evaluate(context(session(0.0, 9.0), [tc]))
    assert f.category is C.TEST_STEP_FAILED and f.details["spec_step"] == 2


def test_test_unit_stopped():
    log = TraceEvent(5.0, EventKind.LOG, EvidenceRef(Source.CANOE_LOG, "x.txt", "line 3"),
                     fields={"level": "error", "text": "Test unit 'SCI-TDS': Execution stop forced."})
    (f,) = AbortRule().evaluate(context([log], [case(TC, 4.0, 5.0, Verdict.INCONCLUSIVE)]))
    assert f.category is C.TEST_ABORTED and f.details["detail"] == "test_unit_stopped_by_user"


def test_device_state_is_tracked_per_element():
    events = session(0.0, 9.0) + [status(2.0, 3, sender="35W2"), status(3.0, 1), status(4.0, 3, sender="35W2")]
    findings = DeviceStateRule().evaluate(context(events, [case(TC, 0.0, 10.0, Verdict.FAIL)]))
    # 35W2 stays disturbed: one finding, even though 34W1 reports "frei" in between
    assert [(f.time, f.details["element"]) for f in findings] == [(2.0, "35W2")]


# --- configuration and data quality ------------------------------------------------------------------------

BL7_STATUS = SpecStep(2, "BTP", "TDS:O", "Md", "", 0x0007, False, 0.5, {"44": "0x02", "45..46": "0xFFFF", "47": "0xFF"})


def test_spec_expects_other_baseline_and_version():
    ctx = context([], [case("TC_X(O)", 0.0, 1.0, version="5")], [spec("TC_X", SEND_AZGH, BL7_STATUS, version="4")])
    findings = ConfigurationRule().evaluate(ctx)
    assert categories(findings) == [C.CONFIGURATION_MISMATCH] * 2
    assert any("not a valid BL5 grundstellbar" in p for p in findings[0].details["problems"])


def test_spec_layout_longer_than_sent_telegram_is_a_length_failure():
    events = session(0.0, 5.0)    # start-up reports a 47-byte BL5 status
    ctx = context(events, [case("TC_X(O)", 0.0, 10.0)], [spec("TC_X", SEND_AZGH, BL7_STATUS)])
    (f,) = LengthRule().evaluate(ctx)
    assert f.category is C.INCORRECT_LENGTH and f.severity is Severity.ERROR
    assert (f.details["expected"], f.details["actual"], f.details["spec_step"]) == (48, 47, 2)
    assert f.details["bytes_beyond"] == ["47"] and f.time == 0.8


def test_spec_length_failure_does_not_explain_a_preparation_failure():
    steps = [step(5.0, "Preparation", "", "Sollzustand: Belegungszustand=2, Grundstellbarkeit=0", Verdict.FAIL)]
    events = session(0.0, 9.0) + [status(2.0, 3)]
    ctx = context(events, [case("TC_X(O)", 0.0, 10.0, Verdict.FAIL, steps)], [spec("TC_X", SEND_AZGH, BL7_STATUS)])
    (d,) = diagnose(ctx, run_rules(ctx))
    assert (d.symptom.category, d.cause.category) == (C.PRECONDITION_NOT_REACHED, C.DEVICE_DISTURBED)
    assert C.INCORRECT_LENGTH in {f.category for f in d.contributing}


def test_frames_recorded_differently_by_the_two_captures():
    a = rasta(1.0, RastaType.DATA, RX, 5)
    differs = [FrameDifference(1.0, a.ref, EvidenceRef(Source.BLF, "x.blf", "object 9"), 82, 81, 80, "DATA"),
               FrameDifference(2.0, a.ref, EvidenceRef(Source.BLF, "x.blf", "object 12"), 82, 82, 51, "DATA")]
    ctx = context(session(0.0, 5.0), [case(TC, 0.0, 10.0)], merge=MergeStats(Source.PCAPNG, Source.BLF, 10,
                                                                                differing=tuple(differs)))
    (length,) = LengthRule().evaluate(ctx)
    (payload,) = PayloadRule().evaluate(ctx)
    assert length.category is C.INCORRECT_LENGTH and "82 bytes" in length.summary and "81 bytes" in length.summary
    assert payload.category is C.INVALID_PAYLOAD and "from byte 51" in payload.summary
    assert TimeAlignmentRule().evaluate(ctx) == []


def test_main_part_started_in_wrong_state():
    precondition = 'OC: Normal operation; BP: GFM-A is in the state "GFM-A occupied and cannot be primed"'
    occupied = replace(spec("TC_X", SEND_AZGH, NOT_STATUS), precondition=precondition)
    steps = [step(2.0, "Main Part", "1", "Sende 'Kommando AchszaehlgrundstellungHilfsbedienung'")]
    ctx = context(session(0.0, 9.0), [case("TC_X(O)", 0.0, 10.0, steps=steps)], [occupied])   # state stays 1/0
    (f,) = PreconditionRule().evaluate(ctx)
    assert f.category is C.PRECONDITION_NOT_REACHED and f.time == 2.0
    assert (f.details["target"], f.details["actual"][:2], f.details["target_source"]) == ([2, 0], [1, 0],
                                                                                          "Test_Description")
    (d,) = diagnose(ctx, run_rules(ctx))
    assert d.verdict is Verdict.FAIL and d.symptom == f


def test_spec_and_report_disagree_on_the_target_state():
    precondition = 'BP: GFM-A ist im Zustand "GFM-A belegt und grundstellbar"'
    steps = [step(1.0, "Preparation", "", "Sollzustand: Belegungszustand=2, Grundstellbarkeit=0")]
    ctx = context([], [case("TC_X(O)", 0.0, 10.0, steps=steps)],
                  [replace(spec("TC_X", SEND_AZGH), precondition=precondition)])
    (f,) = ConfigurationRule().evaluate(ctx)
    assert f.details["spec_target"] == [2, 1] and f.details["report_target"] == [2, 0]


def test_time_alignment_warnings():
    ctx = context([], alignments={Source.PCAPNG: Alignment(Source.PCAPNG, 0.0, "first_frame", note="no reference")},
                  checks=[ConsistencyCheck("gfma_status", (Source.PCAPNG, Source.CANOE_LOG), 3, 0.02, 1)],
                  merge=MergeStats(Source.PCAPNG, Source.BLF, 10, (), ("object 7",)))
    findings = TimeAlignmentRule().evaluate(ctx)
    assert categories(findings) == [C.TIME_ALIGNMENT] * 3


# --- engine ------------------------------------------------------------------------------------------------

def test_diagnosis_symptom_cause_and_ruled_out():
    ctx = disturbed_run()
    diagnoses = {d.test_case.name: d for d in diagnose(ctx, run_rules(ctx))}
    first, second = diagnoses["TC_A(O)"], diagnoses["TC_B(F)"]
    assert (first.symptom.category, first.cause.category) == (C.PRECONDITION_NOT_REACHED, C.DEVICE_DISTURBED)
    assert (second.symptom.category, second.cause.category) == (C.PRECONDITION_NOT_REACHED, C.CASCADE_FAILURE)
    assert {f.category for f in second.contributing} == {C.DEVICE_DISTURBED, C.MANUAL_INTERVENTION}
    assert C.CONNECTION_INTERRUPTION in first.ruled_out and C.MANUAL_INTERVENTION not in first.ruled_out


def test_precise_step_finding_replaces_generic_symptom():
    steps = [step(2.0, "Main Part", "1", "Sende 'Kommando AchszaehlgrundstellungHilfsbedienung'"),
             step(2.5, "Main Part", "2", "Antwort fehlt", Verdict.FAIL)]
    events = session(0.0, 9.0) + [tel(2.002, 0x0003, TX)]
    ctx = context(events, [case("TC_X(O)", 0.0, 10.0, Verdict.FAIL, steps)], [spec("TC_X", SEND_AZGH, EXPECT_STATUS)])
    (d,) = diagnose(ctx, run_rules(ctx))
    assert d.symptom.category is C.MISSING_MESSAGE and d.cause is d.symptom


def test_every_default_rule_declares_categories():
    assert all(rule.categories for rule in DEFAULT_RULES)
    assert {c for rule in DEFAULT_RULES for c in rule.categories} == set(C)
    assert CONFIG["nodes"]["test_system"]["id"] == ZE_ID


def test_spec_preconditions_parsed():
    from trace_analyzer.rules.common import spec_target_state

    def target(text):
        return spec_target_state(replace(spec("TC_X"), precondition=text))

    assert target('OC: Normal operation; BP: GFM-A is in the state "GFM-A occupied and cannot be primed"') == (2, 0)
    assert target('OC: Normal operation; BP: GFM-A is in the state "GFM-A free and not primeable"') == (1, 0)
    assert target('OC: REGELBETRIEB; BP: GFM-A ist im Zustand "GFM-A belegt und grundstellbar"') == (2, 1)
    assert target('BP: GFM-A is in the state ""GFM-A occupied and ready for basic operation""') == (2, 1)
    assert target('BP: GFM-A is in the state "GFM-A disturbed"') == (3, 0)
    assert target("OC: Normal operation") is None
