"""The 15 analysis scenarios: what each one is, which data shows it, and what the analyzer must conclude.

Real scenarios are checked on the RealOC run as it is. Synthetic scenarios edit a copy of the RealOC pcapng
(see `capture.py`) and run the analyzer on it together with the real PDF report, CANoe log, Test_Description and
the BLF's CANoe objects. Only the network trace changes, so the report may still say "pass" where the analyzer
finds a failure; the analyzer's own verdict (`Diagnosis.verdict`) is what the scenario checks.
"""

from collections.abc import Callable
from dataclasses import dataclass, field

from trace_analyzer.model import Belegung, Direction, FailureCategory, SciMessage, Source, Verdict
from trace_analyzer.pipeline import AnalysisResult

from .capture import Capture, telegram

C = FailureCategory
TX, RX = Direction.TX, Direction.RX

TC1, TC2, TC3, TC4, TC5 = ("TC_NPRO.295.02283.01", "TC_NPRO.295.02284.01", "TC_NPRO.295.02288.01",
                           "TC_NPRO.295.00525.01", "TC_NPRO.295.00522.01")


@dataclass(frozen=True, slots=True)
class Expectation:
    """What the analyzer must report for one test case.

    role: "cause" / "symptom" (of the diagnosis), "finding" (any finding of the test case), "ruled_out".
    """

    test_id: str | None                # None: a run-level finding (no test case)
    category: FailureCategory
    role: str = "finding"
    verdict: Verdict | None = None     # analyzer verdict of the test case
    contains: str | None = None        # text the finding's summary must contain


@dataclass(frozen=True, slots=True)
class Scenario:
    number: str
    key: str
    title: str
    detection: str
    sources: str
    expectations: tuple[Expectation, ...]
    mutate: Callable[[Capture, AnalysisResult], None] | None = None
    blf_ethernet: bool = False         # synthetic: keep the BLF frames to compare them with the edited pcapng
    check: Callable[[AnalysisResult], list[str]] | None = None   # extra checks, returns problems

    @property
    def synthetic(self) -> bool:
        return self.mutate is not None


def window(base: AnalysisResult, test_id: str) -> tuple[float, float]:
    tc = next(tc for tc in base.context.test_cases if tc.test_id == test_id)
    return tc.start, tc.end


def step_time(base: AnalysisResult, test_id: str, title: str) -> float:
    tc = next(tc for tc in base.context.test_cases if tc.test_id == test_id)
    return next(s.time for s in tc.steps if s.section == "Main Part" and s.title.startswith(title))


def startup_report(cap: Capture, base: AnalysisResult, test_id: str):
    """The RX frame with Aufrüstbeginn, start-up status and Aufrüstende of the test case's session."""
    return cap.first(sci=SciMessage.MELDUNG_AUFRUESTBEGINN, direction=RX, start=window(base, test_id)[0])


def status_template(cap: Capture) -> bytes:
    frame = cap.first(sci=SciMessage.MELDUNG_GFMA_BELEGUNGSZUSTAND, direction=RX)
    return frame.rasta.app_data[frame.message_types.index(SciMessage.MELDUNG_GFMA_BELEGUNGSZUSTAND)]


def azgh_step(cap: Capture, base: AnalysisResult, test_id: str):
    t = step_time(base, test_id, "Sende 'Kommando AchszaehlgrundstellungHilfsbedienung'")
    return cap.first(sci=SciMessage.KOMMANDO_AZGH, direction=TX, start=t - 0.01)


# --- edits -------------------------------------------------------------------------------------------------

def delay_startup_report(cap: Capture, base: AnalysisResult) -> None:
    report = startup_report(cap, base, TC1)
    later = cap.heartbeat_after(report.time + 0.6, RX)
    cap.move_app_data(report, later, f"frame {report.number}: Aufrüstbeginn/status/Aufrüstende sent "
                                     f"{later.time - report.time:.3f} s later, in frame {later.number}")


def drop_aufruestende(cap: Capture, base: AnalysisResult) -> None:
    report = startup_report(cap, base, TC1)
    keep = [d for d, t in zip(report.rasta.app_data, report.message_types) if t != SciMessage.MELDUNG_AUFRUESTENDE]
    cap.set_app_data(report, keep, f"frame {report.number}: Meldung Aufrüstende removed")


def unexpected_status_after_azgh(cap: Capture, base: AnalysisResult) -> None:
    azgh = azgh_step(cap, base, TC2)
    slot = cap.heartbeat_after(azgh.time + 0.1, RX)
    status = telegram(status_template(cap), SciMessage.MELDUNG_GFMA_BELEGUNGSZUSTAND,
                      belegung=Belegung.FREI, grundstellbar=1)
    cap.set_app_data(slot, [status], f"frame {slot.number}: heartbeat replaced by Meldung GFM-A Belegungszustand "
                                     f"1/1, {1000 * (slot.time - azgh.time):.0f} ms after the AZGH")


def swap_version_check_and_aufruestanforderung(cap: Capture, base: AnalysisResult) -> None:
    start = window(base, TC1)[0]
    version = cap.first(sci=SciMessage.KOMMANDO_BTP_VERSIONSABGLEICH, direction=TX, start=start)
    request = cap.first(sci=SciMessage.KOMMANDO_AUFRUESTANFORDERUNG, direction=TX, start=start)
    a, b = list(version.rasta.app_data), list(request.rasta.app_data)
    cap.set_app_data(version, b, f"frames {version.number}/{request.number}: Aufrüstanforderung sent before the "
                                 f"BTP version check")
    cap.set_app_data(request, a)


def _status_frame(cap: Capture, base: AnalysisResult, test_id: str, nth: int = 1):
    start, end = window(base, test_id)
    frames = cap.find(sci=SciMessage.MELDUNG_GFMA_BELEGUNGSZUSTAND, direction=RX, start=start, end=end)
    return frames[nth]


def invalid_belegung(cap: Capture, base: AnalysisResult) -> None:
    frame = _status_frame(cap, base, TC1)
    index = frame.message_types.index(SciMessage.MELDUNG_GFMA_BELEGUNGSZUSTAND)
    cap.edit_telegram(frame, index, lambda d: d[:43] + b"\x09" + d[44:],
                      f"frame {frame.number}: Belegungszustand 0x09 (valid: 1-5)")


def truncate_status(cap: Capture, base: AnalysisResult) -> None:
    frame = _status_frame(cap, base, TC1)
    index = frame.message_types.index(SciMessage.MELDUNG_GFMA_BELEGUNGSZUSTAND)
    cap.edit_telegram(frame, index, lambda d: d[:-1], f"frame {frame.number}: GFM-A status telegram 46 bytes "
                                                       f"instead of 47")


def truncate_azgh_on_the_wire(cap: Capture, base: AnalysisResult) -> None:
    frame = azgh_step(cap, base, TC1)
    index = frame.message_types.index(SciMessage.KOMMANDO_AZGH)
    cap.edit_telegram(frame, index, lambda d: d[:-1], f"frame {frame.number}: AZGH 42 bytes on the wire; the BLF "
                                                       f"(sender side) keeps 43")


def interrupt_connection(cap: Capture, base: AnalysisResult) -> None:
    start = window(base, TC1)[0] + 57.6      # 70.0 s: inside session 2, between preparation and test step
    lost = cap.find(start=start, end=start + 2.0)
    cap.drop(lost, f"{len(lost)} frames between {start:.1f} s and {start + 2.0:.1f} s removed (both directions)")


def drop_one_heartbeat(cap: Capture, base: AnalysisResult) -> None:
    frame = cap.heartbeat_after(window(base, TC1)[0] + 47.6, RX)    # ~60 s
    cap.drop([frame], f"frame {frame.number}: one RX heartbeat (seq {frame.rasta.seq}) removed")


def reject_preparation_azgh(cap: Capture, base: AnalysisResult) -> None:
    """The AZGH that prepares 02283 (state "belegt und grundstellbar") is rejected instead of executed."""
    start, _ = window(base, TC1)
    azgh = cap.first(sci=SciMessage.KOMMANDO_AZGH, direction=TX, start=start)
    slot = cap.heartbeat_after(azgh.time + 0.1, RX)
    rejection = telegram(status_template(cap), SciMessage.MELDUNG_KOMMANDO_ABGEWIESEN, abweisungsgrund=2)
    cap.set_app_data(slot, [rejection], f"frame {slot.number}: Meldung Kommando abgewiesen (technisch) "
                                        f"{1000 * (slot.time - azgh.time):.0f} ms after the preparatory AZGH")


def reject_negative_test_azgh(cap: Capture, base: AnalysisResult) -> None:
    """02284 sends AZGH in state "frei, nicht grundstellbar" and only forbids a status: rejection is allowed."""
    azgh = azgh_step(cap, base, TC2)
    slot = cap.heartbeat_after(azgh.time + 0.1, RX)
    rejection = telegram(status_template(cap), SciMessage.MELDUNG_KOMMANDO_ABGEWIESEN, abweisungsgrund=1)
    cap.set_app_data(slot, [rejection], f"frame {slot.number}: Meldung Kommando abgewiesen (betrieblich) "
                                        f"{1000 * (slot.time - azgh.time):.0f} ms after the AZGH of the test step")


def clock_step(cap: Capture, base: AnalysisResult) -> None:
    start = window(base, TC3)[0]
    later = cap.find(start=start)
    cap.shift(later, 0.020, f"timestamps of {len(later)} frames from {start:.1f} s on shifted by +20 ms "
                            f"(clock step in the capturing PC)")


# --- extra checks for real scenarios ------------------------------------------------------------------------

def clocks_aligned(result: AnalysisResult) -> list[str]:
    a = result.context.alignments[Source.PCAPNG]
    problems = []
    if a.method != "frame_match":
        problems.append(f"pcapng aligned via {a.method}, expected frame_match")
    if a.spread > 0.001:
        problems.append(f"offset spread {a.spread * 1000:.3f} ms")
    if any(f.category is C.TIME_ALIGNMENT for f in result.findings):
        problems.append("time_alignment finding on the real run")
    return problems


# --- catalogue ---------------------------------------------------------------------------------------------

SCENARIOS: tuple[Scenario, ...] = (
    Scenario("1", "response_timeout", "TDS response timeout",
             "Response later than 500 ms after the request (start-up: Aufrüstanforderung → Aufrüstbeginn)",
             "pcapng, Test_Description",
             (Expectation(TC1, C.TIMEOUT, "cause", Verdict.FAIL, "MELDUNG_AUFRUESTBEGINN after"),),
             delay_startup_report),
    Scenario("2", "missing_message", "Missing message",
             "Expected response never arrives (Aufrüstende after Aufrüstbeginn)", "pcapng",
             (Expectation(TC1, C.MISSING_MESSAGE, "cause", Verdict.FAIL, "No MELDUNG_AUFRUESTENDE"),
              Expectation(TC1, C.WRONG_ORDER)),
             drop_aufruestende),
    Scenario("3", "unexpected_response_real", "Unexpected response (real check)",
             "NOT step of the Test_Description: no Meldung GFM-A Belegungszustand within 500 ms after the AZGH",
             "pcapng, Test_Description",
             (Expectation(TC1, C.UNEXPECTED_RESPONSE, "ruled_out", Verdict.PASS),
              Expectation(TC2, C.UNEXPECTED_RESPONSE, "ruled_out", Verdict.PASS))),
    Scenario("3s", "unexpected_response", "Unexpected response",
             "A status telegram arrives within the 500 ms the NOT step forbids", "pcapng, Test_Description",
             (Expectation(TC2, C.UNEXPECTED_RESPONSE, "cause", Verdict.FAIL, "requires it NOT to be sent"),),
             unexpected_status_after_azgh),
    Scenario("4", "wrong_order", "Wrong message order",
             "Start-up order: version check → Aufrüstanforderung → Aufrüstbeginn → reports → Aufrüstende", "pcapng",
             (Expectation(TC1, C.WRONG_ORDER, "cause", Verdict.FAIL,
                          "KOMMANDO_AUFRUESTANFORDERUNG before KOMMANDO_BTP_VERSIONSABGLEICH"),),
             swap_version_check_and_aufruestanforderung),
    Scenario("5", "invalid_payload", "Invalid payload",
             "Field value outside its BL5 range (Belegungszustand 1-5), wrong identifiers", "pcapng, PDF",
             (Expectation(TC1, C.INVALID_PAYLOAD, "cause", Verdict.FAIL, "belegung=9"),),
             invalid_belegung),
    Scenario("6", "incorrect_length_spec", "Incorrect length: Test_Description vs. device (real)",
             "Test_Description expects a 48-byte BL6/BL7 status, the RealOC sends 47 bytes (BL5)",
             "Test_Description, pcapng",
             (Expectation(TC3, C.INCORRECT_LENGTH, "finding", Verdict.FAIL, "expects a 48-byte"),
              Expectation(TC3, C.DEVICE_DISTURBED, "cause"))),
    Scenario("6s", "incorrect_length", "Incorrect length",
             "Telegram shorter than its BL5 layout", "pcapng, PDF",
             (Expectation(TC1, C.INCORRECT_LENGTH, "cause", Verdict.FAIL, "46 bytes, BL5 layout has 47"),),
             truncate_status),
    Scenario("6c", "length_sender_receiver", "Incorrect length: sender vs. receiver side",
             "Same frame with different length in the two captures (BLF at the sender, pcapng on the wire)",
             "pcapng, BLF",
             (Expectation(TC1, C.INCORRECT_LENGTH, "finding", Verdict.FAIL, "bytes in RealOCWorking_TDS_21026.blf"),),
             truncate_azgh_on_the_wire, blf_ethernet=True),
    Scenario("7", "connection_interruption_real", "Connection interruption (real check)",
             "RaSTA gap above the limit, disconnect reason other than user request, disconnect by the device",
             "pcapng, BLF",
             (Expectation(TC3, C.CONNECTION_INTERRUPTION, "ruled_out"),
              Expectation(TC4, C.CONNECTION_INTERRUPTION, "ruled_out"))),
    Scenario("7s", "connection_interruption", "Connection interruption",
             "No RaSTA message for 2 s (limit 750 ms)", "pcapng",
             (Expectation(TC1, C.CONNECTION_INTERRUPTION, "cause", Verdict.FAIL, "No RaSTA message"),),
             interrupt_connection),
    Scenario("8", "sequence_gap", "RaSTA sequence gap / retransmission",
             "Sequence number skipped or repeated", "pcapng",
             (Expectation(TC1, C.SEQUENCE_ERROR, "cause", Verdict.FAIL),),
             drop_one_heartbeat),
    Scenario("9", "precondition_not_reached", "Precondition not reached (real)",
             "GFM-A not in the Test_Description target state within 120 s", "PDF, Test_Description, BLF, pcapng",
             (Expectation(TC3, C.PRECONDITION_NOT_REACHED, "symptom", Verdict.FAIL, "target Belegung/Grundstellbarkeit 2/0"),
              Expectation(TC4, C.PRECONDITION_NOT_REACHED, "symptom", Verdict.FAIL, "1/0 (Test_Description)"))),
    Scenario("10", "device_disturbed", "GFM-A disturbed (real)",
             "Belegungszustand 3; precursor: occupied with Achszählfüllstand 0x0000", "pcapng, BLF, CANoe log",
             (Expectation(TC3, C.DEVICE_DISTURBED, "cause", Verdict.FAIL, "102 ms after an occupied report"),)),
    Scenario("11", "cleanup_cascade", "Cleanup failure cascade (real)",
             "Cleanup of test N failed, test N+1 starts in the disturbed state", "PDF, pcapng",
             (Expectation(TC4, C.CASCADE_FAILURE, "cause", Verdict.FAIL, "left by TC_NPRO.295.02288.01(O)"),)),
    Scenario("12", "test_aborted", "Test aborted / inconclusive (real)",
             "Test unit stopped by the user", "PDF, BLF, CANoe log",
             (Expectation(TC5, C.TEST_ABORTED, "cause", Verdict.INCONCLUSIVE, "stopped by the user"),)),
    Scenario("13", "configuration_mismatch", "Configuration mismatch (real)",
             "Spec value invalid for BL5, test case version report vs. Test_Description",
             "Test_Description, PDF",
             (Expectation(TC3, C.CONFIGURATION_MISMATCH, contains="not a valid BL5 grundstellbar"),
              Expectation(TC1, C.CONFIGURATION_MISMATCH, contains="version 5 in the report, 7")),),
    Scenario("14", "command_rejected", "Command rejected",
             "Meldung Kommando abgewiesen (0x0006) with its reason and the command it answers; the test relied "
             "on the command (preparation)", "pcapng",
             (Expectation(TC1, C.COMMAND_REJECTED, "cause", Verdict.FAIL, "KOMMANDO_AZGH rejected (technisch)"),),
             reject_preparation_azgh),
    Scenario("14n", "command_rejected_allowed", "Command rejected in a negative test",
             "Rejection of the trigger command of a test that only forbids telegrams: reported, not a failure",
             "pcapng, Test_Description",
             (Expectation(TC2, C.COMMAND_REJECTED, "finding", Verdict.PASS, "allowed answer"),),
             reject_negative_test_azgh),
    Scenario("15", "clock_alignment_real", "Source clock offset (real)",
             "Offset pcapng → CANoe time from identical frames; spread and drift", "pcapng, BLF",
             (), check=clocks_aligned),
    Scenario("15s", "clock_step", "Source clock mismatch",
             "Offset between pcapng and BLF changes by 20 ms during the run", "pcapng, BLF",
             (Expectation(None, C.TIME_ALIGNMENT, contains="offset varies by 20.0 ms"),),
             clock_step, blf_ethernet=True),
)


@dataclass(slots=True)
class ScenarioResult:
    scenario: Scenario
    result: AnalysisResult
    changes: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    capture: str | None = None        # path of the synthetic pcapng

    @property
    def passed(self) -> bool:
        return not self.problems


def evaluate(scenario: Scenario, result: AnalysisResult) -> list[str]:
    """Problems with the analyzer output; empty if every expectation holds."""
    problems = []
    diagnoses = {d.test_case.test_id: d for d in result.diagnoses}
    all_findings = result.findings
    for e in scenario.expectations:
        if e.test_id is None:
            if not [f for f in all_findings if f.category is e.category and (not e.contains or e.contains in f.summary)]:
                problems.append(f"run: no {e.category.value} finding"
                                f"{' containing ' + repr(e.contains) if e.contains else ''}")
            continue
        d = diagnoses.get(e.test_id)
        if d is None:
            problems.append(f"{e.test_id}: no diagnosis")
            continue
        if e.role == "ruled_out":
            if e.category not in d.ruled_out:
                problems.append(f"{e.test_id}: {e.category.value} not ruled out")
        else:
            if e.role in ("cause", "symptom"):
                f = getattr(d, e.role)
                candidates = [f] if f is not None and f.category is e.category else []
            else:
                candidates = [f for f in all_findings if f.test_case == d.test_case.name and f.category is e.category]
            if e.contains:
                candidates = [f for f in candidates if e.contains in f.summary]
            if not candidates:
                actual = getattr(d, e.role) if e.role in ("cause", "symptom") else None
                got = f", got {actual.category.value}: {actual.summary}" if actual else ""
                problems.append(f"{e.test_id}: no {e.category.value} as {e.role}"
                                f"{' containing ' + repr(e.contains) if e.contains else ''}{got}")
        if e.verdict is not None and d.verdict is not e.verdict:
            problems.append(f"{e.test_id}: analyzer verdict {d.verdict.value}, expected {e.verdict.value}")
    if scenario.check is not None:
        problems += scenario.check(result)
    return problems
