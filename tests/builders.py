"""Builders for synthetic events and analysis contexts used by the rule tests."""

from trace_analyzer.correlate import build_sessions
from trace_analyzer.model import (
    AnalysisContext,
    Direction,
    EventKind,
    EvidenceRef,
    RastaType,
    Source,
    SpecStep,
    TestCaseResult,
    TestSpec,
    TestStep,
    TraceEvent,
    Verdict,
)
from trace_analyzer.readers.decode import bl5_length
from trace_analyzer.rules.common import message_name

ZE_ID, AZ_ID, ELEMENT = "DETHMM ZE 35##0001", "DETHMM AZA34##0001", "34W1"
CONFIG = {
    "nodes": {"test_system": {"ip": "1.208.188.16", "id": ZE_ID}, "dut": {"ip": "10.129.15.2", "id": AZ_ID}},
    "protocol": {"sci_tds_baseline": 5},
    "timing": {"response_timeout_ms": 500},
    "rasta": {"max_message_gap_ms": 750},
    "alignment": {"max_spread_ms": 5},
}
_counter = iter(range(1, 10**9))


def ref(source: Source = Source.PCAPNG) -> EvidenceRef:
    return EvidenceRef(source, f"x.{source.value}", f"frame {next(_counter)}")


def tel(t: float, msg_type: int, direction: Direction, length: int | None = None, sender: str | None = None,
        receiver: str | None = None, raw: bytes | None = None, **fields) -> TraceEvent:
    element_message = msg_type in (0x0001, 0x0002, 0x0003, 0x0006, 0x0007, 0x0009, 0x000A, 0x000B)
    other = ELEMENT if element_message else AZ_ID
    if sender is None:
        sender = ZE_ID if direction is Direction.TX else other
    if receiver is None:
        receiver = other if direction is Direction.TX else ZE_ID
    fields = {"protocol_type": 0x20, **fields}
    return TraceEvent(t, EventKind.SCI_TELEGRAM, ref(), direction, msg_type, message_name(msg_type),
                      sender, receiver, length if length is not None else bl5_length(msg_type, fields), fields, raw)


def status(t: float, belegung: int, grundstellbar: int = 0, fill: int = 0, **kw) -> TraceEvent:
    return tel(t, 0x0007, Direction.RX, belegung=belegung, grundstellbar=grundstellbar, achszaehlfuellstand=fill, **kw)


def rasta(t: float, typ: RastaType, direction: Direction, seq: int = 0, **fields) -> TraceEvent:
    return TraceEvent(t, EventKind.RASTA, ref(), direction, int(typ), typ.name, length=36, fields={"seq": seq, **fields})


def session(t0: float, t1: float, with_startup: bool = True, closed_by: Direction = Direction.TX,
            reason: int = 0, heartbeat: float = 0.3, state: tuple[int, int, int] = (1, 0, 0)) -> list[TraceEvent]:
    """RaSTA connection from t0 to t1 with heartbeats and (optionally) the SCI start-up sequence.

    `state` is the GFM-A status reported during the start-up (Aufrüstung).
    """
    events = [rasta(t0, RastaType.CONNECTION_REQUEST, Direction.TX, 0),
              rasta(t0 + 0.1, RastaType.CONNECTION_RESPONSE, Direction.RX, 0)]
    seq = {Direction.TX: 1, Direction.RX: 1}
    t = t0 + 0.1 + heartbeat
    while t < t1:
        for d in (Direction.TX, Direction.RX):
            events.append(rasta(t, RastaType.HEARTBEAT, d, seq[d]))
            seq[d] += 1
        t += heartbeat
    events.append(rasta(t1, RastaType.DISCONNECTION_REQUEST, closed_by, seq[closed_by], reason=reason))
    if with_startup:
        events += [tel(t0 + 0.2, 0x0024, Direction.TX, btp_version=1),
                   tel(t0 + 0.5, 0x0025, Direction.RX, ergebnis=1, btp_version=1, checksum_length=0),
                   tel(t0 + 0.51, 0x0021, Direction.TX),
                   tel(t0 + 0.8, 0x0022, Direction.RX), status(t0 + 0.8, *state), tel(t0 + 0.8, 0x0023, Direction.RX)]
    return events


def step(t: float, section: str, number: str, title: str, verdict: Verdict = Verdict.NONE) -> TestStep:
    return TestStep(t, number, title, verdict, section, ref=EvidenceRef(Source.PDF_REPORT, "r.pdf", "page 1"))


def case(name: str, start: float, end: float, verdict: Verdict = Verdict.PASS, steps=(), version=None) -> TestCaseResult:
    return TestCaseResult(name, verdict, start, end, version, list(steps))


def spec(test_id: str, *steps: SpecStep, version: str | None = None) -> TestSpec:
    return TestSpec(test_id, "", "", "", version, list(steps), EvidenceRef(Source.TEST_SPEC, f"{test_id}.txt", "row 1"))


def context(events, test_cases=(), specs=(), **kw) -> AnalysisContext:
    events = sorted(events, key=lambda e: e.time)
    test_cases = list(test_cases)
    return AnalysisContext(events, test_cases, {s.test_id: s for s in specs}, build_sessions(events, test_cases),
                           kw.pop("config", CONFIG), **kw)
