"""Rules on the RaSTA connection: establishment, interruptions, disconnect reasons, sequence numbers."""

from trace_analyzer.model import (
    AnalysisContext,
    Direction,
    DisconnectReason,
    EventKind,
    FailureCategory,
    Finding,
    RastaType,
    Session,
    Severity,
    TraceEvent,
)

from .base import NetworkRule
from .common import finding

C = FailureCategory
RETRANSMISSION = (RastaType.RETRANSMISSION_REQUEST, RastaType.RETRANSMISSION_RESPONSE, RastaType.RETRANSMITTED_DATA)


def rasta_events(ctx: AnalysisContext, session: Session) -> list[TraceEvent]:
    return [e for e in ctx.events if e.kind is EventKind.RASTA and session.start <= e.time <= session.end]


class ConnectionRule(NetworkRule):
    name = "connection"
    categories = (C.CONNECTION_INTERRUPTION,)

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        gap_limit = ctx.config.get("rasta", {}).get("max_message_gap_ms", 750) / 1000
        findings = []
        for session in ctx.sessions:
            events = rasta_events(ctx, session)
            if not session.established:
                findings.append(finding(ctx, C.CONNECTION_INTERRUPTION, Severity.ERROR,
                                        "Connection request was not answered", session.start, events[:1],
                                        session=session.index))
            if session.disconnect_reason not in (None, DisconnectReason.USER_REQUEST):
                try:
                    reason = DisconnectReason(session.disconnect_reason).name.lower()
                except ValueError:
                    reason = str(session.disconnect_reason)
                findings.append(finding(ctx, C.CONNECTION_INTERRUPTION, Severity.ERROR,
                                        f"Connection closed with reason {reason}", session.end, events[-1:],
                                        session=session.index, reason=reason))
            if session.closed_by is Direction.RX:
                findings.append(finding(ctx, C.CONNECTION_INTERRUPTION, Severity.ERROR,
                                        "Device under test closed the connection", session.end, events[-1:],
                                        session=session.index))
            for direction in (Direction.TX, Direction.RX):
                side = [e for e in events if e.direction is direction]
                for before, after in zip(side, side[1:]):
                    if after.time - before.time > gap_limit:
                        findings.append(finding(
                            ctx, C.CONNECTION_INTERRUPTION, Severity.ERROR,
                            f"No RaSTA message from {direction.value.upper()} side for "
                            f"{(after.time - before.time) * 1000:.0f} ms (limit {gap_limit * 1000:.0f} ms)",
                            before.time, [before, after], session=session.index, gap_s=after.time - before.time))
        return findings


class SequenceRule(NetworkRule):
    name = "sequence"
    categories = (C.SEQUENCE_ERROR,)

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        findings = []
        for session in ctx.sessions:
            events = rasta_events(ctx, session)
            for direction in (Direction.TX, Direction.RX):
                previous = None
                for e in (x for x in events if x.direction is direction):
                    seq = e.fields.get("seq")
                    if previous is not None and seq is not None and seq != (previous.fields["seq"] + 1) % 2**32:
                        kind = "repeated" if seq == previous.fields["seq"] else "jumped"
                        findings.append(finding(
                            ctx, C.SEQUENCE_ERROR, Severity.ERROR,
                            f"RaSTA sequence number {kind} from {previous.fields['seq']} to {seq} "
                            f"({direction.value.upper()})", e.time, [previous, e], session=session.index))
                    previous = e
            for e in events:
                if e.msg_type in RETRANSMISSION:
                    findings.append(finding(ctx, C.SEQUENCE_ERROR, Severity.WARNING,
                                            f"RaSTA {e.name.lower().replace('_', ' ')}", e.time, [e],
                                            session=session.index))
        return findings
