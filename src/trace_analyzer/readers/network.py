"""Turn raw Ethernet frames (from PCAPNG or BLF) into RaSTA, SCI and network events."""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

import dpkt

from trace_analyzer.model import Direction, EventKind, EvidenceRef, SciMessage, Source, TraceEvent

from .decode import decode_ethernet, decode_rasta, decode_sci


@dataclass(frozen=True, slots=True)
class RawFrame:
    time: float
    data: bytes
    locator: str                                   # "frame 16" (PCAPNG), "object 1234" (BLF)
    fields: dict[str, Any] = field(default_factory=dict)


def node_directions(nodes: Mapping[str, Mapping[str, Any]]) -> dict[str, Direction]:
    """IP → direction of messages sent from that IP, from the `nodes` config section."""
    directions = {}
    if "test_system" in nodes:
        directions[str(nodes["test_system"]["ip"])] = Direction.TX
    if "dut" in nodes:
        directions[str(nodes["dut"]["ip"])] = Direction.RX
    return directions


def sci_name(message_type: int) -> str:
    try:
        return SciMessage(message_type).name
    except ValueError:
        return f"UNKNOWN_0x{message_type:04x}"


def frames_to_events(
    frames: Iterable[RawFrame],
    source: Source,
    file: str,
    nodes: Mapping[str, Mapping[str, Any]],
    baseline: int = 5,
    rasta_port: int | None = None,
) -> list[TraceEvent]:
    directions = node_directions(nodes)
    events: list[TraceEvent] = []

    for frame in frames:
        ref = EvidenceRef(source, file, frame.locator)
        try:
            packet = decode_ethernet(frame.data)
        except (dpkt.UnpackError, ValueError) as exc:
            events.append(TraceEvent(frame.time, EventKind.NETWORK, ref, name="undecodable frame",
                                     length=len(frame.data), fields={"error": str(exc), **frame.fields},
                                     raw=frame.data))
            continue

        direction = directions.get(packet.src or "", Direction.NONE)
        on_rasta_port = rasta_port is None or rasta_port in (packet.src_port, packet.dst_port)
        rasta = decode_rasta(packet.payload) if packet.protocol == "udp" and on_rasta_port else None

        if rasta is None:
            events.append(TraceEvent(
                frame.time, EventKind.NETWORK, ref, direction, msg_type=packet.protocol,
                name=packet.info or packet.protocol, sender=packet.src, receiver=packet.dst,
                length=len(frame.data), fields={**packet.fields, **frame.fields}, raw=frame.data,
            ))
            continue

        rasta_fields = {
            "seq": rasta.seq, "confirmed_seq": rasta.confirmed_seq,
            "timestamp": rasta.timestamp, "confirmed_timestamp": rasta.confirmed_timestamp,
            "red_seq": rasta.red_seq, "telegrams": len(rasta.app_data), **rasta.fields, **frame.fields,
        }
        if rasta.error:
            rasta_fields["decode_error"] = rasta.error
        events.append(TraceEvent(
            frame.time, EventKind.RASTA, ref, direction, msg_type=rasta.type, name=rasta.name,
            sender=str(rasta.sender), receiver=str(rasta.receiver), length=rasta.length,
            fields=rasta_fields, raw=packet.payload,
        ))

        for i, app in enumerate(rasta.app_data, start=1):
            telegram = decode_sci(app, baseline)
            fields = {"protocol_type": telegram.protocol_type, **telegram.fields}
            if telegram.error:
                fields["decode_error"] = telegram.error
            events.append(TraceEvent(
                frame.time, EventKind.SCI_TELEGRAM, EvidenceRef(source, file, f"{frame.locator} telegram {i}"),
                direction, msg_type=telegram.message_type, name=sci_name(telegram.message_type),
                sender=telegram.sender, receiver=telegram.receiver, length=telegram.length,
                fields=fields, raw=app,
            ))
    return events
