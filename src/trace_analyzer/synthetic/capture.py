"""Editable copy of a PCAPNG capture, for synthetic failure scenarios built from a real run.

Frames are changed at the RaSTA level so that the result stays a consistent capture: a data message can become
a heartbeat and vice versa (same sequence number), application data can be added, removed or edited, frames can
be dropped. Lengths and IPv4/UDP checksums are recomputed. The RaSTA safety code (half MD4 with the link's own
initial values) cannot be recomputed and is kept from the original frame; neither the analyzer nor the NeuPro
dissector verify it.

Times are CANoe measurement time, from the capture's offset to the master timeline.
"""

import struct
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field, replace
from pathlib import Path

import dpkt

from trace_analyzer.model import Direction, RastaType
from trace_analyzer.readers.decode import (
    RASTA_RED_HEADER,
    RASTA_SAF_HEADER,
    SAFETY_CODE_LENGTH,
    RastaMessage,
    SciTelegram,
    bl5_layout,
    bl5_length,
    decode_ethernet,
    decode_rasta,
    decode_sci,
)
from trace_analyzer.readers.network import node_directions
from trace_analyzer.readers.pcapng import ENHANCED_PACKET, INTERFACE_DESCRIPTION, _interface_options

BTP_HEADER = 43   # protocol type, message type, sender and receiver identifier


@dataclass(slots=True)
class Frame:
    block: int                     # index into Capture.blocks
    number: int                    # Wireshark frame number in the original capture
    time: float                    # master time
    data: bytes
    direction: Direction
    rasta: RastaMessage | None
    telegrams: list[SciTelegram] = field(default_factory=list)

    @property
    def message_types(self) -> list[int]:
        return [t.message_type for t in self.telegrams]


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def with_udp_payload(frame: bytes, payload: bytes) -> bytes:
    """Same Ethernet/IPv4/UDP frame with another UDP payload; lengths and checksums recomputed."""
    eth = dpkt.ethernet.Ethernet(frame)
    ip, udp = eth.data, eth.data.data
    had_udp_checksum = udp.sum != 0
    udp.data, udp.ulen, udp.sum = payload, 8 + len(payload), 0
    if had_udp_checksum:
        pseudo = ip.src + ip.dst + struct.pack("!BBH", 0, ip.p, udp.ulen)
        udp.sum = _checksum(pseudo + bytes(udp)) or 0xFFFF
    ip.data = udp
    ip.len = ip.__hdr_len__ + len(ip.opts) + udp.ulen
    ip.sum = 0
    ip.sum = _checksum(ip.pack_hdr() + bytes(ip.opts))
    eth.data = ip
    return bytes(eth)


def rasta_payload(original: bytes, typ: int, app_data: Iterable[bytes] = ()) -> bytes:
    """RaSTA redundancy + safety PDU from an original one, with another message type and application data.

    Header fields (sequence numbers, timestamps, identifiers) and the safety code are kept, and so is the body
    of a message whose type does not change and carries no application data (connection, disconnection).
    """
    red_seq = struct.unpack_from("<I", original, 4)[0]
    saf = original[RASTA_RED_HEADER:]
    header = bytearray(saf[:RASTA_SAF_HEADER])
    code = saf[-SAFETY_CODE_LENGTH:]
    original_type = struct.unpack_from("<H", saf, 2)[0]
    if typ in (RastaType.DATA, RastaType.RETRANSMITTED_DATA):
        body = b"".join(struct.pack("<H", len(d)) + d for d in app_data)
    elif typ == original_type:
        body = saf[RASTA_SAF_HEADER:-SAFETY_CODE_LENGTH]
    else:
        body = b""
    saf_length = RASTA_SAF_HEADER + len(body) + SAFETY_CODE_LENGTH
    struct.pack_into("<HH", header, 0, saf_length, typ)
    pdu = bytes(header) + body + code
    return struct.pack("<HHI", RASTA_RED_HEADER + len(pdu), 0, red_seq) + pdu


def telegram(template: bytes, message_type: int, **fields: int) -> bytes:
    """BL5 telegram with the BTP header (protocol type, identifiers) of `template` and the given fields."""
    data = bytearray(template[:BTP_HEADER].ljust(BTP_HEADER, b"_"))
    data[1:3] = message_type.to_bytes(2, "little")
    data += bytes(bl5_length(message_type) - BTP_HEADER)
    for name, offset, size in bl5_layout(message_type):
        data[offset:offset + size] = fields.get(name, 0).to_bytes(size, "little")
    return bytes(data)


class Capture:
    """A PCAPNG file as a list of blocks; Ethernet frames are decoded and can be edited."""

    def __init__(self, blocks: list[bytes], frames: list[Frame], offset: float, endian: str,
                 resolutions: list[tuple[float, float]]):
        self.blocks = blocks
        self.frames = frames
        self.offset = offset
        self._endian = endian
        self._resolutions = resolutions      # per interface: (resolution, offset)
        self.changes: list[str] = []         # human-readable log of every edit

    @classmethod
    def load(cls, path: Path, nodes: dict, offset: float, baseline: int = 5) -> "Capture":
        data = Path(path).read_bytes()
        directions = node_directions(nodes)
        endian, blocks, frames, resolutions, number, pos = "<", [], [], [], 0, 0
        while pos + 12 <= len(data):
            if data[pos:pos + 4] == b"\x0a\x0d\x0d\x0a":
                endian = "<" if data[pos + 8:pos + 12] == b"\x4d\x3c\x2b\x1a" else ">"
                resolutions = []
            block_type, length = struct.unpack_from(endian + "II", data, pos)
            block = data[pos:pos + length]
            body = block[8:-4]
            if block_type == INTERFACE_DESCRIPTION:
                resolutions.append(_interface_options(body, endian))
            elif block_type == ENHANCED_PACKET or block_type in (0x00000003, 0x00000BAD, 0x40000BAD):
                number += 1
            if block_type == ENHANCED_PACKET:
                iface, high, low, captured, _original = struct.unpack_from(endian + "IIIII", body, 0)
                resolution, ts_offset = resolutions[iface]
                time = ((high << 32) | low) * resolution + ts_offset + offset
                frames.append(cls._decode(len(blocks), number, time, body[20:20 + captured], directions, baseline))
            blocks.append(block)
            pos += length
        return cls(blocks, frames, offset, endian, resolutions)

    @staticmethod
    def _decode(block: int, number: int, time: float, data: bytes, directions: dict, baseline: int) -> Frame:
        packet = decode_ethernet(data)
        rasta = decode_rasta(packet.payload) if packet.protocol == "udp" else None
        telegrams = [decode_sci(d, baseline) for d in rasta.app_data] if rasta else []
        return Frame(block, number, time, data, directions.get(packet.src or "", Direction.NONE), rasta, telegrams)

    # --- selection -------------------------------------------------------------------------------------------

    def find(self, sci: int | None = None, rasta: RastaType | None = None, direction: Direction | None = None,
             start: float = float("-inf"), end: float = float("inf")) -> list[Frame]:
        return [f for f in self.frames
                if start <= f.time < end and (direction is None or f.direction is direction)
                and (rasta is None or (f.rasta is not None and f.rasta.type == rasta))
                and (sci is None or sci in f.message_types)]

    def first(self, **criteria) -> Frame:
        found = self.find(**criteria)
        if not found:
            raise LookupError(f"no frame matches {criteria}")
        return found[0]

    def heartbeat_after(self, t: float, direction: Direction) -> Frame:
        return self.first(rasta=RastaType.HEARTBEAT, direction=direction, start=t)

    # --- edits -----------------------------------------------------------------------------------------------

    def set_app_data(self, frame: Frame, app_data: list[bytes], note: str = "") -> None:
        """Replace the application data; an empty list turns a data message into a heartbeat and back."""
        typ = RastaType.DATA if app_data else RastaType.HEARTBEAT
        payload = rasta_payload(decode_ethernet(frame.data).payload, typ, app_data)
        self._replace(frame, with_udp_payload(frame.data, payload), note)

    def edit_telegram(self, frame: Frame, index: int, edit: Callable[[bytes], bytes], note: str = "") -> None:
        app = list(frame.rasta.app_data)
        app[index] = edit(app[index])
        self.set_app_data(frame, app, note)

    def move_app_data(self, source: Frame, target: Frame, note: str = "") -> None:
        """Send the application data of `source` in `target` (a heartbeat) instead: delays or reorders it."""
        if target.rasta is None or target.rasta.type != RastaType.HEARTBEAT or target.direction is not source.direction:
            raise ValueError("target must be a heartbeat in the same direction")
        app = list(source.rasta.app_data)
        self.set_app_data(source, [], note)
        self.set_app_data(self.frames[self._index(target)], app, "")

    def drop(self, frames: Iterable[Frame], note: str = "") -> None:
        dropped = {frame.block for frame in frames}
        for block in dropped:
            self.blocks[block] = b""
        self.frames = [f for f in self.frames if f.block not in dropped]
        if note:
            self.changes.append(note)

    def shift(self, frames: Iterable[Frame], seconds: float, note: str = "") -> None:
        """Move frame timestamps (e.g. a clock step in the capturing PC)."""
        for frame in list(frames):
            block = bytearray(self.blocks[frame.block])
            iface, high, low = struct.unpack_from(self._endian + "III", block, 8)
            resolution, _ = self._resolutions[iface]
            ticks = ((high << 32) | low) + round(seconds / resolution)
            struct.pack_into(self._endian + "II", block, 12, ticks >> 32, ticks & 0xFFFFFFFF)
            self.blocks[frame.block] = bytes(block)
            i = self._index(frame)
            self.frames[i] = replace(self.frames[i], time=frame.time + seconds)
        if note:
            self.changes.append(note)

    def _replace(self, frame: Frame, data: bytes, note: str) -> None:
        old = self.blocks[frame.block]
        body = old[8:-4]
        captured = struct.unpack_from(self._endian + "I", body, 12)[0]
        options = body[20 + captured + (-captured % 4):]
        packet = body[:12] + struct.pack(self._endian + "II", len(data), len(data)) + data + bytes(-len(data) % 4)
        length = 12 + len(packet) + len(options)
        block = struct.pack(self._endian + "II", ENHANCED_PACKET, length) + packet + options + struct.pack(
            self._endian + "I", length)
        self.blocks[frame.block] = block
        decoded = self._decode(frame.block, frame.number, frame.time, data, {}, 5)
        self.frames[self._index(frame)] = replace(decoded, direction=frame.direction)
        if note:
            self.changes.append(note)

    def _index(self, frame: Frame) -> int:
        return next(i for i, f in enumerate(self.frames) if f.block == frame.block)

    def save(self, path: Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"".join(self.blocks))
        return path
