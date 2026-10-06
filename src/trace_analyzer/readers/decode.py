"""Decode raw Ethernet frames into IP/UDP, RaSTA and SCI-TDS (BL5) telegrams.

The byte layouts follow the NeuPro Lua dissectors (rasta_redundancy_layer.lua, rasta_safety_layer.lua,
sci_common.lua, SCI-TDS_BL5.lua). Decoding is done here instead of in tshark so that malformed telegrams are
kept (with an error) rather than dropped, and so that BLF frames can be decoded in measurement time.
"""

import socket
import struct
from dataclasses import dataclass, field
from typing import Any

import dpkt

from trace_analyzer.model.protocol import BTP_HEADER_LENGTH, RastaType

RASTA_RED_HEADER = 8    # length, reserved, sequence number
RASTA_SAF_HEADER = 28   # length, type, receiver, sender, seq, confirmed seq, timestamp, confirmed timestamp
SAFETY_CODE_LENGTH = 8  # "Half" MD4 safety code, as configured on the RealOC link

_ICMP_UNREACHABLE = {0: "net", 1: "host", 2: "protocol", 3: "port"}


@dataclass(frozen=True, slots=True)
class Packet:
    protocol: str                  # "udp", "icmp", "arp", "ip", "other"
    src: str | None = None
    dst: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    payload: bytes = b""
    info: str = ""
    fields: dict[str, Any] = field(default_factory=dict)


def decode_ethernet(frame: bytes) -> Packet:
    """Ethernet (with or without 802.1Q tag) → IPv4 → UDP/ICMP, or ARP."""
    eth = dpkt.ethernet.Ethernet(frame)
    l3 = eth.data
    if isinstance(l3, dpkt.arp.ARP):
        op = "request" if l3.op == dpkt.arp.ARP_OP_REQUEST else "reply"
        return Packet("arp", socket.inet_ntoa(l3.spa), socket.inet_ntoa(l3.tpa), info=f"ARP {op}")
    if not isinstance(l3, dpkt.ip.IP):
        return Packet("other", info=f"ethertype 0x{eth.type:04x}", fields={"ethertype": eth.type})

    src, dst = socket.inet_ntoa(l3.src), socket.inet_ntoa(l3.dst)
    l4 = l3.data
    if isinstance(l4, dpkt.udp.UDP):
        return Packet("udp", src, dst, l4.sport, l4.dport, bytes(l4.data))
    if isinstance(l4, dpkt.icmp.ICMP):
        info = f"ICMP type {l4.type} code {l4.code}"
        if l4.type == dpkt.icmp.ICMP_UNREACH:
            info = f"ICMP destination unreachable ({_ICMP_UNREACHABLE.get(l4.code, l4.code)} unreachable)"
        return Packet("icmp", src, dst, info=info, fields={"type": l4.type, "code": l4.code})
    return Packet("ip", src, dst, info=f"IP protocol {l3.p}", fields={"ip_protocol": l3.p})


@dataclass(frozen=True, slots=True)
class RastaMessage:
    type: int
    receiver: int
    sender: int
    seq: int
    confirmed_seq: int
    timestamp: int
    confirmed_timestamp: int
    red_seq: int
    length: int                        # safety-layer PDU length
    app_data: tuple[bytes, ...] = ()   # data / retransmitted data only
    fields: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    @property
    def name(self) -> str:
        try:
            return RastaType(self.type).name
        except ValueError:
            return f"UNKNOWN_{self.type}"


def decode_rasta(udp_payload: bytes) -> RastaMessage | None:
    """Redundancy + safety layer. Returns None if the payload is not RaSTA (dissector heuristic: length field)."""
    p = udp_payload
    if len(p) < RASTA_RED_HEADER + RASTA_SAF_HEADER:
        return None
    red_length, _reserved, red_seq = struct.unpack_from("<HHI", p, 0)
    if red_length != len(p):
        return None

    saf = p[RASTA_RED_HEADER:]
    saf_length, typ, receiver, sender, seq, cseq, ts, cts = struct.unpack_from("<HHIIIIII", saf, 0)
    body = saf[RASTA_SAF_HEADER:max(RASTA_SAF_HEADER, saf_length - SAFETY_CODE_LENGTH)]
    fields: dict[str, Any] = {}
    app_data: list[bytes] = []
    error = None if saf_length == len(saf) else f"safety-layer length {saf_length} != {len(saf)} bytes received"

    if typ in (RastaType.CONNECTION_REQUEST, RastaType.CONNECTION_RESPONSE) and len(body) >= 6:
        fields["version"] = body[0:4].decode("ascii", "replace")
        fields["nsendmax"] = struct.unpack_from("<H", body, 4)[0]
    elif typ == RastaType.DISCONNECTION_REQUEST and len(body) >= 4:
        fields["detail"], fields["reason"] = struct.unpack_from("<HH", body, 0)
    elif typ in (RastaType.DATA, RastaType.RETRANSMITTED_DATA):
        offset = 0
        while offset + 2 <= len(body):
            (n,) = struct.unpack_from("<H", body, offset)
            if offset + 2 + n > len(body):
                error = error or f"application data length {n} exceeds message at offset {offset}"
                break
            app_data.append(body[offset + 2:offset + 2 + n])
            offset += 2 + n

    return RastaMessage(typ, receiver, sender, seq, cseq, ts, cts, red_seq, saf_length, tuple(app_data), fields, error)


# Payload layout per message type for SCI-TDS BL5: (field, offset, size). Multi-byte fields are little-endian.
_BL5_FIELDS: dict[int, tuple[tuple[str, int, int], ...]] = {
    0x0001: (("grundstellungsart", 43, 1),),
    0x0006: (("abweisungsgrund", 43, 1),),
    0x0007: (("belegung", 43, 1), ("grundstellbar", 44, 1), ("achszaehlfuellstand", 45, 2)),
    0x000A: (("richtung", 43, 1),),
    0x000B: (("befahrung", 43, 1), ("richtung", 44, 1)),
    0x0024: (("btp_version", 43, 1),),
    0x0025: (("ergebnis", 43, 1), ("btp_version", 44, 1), ("checksum_length", 45, 1)),
}


def bl5_layout(message_type: int) -> tuple[tuple[str, int, int], ...]:
    """(field, offset, size) of the payload fields of a BL5 telegram type."""
    return _BL5_FIELDS.get(message_type, ())


def bl5_field_names(message_type: int) -> tuple[str, ...]:
    return tuple(name for name, _, _ in bl5_layout(message_type))


def bl5_length(message_type: int, fields: dict[str, Any] | None = None) -> int:
    """Length of a complete BL5 telegram of this type (header-only and unknown types: 43 bytes)."""
    if message_type == 0x0025 and fields and "checksum_length" in fields:
        return 46 + fields["checksum_length"]
    layout = _BL5_FIELDS.get(message_type, ())
    return max([BTP_HEADER_LENGTH] + [offset + size for _, offset, size in layout])


@dataclass(frozen=True, slots=True)
class SciTelegram:
    protocol_type: int
    message_type: int
    sender: str
    receiver: str
    length: int
    fields: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


def _identifier(raw: bytes) -> str:
    return raw.decode("latin-1").rstrip("_\x00")


def decode_sci(data: bytes, baseline: int = 5) -> SciTelegram:
    """One SCI/BTP telegram (RaSTA application data packet)."""
    if baseline != 5:
        raise ValueError(f"SCI-TDS baseline {baseline} is not implemented; only BL5 is")
    if len(data) < 3:
        return SciTelegram(data[0] if data else -1, -1, "", "", len(data), error=f"truncated: {len(data)} bytes")

    protocol_type = data[0]
    message_type = int.from_bytes(data[1:3], "little")
    sender = _identifier(data[3:23])
    receiver = _identifier(data[23:BTP_HEADER_LENGTH])

    fields: dict[str, Any] = {}
    for name, offset, size in _BL5_FIELDS.get(message_type, ()):
        if offset + size <= len(data):
            fields[name] = int.from_bytes(data[offset:offset + size], "little")
    required = bl5_length(message_type, fields)
    if message_type == 0x0025 and "checksum_length" in fields:
        fields["checksum"] = data[46:required].hex()

    error = None
    if len(data) < required:
        error = f"truncated: {len(data)} bytes, BL5 layout needs {required}"
    return SciTelegram(protocol_type, message_type, sender, receiver, len(data), fields, error)
