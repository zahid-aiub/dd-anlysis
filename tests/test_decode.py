"""Decoder unit tests on hand-built frames."""

import socket
import struct

import dpkt
import pytest

from trace_analyzer.model import Direction, EventKind, RastaType, SciMessage, Source
from trace_analyzer.readers.decode import decode_ethernet, decode_rasta, decode_sci
from trace_analyzer.readers.network import RawFrame, frames_to_events
from trace_analyzer.readers.pcapng import read_pcapng_frames

ZE, AZ = "1.208.188.16", "10.129.15.2"
NODES = {"test_system": {"ip": ZE}, "dut": {"ip": AZ}}


def btp(message_type: int, sender: str, receiver: str, payload: bytes = b"") -> bytes:
    return (bytes([0x20]) + message_type.to_bytes(2, "little")
            + sender.ljust(20, "_").encode() + receiver.ljust(20, "_").encode() + payload)


def status(belegung: int, grundstellbar: int, zaehl: int) -> bytes:
    return btp(0x0007, "34W1", "DETHMM ZE 35##0001", bytes([belegung, grundstellbar]) + zaehl.to_bytes(2, "little"))


def rasta(typ: int, body: bytes = b"", seq: int = 1) -> bytes:
    saf = struct.pack("<HHIIIIII", 28 + len(body) + 8, typ, 1617088647, 1617088648, seq, 0, 0, 0) + body + bytes(8)
    return struct.pack("<HHI", 8 + len(saf), 0, seq) + saf


def data_body(*telegrams: bytes) -> bytes:
    return b"".join(struct.pack("<H", len(t)) + t for t in telegrams)


def udp_frame(payload: bytes, src: str = AZ, dst: str = ZE, port: int = 24001) -> bytes:
    udp = dpkt.udp.UDP(sport=port, dport=port, data=payload)
    udp.ulen = len(udp)
    ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst), p=dpkt.ip.IP_PROTO_UDP, data=udp)
    ip.len = len(ip)
    return bytes(dpkt.ethernet.Ethernet(src=b"\x02" * 6, dst=b"\x04" * 6, type=dpkt.ethernet.ETH_TYPE_IP, data=ip))


# --- SCI ---------------------------------------------------------------------------------------------------

def test_status_telegram():
    t = decode_sci(status(2, 1, 1))
    assert (t.protocol_type, t.message_type, t.length) == (0x20, 0x0007, 47)
    assert (t.sender, t.receiver) == ("34W1", "DETHMM ZE 35##0001")
    assert t.fields == {"belegung": 2, "grundstellbar": 1, "achszaehlfuellstand": 1}
    assert t.error is None


def test_truncated_status_telegram_keeps_what_is_there():
    t = decode_sci(status(3, 0, 0)[:45])
    assert t.fields == {"belegung": 3, "grundstellbar": 0}
    assert "truncated" in t.error


def test_azg_parameter():
    assert decode_sci(btp(0x0001, "DETHMM ZE 35##0001", "34W1", b"\x02")).fields == {"grundstellungsart": 2}


def test_btp_version_report_with_checksum():
    t = decode_sci(btp(0x0025, "DETHMM AZA34##0001", "DETHMM ZE 35##0001", bytes([1, 1, 2, 0xAB, 0xCD])))
    assert t.fields == {"ergebnis": 1, "btp_version": 1, "checksum_length": 2, "checksum": "abcd"}
    assert t.error is None


def test_unknown_message_type_is_not_an_error():
    t = decode_sci(btp(0x0042, "A", "B"))
    assert t.fields == {} and t.error is None


def test_other_baselines_are_rejected():
    with pytest.raises(ValueError, match="baseline 6"):
        decode_sci(status(1, 0, 0), baseline=6)


# --- RaSTA -------------------------------------------------------------------------------------------------

def test_heartbeat():
    m = decode_rasta(rasta(RastaType.HEARTBEAT, seq=77))
    assert m.type == RastaType.HEARTBEAT and m.seq == 77 and m.app_data == () and m.error is None


def test_data_message_with_two_telegrams():
    m = decode_rasta(rasta(RastaType.DATA, data_body(btp(0x0022, "A", "B"), status(1, 0, 0))))
    assert [decode_sci(a).message_type for a in m.app_data] == [0x0022, 0x0007]


def test_disconnect_reason():
    m = decode_rasta(rasta(RastaType.DISCONNECTION_REQUEST, struct.pack("<HH", 0, 4)))
    assert m.fields == {"detail": 0, "reason": 4}


def test_connection_request_version():
    m = decode_rasta(rasta(RastaType.CONNECTION_REQUEST, b"0303" + struct.pack("<H", 20) + bytes(8)))
    assert m.fields == {"version": "0303", "nsendmax": 20}


def test_non_rasta_payload():
    assert decode_rasta(b"\x00" * 50) is None


def test_application_length_overflow_is_reported():
    m = decode_rasta(rasta(RastaType.DATA, struct.pack("<H", 200) + b"\x20\x07\x00"))
    assert m.app_data == () and "exceeds" in m.error


# --- frames → events ---------------------------------------------------------------------------------------

def test_ethernet_udp():
    p = decode_ethernet(udp_frame(b"xyz"))
    assert (p.protocol, p.src, p.dst, p.src_port, p.payload) == ("udp", AZ, ZE, 24001, b"xyz")


def test_frames_to_events():
    frames = [
        RawFrame(1.0, udp_frame(rasta(RastaType.DATA, data_body(status(3, 0, 0)))), "frame 1"),
        RawFrame(2.0, udp_frame(b"not rasta", src=ZE, dst=AZ), "frame 2"),
        RawFrame(3.0, b"\x00\x01", "frame 3"),
    ]
    events = frames_to_events(frames, Source.PCAPNG, "x.pcapng", NODES, rasta_port=24001)
    kinds = [(e.kind, e.direction, e.ref.locator) for e in events]
    assert kinds == [
        (EventKind.RASTA, Direction.RX, "frame 1"),
        (EventKind.SCI_TELEGRAM, Direction.RX, "frame 1 telegram 1"),
        (EventKind.NETWORK, Direction.TX, "frame 2"),
        (EventKind.NETWORK, Direction.NONE, "frame 3"),
    ]
    telegram = events[1]
    assert telegram.msg_type == SciMessage.MELDUNG_GFMA_BELEGUNGSZUSTAND
    assert telegram.fields["belegung"] == 3 and telegram.raw == status(3, 0, 0)
    assert events[3].name == "undecodable frame"


# --- PCAPNG ------------------------------------------------------------------------------------------------

def _block(block_type: int, body: bytes) -> bytes:
    body += bytes(-len(body) % 4)
    length = 12 + len(body)
    return struct.pack("<II", block_type, length) + body + struct.pack("<I", length)


def test_pcapng_frame_numbers_count_custom_blocks(tmp_path):
    shb = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
    idb = struct.pack("<HHI", 1, 0, 0)
    frame = udp_frame(b"abc")

    def epb(us: int) -> bytes:
        return struct.pack("<IIIII", 0, us >> 32, us & 0xFFFFFFFF, len(frame), len(frame)) + frame

    path = tmp_path / "t.pcapng"
    path.write_bytes(
        _block(0x0A0D0D0A, shb) + _block(0x0BAD, b"\x00\x00\x00\x00<xml/>") + _block(1, idb)
        + _block(6, epb(1_000_000)) + _block(6, epb(2_500_000))
    )
    frames, meta = read_pcapng_frames(path)
    assert [(f.locator, f.time) for f in frames] == [("frame 2", 1.0), ("frame 3", 2.5)]
    assert meta["custom_blocks"] == ["<xml/>"] and meta["frames"] == 3
