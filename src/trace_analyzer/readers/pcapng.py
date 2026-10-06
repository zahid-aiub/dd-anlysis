"""PCAPNG reader.

Blocks are walked directly (instead of via dpkt) so that frame numbers match Wireshark, which also counts
custom blocks (e.g. Vector "pcaplog" metadata) as frames.
"""

import struct
from pathlib import Path
from typing import Any

from trace_analyzer.model import Source, SourceData, TimeBase, TimeReference

from .network import RawFrame, frames_to_events

SECTION_HEADER = 0x0A0D0D0A
INTERFACE_DESCRIPTION = 0x00000001
SIMPLE_PACKET = 0x00000003
ENHANCED_PACKET = 0x00000006
CUSTOM_BLOCKS = (0x00000BAD, 0x40000BAD)
LINKTYPE_ETHERNET = 1


def _interface_options(body: bytes, endian: str) -> tuple[float, float]:
    """(timestamp resolution in seconds, timestamp offset in seconds) from an IDB."""
    resolution, offset = 1e-6, 0.0
    pos = 8
    while pos + 4 <= len(body):
        code, length = struct.unpack_from(endian + "HH", body, pos)
        value = body[pos + 4:pos + 4 + length]
        if code == 0:
            break
        if code == 9 and length >= 1:      # if_tsresol
            r = value[0]
            resolution = 2.0 ** -(r & 0x7F) if r & 0x80 else 10.0 ** -r
        elif code == 14 and length >= 8:   # if_tsoffset
            offset = float(struct.unpack_from(endian + "q", value)[0])
        pos += 4 + length + (-length % 4)
    return resolution, offset


def read_pcapng_frames(path: Path) -> tuple[list[RawFrame], dict[str, Any]]:
    data = path.read_bytes()
    endian = "<"
    interfaces: list[tuple[int, float, float]] = []   # (linktype, resolution, offset)
    frames: list[RawFrame] = []
    metadata: dict[str, Any] = {"custom_blocks": [], "unsupported_frames": 0}
    frame_number = 0
    pos = 0

    while pos + 12 <= len(data):
        if data[pos:pos + 4] == b"\x0a\x0d\x0d\x0a":
            endian = "<" if data[pos + 8:pos + 12] == b"\x4d\x3c\x2b\x1a" else ">"
            interfaces = []
        block_type, block_length = struct.unpack_from(endian + "II", data, pos)
        if block_length < 12:
            raise ValueError(f"{path}: corrupt block at offset {pos}")
        body = data[pos + 8:pos + block_length - 4]

        if block_type == INTERFACE_DESCRIPTION:
            linktype = struct.unpack_from(endian + "H", body, 0)[0]
            interfaces.append((linktype, *_interface_options(body, endian)))
        elif block_type == ENHANCED_PACKET:
            frame_number += 1
            iface, ts_high, ts_low, captured, original = struct.unpack_from(endian + "IIIII", body, 0)
            linktype, resolution, offset = interfaces[iface]
            if linktype == LINKTYPE_ETHERNET:
                time = ((ts_high << 32) | ts_low) * resolution + offset
                frames.append(RawFrame(time, body[20:20 + captured], f"frame {frame_number}",
                                       {"interface": iface, "original_length": original}))
            else:
                metadata["unsupported_frames"] += 1
        elif block_type == SIMPLE_PACKET:
            frame_number += 1
            metadata["unsupported_frames"] += 1
        elif block_type in CUSTOM_BLOCKS:
            frame_number += 1
            metadata["custom_blocks"].append(body[4:].decode("utf-8", "replace").rstrip("\x00"))
        pos += block_length

    metadata["frames"] = frame_number
    return frames, metadata


class PcapngReader:
    source = Source.PCAPNG

    def __init__(self, nodes: dict, baseline: int = 5, rasta_port: int | None = None):
        self.nodes = nodes
        self.baseline = baseline
        self.rasta_port = rasta_port

    def read(self, path: Path) -> SourceData:
        path = Path(path)
        frames, metadata = read_pcapng_frames(path)
        events = frames_to_events(frames, self.source, path.name, self.nodes, self.baseline, self.rasta_port)
        return SourceData(self.source, path, TimeBase(TimeReference.EPOCH), events, metadata=metadata)
