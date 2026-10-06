"""Vector BLF reader: Ethernet frames, CANoe variables, panel actions and test structure.

Object layouts follow Vector's binlog object definitions. Values marked "observed" were verified against the
RealOC run (test-structure results, distributed-object value encoding).
"""

import re
import struct
import zlib
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from typing import Any

from trace_analyzer.model import (
    Direction,
    EventKind,
    EvidenceRef,
    SciMessage,
    Source,
    SourceData,
    TestCaseResult,
    TimeBase,
    TimeReference,
    TraceEvent,
    Verdict,
)

from .decode import bl5_field_names
from .network import RawFrame, frames_to_events

OBJ_LOG_CONTAINER = 10
OBJ_APP_TEXT = 65
OBJ_TEST_STRUCTURE = 118
OBJ_ETHERNET_FRAME_EX = 120
OBJ_DISTRIBUTED_OBJECT = 130

TEST_TYPES = {1: "test_module", 2: "test_group", 3: "test_case", 8: "test_configuration", 9: "test_unit",
              10: "test_group", 11: "test_fixture", 12: "test_sequence", 13: "test_sequence_list", 14: "test_case"}
TEST_ACTIONS = {1: "begin", 2: "end", 3: "abort"}
# 2 (pass) and 4 (fail) observed; 3 and 5 per Vector's definition.
TEST_RESULTS = {2: Verdict.PASS, 3: Verdict.INCONCLUSIVE, 4: Verdict.FAIL, 5: Verdict.ERROR}

# Panel members that are operator inputs; other panel members are displays.
OPERATOR_INPUT = re.compile(r"(Button|kdSelection)$")

_BTP_IN_VALUE = b"\x2d\x00\x00\x00\x20"  # serialized header length 45, then protocol type 0x20 (TDS)


def _systemtime(raw: bytes) -> datetime | None:
    year, month, _weekday, day, hour, minute, second, ms = struct.unpack("<8H", raw)
    if not year:
        return None
    return datetime(year, month, day, hour, minute, second, ms * 1000)


def iter_objects(data: bytes) -> Iterator[tuple[int, int, float, bytes]]:
    """Yield (index, object type, timestamp in seconds, object body) for every object inside the log containers."""
    pos = struct.unpack_from("<I", data, 4)[0]
    inner = bytearray()
    while pos + 16 <= len(data):
        _hs, _hv, size, obj_type = struct.unpack_from("<HHII", data, pos + 4)
        if obj_type == OBJ_LOG_CONTAINER:
            method = struct.unpack_from("<H", data, pos + 16)[0]
            payload = data[pos + 32:pos + size]
            inner += zlib.decompress(payload) if method == 2 else payload
        pos += size + size % 4

    index, pos = 0, 0
    while pos + 32 <= len(inner):
        header_size, _hv, size, obj_type = struct.unpack_from("<HHII", inner, pos + 4)
        flags = struct.unpack_from("<I", inner, pos + 16)[0]
        ticks = struct.unpack_from("<Q", inner, pos + 24)[0]
        timestamp = ticks / 1e9 if flags == 2 else ticks / 1e5   # flag 2: ns, flag 1: 10 µs
        index += 1
        yield index, obj_type, timestamp, bytes(inner[pos + header_size:pos + size])
        nxt = pos + size
        # objects are 4-byte aligned in most files; resynchronise on the next signature
        for skip in range(4):
            if inner[nxt + skip:nxt + skip + 4] == b"LOBJ":
                break
        pos = nxt + skip


def _ethernet_frame(body: bytes) -> tuple[bytes, dict[str, Any]]:
    struct_length, _flags, channel, hw_channel = struct.unpack_from("<HHHH", body, 0)
    direction, frame_length = struct.unpack_from("<HH", body, 20)
    start = 2 + struct_length
    return body[start:start + frame_length], {"channel": channel, "hw_channel": hw_channel, "blf_dir": direction}


def _variable_value(name: str, value: bytes) -> dict[str, Any]:
    """Decode a distributed-object member value (encoding observed in CANoe 20)."""
    if len(value) in (12, 16):
        return {"value": struct.unpack_from("<i", value, 8)[0]}
    start = value.find(_BTP_IN_VALUE)
    if start < 0:
        return {}
    header = value[start + 4:start + 4 + 45]
    message_type = int.from_bytes(header[1:3], "little")
    fields: dict[str, Any] = {
        "message_type": message_type,
        "sender": header[3:23].decode("latin-1").rstrip("_\x00"),
        "receiver": header[24:44].decode("latin-1").rstrip("_\x00"),
    }
    values, pos = [], start + 4 + 45
    while pos + 20 <= len(value):
        _tag, size, size2, _pad = struct.unpack_from("<IIII", value, pos)
        if size != size2 or size not in (1, 2, 4):
            break
        values.append(int.from_bytes(value[pos + 16:pos + 20], "little"))
        pos += 20
    names = bl5_field_names(message_type)
    if names and len(names) == len(values):
        fields.update(zip(names, values))
    return fields


def _variable_direction(name: str) -> Direction:
    leaf = name.rsplit(".", 2)
    joined = ".".join(leaf[-2:])
    if "SendMonitor" in joined or leaf[-1].startswith("kommando"):
        return Direction.TX
    if "ReceiveMonitor" in joined or leaf[-1].startswith("meldung"):
        return Direction.RX
    return Direction.NONE


class BlfReader:
    source = Source.BLF

    def __init__(self, nodes: dict, baseline: int = 5, rasta_port: int | None = None):
        self.nodes = nodes
        self.baseline = baseline
        self.rasta_port = rasta_port

    def read(self, path: Path) -> SourceData:
        path = Path(path)
        data = path.read_bytes()
        if data[:4] != b"LOGG":
            raise ValueError(f"{path}: not a BLF file")

        file = path.name
        frames: list[RawFrame] = []
        events: list[TraceEvent] = []
        open_cases: dict[int, tuple[str, float]] = {}
        test_cases: list[TestCaseResult] = []
        seen_values: set[tuple[float, bytes, str]] = set()
        counts: dict[int, int] = {}
        metadata: dict[str, Any] = {
            "measurement_start_local": _systemtime(data[40:56]),
            "measurement_stop_local": _systemtime(data[56:72]),
            "app_text": [],
        }
        last_time = 0.0

        for index, obj_type, t, body in iter_objects(data):
            counts[obj_type] = counts.get(obj_type, 0) + 1
            last_time = max(last_time, t)
            ref = EvidenceRef(self.source, file, f"object {index}")

            if obj_type == OBJ_ETHERNET_FRAME_EX:
                frame, info = _ethernet_frame(body)
                frames.append(RawFrame(t, frame, f"object {index}", info))

            elif obj_type == OBJ_DISTRIBUTED_OBJECT:
                _kind, _one, name_length, value_length = struct.unpack_from("<IIII", body, 0)
                name = body[16:16 + name_length].decode("utf-8", "replace")
                value = body[16 + name_length:16 + name_length + value_length]
                key = (t, value, name.rsplit(".", 1)[-1])
                if key in seen_values:   # CANoe logs each member under its full path and under an alias
                    continue
                seen_values.add(key)
                fields = _variable_value(name, value)
                leaf = name.rsplit(".", 1)[-1]
                is_input = name.startswith("Panel::") and OPERATOR_INPUT.search(leaf)
                if is_input and leaf == "kdSelection" and "value" in fields:
                    try:
                        fields["command"] = SciMessage(fields["value"]).name
                    except ValueError:
                        pass
                events.append(TraceEvent(
                    t, EventKind.OPERATOR_ACTION if is_input else EventKind.VARIABLE, ref,
                    _variable_direction(name), msg_type=name, name=leaf, length=len(value),
                    fields=fields, raw=value,
                ))

            elif obj_type == OBJ_TEST_STRUCTURE:
                _eid, typ, _res, unique, action, result, l1, l2, l3 = struct.unpack_from("<IHHIHHIII", body, 0)
                strings = body[28:28 + 2 * (l1 + l2 + l3)].decode("utf-16-le", "replace")
                element, text = strings[l1:l1 + l2], strings[l1 + l2:]
                type_name, action_name = TEST_TYPES.get(typ, f"type_{typ}"), TEST_ACTIONS.get(action, f"action_{action}")
                verdict = TEST_RESULTS.get(result, Verdict.NONE)
                events.append(TraceEvent(
                    t, EventKind.TEST, ref, msg_type=f"{type_name}.{action_name}", name=element,
                    fields={"type": type_name, "action": action_name, "verdict": verdict.value,
                            "unique_no": unique, "text": text},
                ))
                if type_name == "test_case" and action_name == "begin":
                    open_cases[unique] = (element, t)
                elif type_name == "test_case" and unique in open_cases:
                    element, start = open_cases.pop(unique)
                    test_cases.append(TestCaseResult(element, verdict, start, t, ref=ref))
                elif action_name == "abort":
                    # test cases still running when the test unit/configuration is aborted
                    for element, start in open_cases.values():
                        test_cases.append(TestCaseResult(element, Verdict.INCONCLUSIVE, start, t, ref=ref))
                    open_cases.clear()

            elif obj_type == OBJ_APP_TEXT:
                text = body[16:].decode("utf-8", "replace").rstrip("\x00")
                if text.startswith("<?xml"):
                    metadata["app_text"].append(text)

        for element, start in open_cases.values():
            test_cases.append(TestCaseResult(element, Verdict.INCONCLUSIVE, start, last_time))

        events += frames_to_events(frames, self.source, file, self.nodes, self.baseline, self.rasta_port)
        events.sort(key=lambda e: e.time)
        test_cases.sort(key=lambda tc: tc.start)
        metadata["object_counts"] = counts
        metadata.update(_app_text_info(metadata["app_text"]))
        return SourceData(self.source, path, TimeBase(TimeReference.MEASUREMENT), events, test_cases, metadata=metadata)


def _app_text_info(texts: list[str]) -> dict[str, str]:
    info = {}
    patterns = {
        "configuration": r'<configuration\s+file="([^"]+)"',
        "user": r'<user\s+name="([^"]+)"',
        "computer": r'computer="([^"]+)"',
        "application_version": r'<application\s+name="[^"]*"\s+version="([^"]+)"',
    }
    for text in texts:
        for key, pattern in patterns.items():
            match = re.search(pattern, text)
            if match and key not in info:
                info[key] = match.group(1)
    return info
