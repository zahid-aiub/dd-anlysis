"""CANoe Write-window log (.txt, tab-separated) reader."""

import re
from datetime import time
from pathlib import Path
from typing import Any

from trace_analyzer.model import EventKind, EvidenceRef, Source, SourceData, TimeBase, TimeReference, TraceEvent

_LINE = re.compile(r"^\[(?P<level>[^\]]*)\]\t(?P<clock>\d+:\d\d:\d\d\.\d+)\t\[(?P<origin>[^\]]*)\]\t(?P<component>[^\t]*)\t?(?P<text>.*)$")
# InterlockingTDSModel lines: "<model time> <spec section> <field>: <value>"
_STATUS = re.compile(r"^(?P<t>\d+\.\d+)\s+3\.4\.11\s+(?P<field>\w+):\s*(?P<value>.*)$")
_START = re.compile(r"Start of measurement (\d+):(\d\d):(\d\d)\.(\d+)")
LEVELS = {"*": "info", "W": "warning", "E": "error"}


def _seconds(clock: str) -> float:
    h, m, s = clock.split(":")
    return int(h) * 3600 + int(m) * 60 + float(s)


def _status_value(field: str, value: str) -> tuple[str, int] | None:
    if field == "belegungszustand":
        return "belegung", int(value)
    if field == "Grundstellungsfaehigkeit":
        return "grundstellbar", 0 if "cannot" in value else 1
    if field == "Achszaehlfuellstand":
        raw = value.split("->")[0].strip()
        return "achszaehlfuellstand", int(raw, 16) if raw.lower().startswith("0x") else int(raw)
    return None


class CanoeLogReader:
    source = Source.CANOE_LOG

    def read(self, path: Path) -> SourceData:
        path = Path(path)
        events: list[TraceEvent] = []
        metadata: dict[str, Any] = {}
        pending: dict[str, Any] | None = None   # 3.4.11 status lines are grouped into one event

        def flush() -> None:
            nonlocal pending
            if pending:
                events.append(TraceEvent(pending.pop("time"), EventKind.LOG, pending.pop("ref"),
                                         msg_type="3.4.11", name="GFM-A status", fields=pending))
            pending = None

        for number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
            match = _LINE.match(line)
            if not match:
                continue
            ref = EvidenceRef(self.source, path.name, f"line {number}")
            text = match["text"].strip()
            status = _STATUS.match(text)
            if status and (parsed := _status_value(status["field"], status["value"])):
                t = float(status["t"])
                if pending is None or abs(pending["time"] - t) > 1e-6:
                    flush()
                    pending = {"time": t, "ref": ref}
                pending[parsed[0]] = parsed[1]
                continue

            flush()
            if start := _START.search(text):
                h, m, s, frac = start.groups()
                metadata["measurement_start_clock"] = time(int(h), int(m), int(s), int(frac.ljust(6, "0")[:6]))
            events.append(TraceEvent(
                _seconds(match["clock"]), EventKind.LOG, ref, msg_type=match["origin"],
                name=match["component"] or match["origin"], fields={
                    "level": LEVELS.get(match["level"], match["level"]), "text": text,
                },
            ))
        flush()
        return SourceData(self.source, path, TimeBase(TimeReference.MEASUREMENT), events, metadata=metadata)
