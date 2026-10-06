"""TraceEvent: the common record every reader produces."""

from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from enum import StrEnum
from typing import Any


class Source(StrEnum):
    PCAPNG = "pcapng"
    BLF = "blf"
    PDF_REPORT = "pdf_report"
    CANOE_LOG = "canoe_log"
    TEST_SPEC = "test_spec"


class EventKind(StrEnum):
    RASTA = "rasta"                      # RaSTA safety-layer message; msg_type is a RastaType
    SCI_TELEGRAM = "sci_telegram"        # one SCI/BTP telegram; a RaSTA data message can carry several
    VARIABLE = "variable"                # CANoe distributed-object member / system variable update
    OPERATOR_ACTION = "operator_action"  # manual interaction on the CANoe panel
    LOG = "log"                          # CANoe write-window line
    TEST = "test"                        # test structure: configuration/unit/case start and end
    NETWORK = "network"                  # other frames (ARP, ICMP)


class Direction(StrEnum):
    TX = "tx"      # sent by the test system (ESTW-ZE simulated by CANoe)
    RX = "rx"      # sent by the device under test (Az-System)
    NONE = "none"  # not a message between the two nodes


@dataclass(frozen=True, slots=True)
class EvidenceRef:
    """Where an event came from, precise enough for an engineer to find it again."""

    source: Source
    file: str
    locator: str  # e.g. "frame 423", "page 12", "line 27", "object 5012"

    def __str__(self) -> str:
        return f"{self.file} {self.locator}"


@dataclass(frozen=True, slots=True)
class TraceEvent:
    """One observation on the common timeline.

    Readers emit `time` in the source's native time base. The time aligner replaces it with CANoe
    measurement time and keeps the native value in `source_time`.
    """

    time: float
    kind: EventKind
    ref: EvidenceRef
    direction: Direction = Direction.NONE
    msg_type: int | str | None = None  # SciMessage / RastaType code, or variable name
    name: str = ""
    sender: str | None = None
    receiver: str | None = None
    length: int | None = None          # telegram length in bytes
    fields: Mapping[str, Any] = field(default_factory=dict, hash=False)
    raw: bytes | None = field(default=None, hash=False, repr=False)
    source_time: float | None = None

    @property
    def source(self) -> Source:
        return self.ref.source

    def shifted(self, offset: float) -> "TraceEvent":
        """Return a copy on the common timeline: native time + offset."""
        native = self.time if self.source_time is None else self.source_time
        return replace(self, time=native + offset, source_time=native)
