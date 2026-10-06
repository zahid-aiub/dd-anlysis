"""Containers passed between pipeline stages."""

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from .events import Direction, EvidenceRef, Source, TraceEvent
from .testcase import TestCaseResult, TestSpec


class TimeReference(StrEnum):
    MEASUREMENT = "measurement"  # native times are CANoe measurement time (BLF, CANoe log, PDF)
    EPOCH = "epoch"              # native times are Unix epoch seconds (pcapng)


@dataclass(frozen=True, slots=True)
class TimeBase:
    reference: TimeReference
    measurement_start_epoch: float | None = None  # absolute start of the measurement, if the source knows it


@dataclass(slots=True)
class SourceData:
    """Everything one reader extracted from one file."""

    source: Source
    path: Path
    time_base: TimeBase
    events: list[TraceEvent] = field(default_factory=list)
    test_cases: list[TestCaseResult] = field(default_factory=list)
    specs: list[TestSpec] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Alignment:
    """How one source was put on the master timeline: t_master = t_native + offset."""

    source: Source
    offset: float
    method: str            # "native", "frame_match", "rasta_timestamp", "measurement_start", "first_frame"
    samples: int = 0       # pairs/values the estimate is based on
    spread: float = 0.0    # deviation of single samples from the estimate (max; p95 for rasta_timestamp), seconds
    drift_ppm: float = 0.0
    note: str = ""


@dataclass(frozen=True, slots=True)
class ConsistencyCheck:
    """Same observation seen in two sources after alignment, e.g. GFM-A status in CANoe log and network."""

    name: str
    sources: tuple[Source, Source]
    matched: int
    max_difference: float  # seconds
    unmatched: int = 0


@dataclass(frozen=True, slots=True)
class FrameDifference:
    """The same frame (same time, direction and RaSTA message) captured with different bytes by two sources."""

    time: float
    primary: EvidenceRef
    secondary: EvidenceRef
    primary_length: int
    secondary_length: int
    first_difference: int        # offset of the first differing byte
    name: str = ""               # RaSTA message of the primary frame


@dataclass(frozen=True, slots=True)
class MergeStats:
    """Result of merging two network sources that captured the same frames."""

    primary: Source
    secondary: Source | None
    matched_frames: int = 0
    only_in_primary: tuple[str, ...] = ()     # evidence locators
    only_in_secondary: tuple[str, ...] = ()
    differing: tuple[FrameDifference, ...] = ()


@dataclass(frozen=True, slots=True)
class Session:
    """One RaSTA connection, from connection request to disconnection request."""

    index: int
    start: float
    end: float
    test_case: str | None = None
    established: bool = True              # connection response received
    closed_by: Direction | None = None    # who sent the disconnection request; None if never closed
    disconnect_reason: int | None = None


@dataclass(slots=True)
class AnalysisContext:
    """Aligned, correlated input for the rule engine."""

    events: list[TraceEvent]          # all sources, CANoe measurement time, sorted
    test_cases: list[TestCaseResult]  # merged from BLF test structure and PDF report
    specs: dict[str, TestSpec]        # by test id
    sessions: list[Session]
    config: dict[str, Any]
    alignments: dict[Source, Alignment] = field(default_factory=dict)
    checks: list[ConsistencyCheck] = field(default_factory=list)
    merge: MergeStats | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def window(self, start: float, end: float) -> list[TraceEvent]:
        return [e for e in self.events if start <= e.time < end]

    def test_case_at(self, t: float) -> TestCaseResult | None:
        return next((tc for tc in self.test_cases if tc.contains(t)), None)
