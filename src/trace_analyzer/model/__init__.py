"""Common internal data structures shared by readers, correlation, rules and reporting."""

from .context import (
    Alignment,
    AnalysisContext,
    ConsistencyCheck,
    FrameDifference,
    MergeStats,
    Session,
    SourceData,
    TimeBase,
    TimeReference,
)
from .events import Direction, EventKind, EvidenceRef, Source, TraceEvent
from .findings import Diagnosis, FailureCategory, Finding, Severity
from .protocol import (
    Abweisungsgrund,
    Belegung,
    DisconnectReason,
    Grundstellbarkeit,
    Grundstellungsart,
    RastaType,
    SciMessage,
)
from .testcase import SpecStep, TestCaseResult, TestSpec, TestStep, ValueCheck, Verdict, split_test_name

__all__ = [
    "Abweisungsgrund", "Alignment", "AnalysisContext", "Belegung", "ConsistencyCheck", "Diagnosis", "Direction",
    "DisconnectReason", "EventKind", "EvidenceRef", "FailureCategory", "Finding", "FrameDifference", "Grundstellbarkeit",
    "Grundstellungsart", "MergeStats", "RastaType", "SciMessage", "Session", "Severity", "Source", "SourceData",
    "SpecStep", "TestCaseResult",
    "TestSpec", "TestStep", "TimeBase", "TimeReference", "TraceEvent", "ValueCheck", "Verdict", "split_test_name",
]
