"""Rule output: findings and the per-test-case diagnosis."""

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from .events import EvidenceRef
from .testcase import TestCaseResult, Verdict


class Severity(StrEnum):
    ERROR = "error"      # explains or contributes to a failure
    WARNING = "warning"  # suspicious, may cause failures
    INFO = "info"        # context, e.g. manual intervention without effect


class FailureCategory(StrEnum):
    # Root-cause categories named in the assignment
    MISSING_MESSAGE = "missing_message"
    WRONG_ORDER = "wrong_order"
    INVALID_PAYLOAD = "invalid_payload"
    INCORRECT_LENGTH = "incorrect_length"
    TIMEOUT = "timeout"
    CONNECTION_INTERRUPTION = "connection_interruption"
    UNEXPECTED_RESPONSE = "unexpected_response"
    CONFIGURATION_MISMATCH = "configuration_mismatch"
    # Further categories from the analysis scenarios
    SEQUENCE_ERROR = "sequence_error"                    # RaSTA sequence gap / retransmission
    COMMAND_REJECTED = "command_rejected"
    PRECONDITION_NOT_REACHED = "precondition_not_reached"
    TEST_STEP_FAILED = "test_step_failed"                # a main-part step failed and no rule explains it
    DEVICE_DISTURBED = "device_disturbed"                # field element reports a disturbed state
    CASCADE_FAILURE = "cascade_failure"                  # inherited bad state from the previous test case
    TEST_ABORTED = "test_aborted"
    MANUAL_INTERVENTION = "manual_intervention"
    TIME_ALIGNMENT = "time_alignment"                    # sources cannot be aligned reliably


@dataclass(frozen=True, slots=True)
class Finding:
    category: FailureCategory
    severity: Severity
    summary: str
    time: float | None = None
    test_case: str | None = None
    confidence: float = 1.0                       # 0..1
    evidence: tuple[EvidenceRef, ...] = ()
    details: Mapping[str, Any] = field(default_factory=dict, hash=False)


@dataclass(slots=True)
class Diagnosis:
    """Explanation of one test case result.

    `symptom` is what the test reported (e.g. precondition timeout); `cause` is the deepest finding that
    explains it (e.g. GFM-A disturbed). For a passed test without error findings both are None.
    """

    test_case: TestCaseResult
    symptom: Finding | None = None
    cause: Finding | None = None
    contributing: list[Finding] = field(default_factory=list)
    ruled_out: list[FailureCategory] = field(default_factory=list)

    @property
    def findings(self) -> list[Finding]:
        """Symptom, cause and contributing findings, each once."""
        result: list[Finding] = []
        for f in (self.symptom, self.cause, *self.contributing):
            if f is not None and not any(f is g for g in result):
                result.append(f)
        return result

    @property
    def verdict(self) -> Verdict:
        """The analyzer's verdict: a test the report passes fails if the analysis found an error in it."""
        if self.test_case.verdict is Verdict.PASS and any(f.severity is Severity.ERROR for f in self.findings):
            return Verdict.FAIL
        return self.test_case.verdict
