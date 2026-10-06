"""Test case results (CANoe report, BLF test structure) and test specifications (Test_Description)."""

import re
from dataclasses import dataclass, field
from enum import StrEnum

from .events import EvidenceRef

_TEST_NAME = re.compile(r"^(?P<id>TC_[\w.]+?)(?:\((?P<variant>[^)]*)\))?$")


class Verdict(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    INCONCLUSIVE = "inconclusive"
    ERROR = "error"  # error in test system
    NONE = "none"


def split_test_name(name: str) -> tuple[str, str | None]:
    """'TC_NPRO.295.02288.01(O)' -> ('TC_NPRO.295.02288.01', 'O')."""
    match = _TEST_NAME.match(name.strip())
    if not match:
        return name.strip(), None
    return match["id"], match["variant"]


@dataclass(frozen=True, slots=True)
class ValueCheck:
    """One row of a CANoe validation table (expected vs. actual)."""

    field: str             # table sub-header, e.g. "Nachrichtentyp", "Bezeichner Sender"
    index: str             # byte index or name, e.g. "1", "Laenge"
    actual: str
    expected: str
    passed: bool


@dataclass(frozen=True, slots=True)
class TestStep:
    """One line of the CANoe report step log."""

    __test__ = False  # not a pytest class

    time: float
    step: str              # "Init", "1", "2", "Cleanup", "Reset", ...
    title: str
    verdict: Verdict = Verdict.NONE
    section: str = ""      # "Preparation", "Main Part", "Completion"
    group: str = ""        # enclosing block, e.g. "BTP-Verbindung aufbauen"
    checks: tuple[ValueCheck, ...] = ()
    ref: EvidenceRef | None = None


@dataclass(slots=True)
class TestCaseResult:
    __test__ = False

    name: str              # as in the report, e.g. "TC_NPRO.295.02288.01(O)"
    verdict: Verdict
    start: float
    end: float
    version: str | None = None
    steps: list[TestStep] = field(default_factory=list)
    ref: EvidenceRef | None = None

    @property
    def test_id(self) -> str:
        return split_test_name(self.name)[0]

    @property
    def variant(self) -> str | None:
        return split_test_name(self.name)[1]

    @property
    def failed_steps(self) -> list[TestStep]:
        return [s for s in self.steps if s.verdict is Verdict.FAIL]

    def contains(self, t: float) -> bool:
        return self.start <= t < self.end


@dataclass(frozen=True, slots=True)
class SpecStep:
    """One design step of a Test_Description."""

    number: int
    interface: str                        # "BTP", "AZ6", "TC.PC"
    direction: str                        # "ZE:O", "TDS:O", "TDS:I", "NOT", ""
    designation: str                      # "Kd_AZGH", "NOT (Md_GFM_A_Belegungszustand)"
    expected: str                         # expected result as written
    message_type: int | None = None       # from "BTP[01..02] = 0x0007"
    expect_absent: bool = False           # "NOT": the telegram must not be sent
    max_delay_s: float | None = None      # from "t-t1 < 500 ms"
    expected_bytes: dict[str, str] = field(default_factory=dict)  # {"43": "0x02", "45..46": "0xFFFF"}


@dataclass(slots=True)
class TestSpec:
    __test__ = False

    test_id: str
    description: str
    precondition: str
    postcondition: str
    version: str | None
    steps: list[SpecStep] = field(default_factory=list)
    ref: EvidenceRef | None = None
