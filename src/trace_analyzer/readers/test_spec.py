"""Test_Description reader (ALM/Excel TSV export, one file per test case, header row optional)."""

import csv
import io
import re
from pathlib import Path

from trace_analyzer.model import EvidenceRef, Source, SourceData, SpecStep, TestSpec, TimeBase, TimeReference

COLUMNS = (
    "Test Name", "Description", "Expected behavior", "1. Precondition", "2. Postcondition",
    "Explanation of parameters", "Test phase", "Integration_Relevance", "Site_Data", "Step number (Design Steps)",
    "Designer", "References to requirements", "Test type", "Created on", "type", "status",
    "INTERFACE (Design Steps)", "DIRECTION (Design Steps)", "Designation (Design Steps)",
    "Description (Design Steps)", "Expected result (of the step)", "Step Delay (Design Steps)",
    "Note (Design Steps)", "Time (Design Steps)", "Setup (Design Steps)", "Version Number",
)
_MESSAGE_TYPE = re.compile(r"BTP\[01\.\.02\]\s*=\s*(0x[0-9A-Fa-f]+)")
_MAX_DELAY = re.compile(r"t\s*-\s*t1\s*<\s*(\d+(?:\.\d+)?)\s*ms")
_BYTE = re.compile(r"BTP\[(\d+(?:\.\.\d+)?)\]\s*=\s*([^;\n]+)")
_STEP = re.compile(r"Step\s+(\d+)")


def _clean(text: str) -> str:
    return " ".join(text.split())


def _step(row: dict[str, str]) -> SpecStep:
    setup, expected, timing = row["Setup (Design Steps)"], row["Expected result (of the step)"], row["Time (Design Steps)"]
    direction, designation = _clean(row["DIRECTION (Design Steps)"]), _clean(row["Designation (Design Steps)"])
    message_type = _MESSAGE_TYPE.search(setup)
    delay = _MAX_DELAY.search(timing)
    step_number = _STEP.search(row["Step number (Design Steps)"])
    return SpecStep(
        number=int(step_number.group(1)) if step_number else 0,
        interface=_clean(row["INTERFACE (Design Steps)"]),
        direction=direction,
        designation=designation,
        expected=_clean(expected),
        message_type=int(message_type.group(1), 16) if message_type else None,
        expect_absent=direction == "NOT" or designation.startswith("NOT"),
        max_delay_s=float(delay.group(1)) / 1000 if delay else None,
        expected_bytes={k: _clean(v) for k, v in _BYTE.findall(setup + "\n" + expected)},
    )


def read_test_description(path: Path) -> TestSpec:
    text = path.read_text(encoding="utf-8", errors="replace")
    rows = [r for r in csv.reader(io.StringIO(text), delimiter="\t") if any(c.strip() for c in r)]
    if rows and rows[0][0].strip() == COLUMNS[0]:
        rows = rows[1:]
    records = [dict(zip(COLUMNS, r + [""] * (len(COLUMNS) - len(r)))) for r in rows]
    if not records:
        raise ValueError(f"{path}: no test description rows")
    first = records[0]
    return TestSpec(
        test_id=first["Test Name"].strip(),
        description=_clean(first["Description"]),
        precondition=_clean(first["1. Precondition"]),
        postcondition=_clean(first["2. Postcondition"]),
        version=first["Version Number"].strip() or None,
        steps=[_step(r) for r in records],
        ref=EvidenceRef(Source.TEST_SPEC, path.name, "row 1"),
    )


class TestSpecReader:
    """Reads every TC_*.txt file of a Test_Description directory."""

    __test__ = False
    source = Source.TEST_SPEC

    def read(self, path: Path) -> SourceData:
        path = Path(path)
        files = sorted(path.glob("TC_*.txt")) if path.is_dir() else [path]
        specs = [read_test_description(f) for f in files]
        return SourceData(self.source, path, TimeBase(TimeReference.MEASUREMENT), specs=specs,
                          metadata={"files": [f.name for f in files]})
