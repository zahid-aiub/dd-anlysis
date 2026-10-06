"""CANoe Test Report Viewer PDF reader.

Text is read with positions (PyMuPDF) and assigned to the step-log columns using the x positions of each
table's header row ("Time Stamp", "Test Step", "Title", "Verdict"), which differ between tables.
"""

import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import pymupdf

from trace_analyzer.model import (
    EvidenceRef,
    Source,
    SourceData,
    TestCaseResult,
    TestStep,
    TimeBase,
    TimeReference,
    ValueCheck,
    Verdict,
)

SECTIONS = {"Preparation", "Main Part", "Completion"}
VERDICTS = {"pass": Verdict.PASS, "fail": Verdict.FAIL, "inconclusive": Verdict.INCONCLUSIVE,
            "error in test system": Verdict.ERROR, "none": Verdict.NONE}
_TIME = re.compile(r"^\d+\.\d+$")
_TEST_CASE_HEADER = re.compile(r"^(\d+)\.\s+(TC_\S+)$")
_WALL_TIME = "%m/%d/%Y %I:%M:%S %p %z"
_POLLING = re.compile(r"^Elapsed time=\d+(\.\d+)?ms \(max=\d+ms\)$")   # wait-loop noise, dropped
_HEADER_FOOTER_MARGIN = 45   # page header at y≈23, footer at y≈751 on a 792 pt page


@dataclass(slots=True)
class _Span:
    x: float
    y: float
    size: float
    bold: bool
    text: str


@dataclass(slots=True)
class _Columns:
    step: float = 100.0
    title: float = 160.0
    verdict: float = 540.0


@dataclass(slots=True)
class _StepDraft:
    time: float
    step: str
    title: str
    verdict: Verdict
    section: str
    group: str
    page: int
    checks: list[ValueCheck] = field(default_factory=list)


@dataclass(slots=True)
class _CaseDraft:
    name: str
    verdict: Verdict
    page: int
    version: str | None = None
    wall_begin: datetime | None = None
    wall_end: datetime | None = None
    steps: list[_StepDraft] = field(default_factory=list)


def _rows(page: pymupdf.Page) -> list[list[_Span]]:
    spans = []
    height = page.rect.height
    for block in page.get_text("dict")["blocks"]:
        for line in block.get("lines", []):
            for s in line["spans"]:
                text = s["text"].strip()
                y = s["bbox"][1]
                if text and _HEADER_FOOTER_MARGIN < y < height - _HEADER_FOOTER_MARGIN:
                    spans.append(_Span(s["bbox"][0], y, s["size"], bool(s["flags"] & 16), text))
    spans.sort(key=lambda s: (round(s.y), s.x))
    rows: list[list[_Span]] = []
    for span in spans:
        if rows and abs(rows[-1][0].y - span.y) < 2:
            rows[-1].append(span)
        else:
            rows.append([span])
    return [sorted(r, key=lambda s: s.x) for r in rows]


def _verdict(text: str) -> Verdict | None:
    return VERDICTS.get(text.strip().lower())


def _wall_time(text: str) -> datetime | None:
    """'10/02/2026 12:24:11 PM +02:00' -> aware datetime."""
    try:
        return datetime.strptime(text.strip(), _WALL_TIME)
    except ValueError:
        return None


class PdfReportReader:
    source = Source.PDF_REPORT

    def read(self, path: Path) -> SourceData:
        path = Path(path)
        doc = pymupdf.open(path)
        cases: list[_CaseDraft] = []
        case_starts: dict[str, float] = {}
        metadata: dict[str, Any] = {}
        columns = _Columns()
        section = group = ""
        last_step: _StepDraft | None = None
        check_field = ""

        for page_number, page in enumerate(doc, start=1):
            for row in _rows(page):
                texts = [s.text for s in row]
                first = row[0]
                joined = " ".join(texts)
                current = cases[-1] if cases else None

                header = _TEST_CASE_HEADER.match(texts[0]) if first.size > 9 else None
                if header:
                    verdict = _verdict(texts[-1]) or Verdict.NONE
                    cases.append(_CaseDraft(header.group(2), verdict, page_number))
                    section = group = ""
                    last_step = None
                    continue

                if current is None and ":" in texts[0]:
                    # "Key: value", either in one span or split over two
                    key, _, value = joined.partition(":")
                    if value.strip():
                        metadata.setdefault(key.strip(), value.strip())
                if current is not None and texts[0].startswith("Version:"):
                    current.version = joined.split(":", 1)[1].strip() or None
                    continue
                if current is not None and texts[0] in ("Test Case Begin:", "Test Case End:"):
                    stamp = _wall_time(" ".join(texts[1:]))
                    if texts[0] == "Test Case Begin:":
                        current.wall_begin = stamp
                    else:
                        current.wall_end = stamp
                    continue

                if first.bold and joined in SECTIONS:
                    section, group = joined, ""
                    continue
                if "Time Stamp" in texts and "Title" in texts:
                    xs = {s.text: s.x for s in row}
                    columns = _Columns(
                        step=xs.get("Test Step", xs["Title"]) - 15,
                        title=xs["Title"] - 3,
                        verdict=xs.get("Verdict", 530) - 15,
                    )
                    continue

                if _TIME.match(texts[0]) and first.x < columns.step:
                    t = float(texts[0])
                    step = " ".join(s.text for s in row[1:] if s.x < columns.title).strip()
                    title = " ".join(s.text for s in row[1:] if columns.title <= s.x < columns.verdict).strip()
                    verdict = next((v for s in row if s.x >= columns.verdict and (v := _verdict(s.text))), Verdict.NONE)
                    if current is None:
                        # fixture "Main Part" lists each test case with its start time
                        name = next((s.text for s in row if s.text.startswith("TC_")), None)
                        if name:
                            case_starts[name] = t
                        continue
                    last_step = _StepDraft(t, step.replace("Resume reason", "Resume"), title, verdict,
                                           section, group, page_number)
                    current.steps.append(last_step)
                    check_field = ""
                    continue

                if current is None or texts[0] == "Index/Name":
                    continue
                if first.x <= columns.step and len(row) <= 2 and not first.bold:
                    # group line, e.g. "BTP-Verbindung aufbauen   Pass"
                    group = first.text
                    continue
                result = _verdict(texts[-1])
                if last_step is not None and len(row) == 4 and result in (Verdict.PASS, Verdict.FAIL):
                    last_step.checks.append(ValueCheck(check_field, texts[0], texts[1], texts[2], result is Verdict.PASS))
                    continue
                if last_step is not None and len(row) == 1 and first.x > columns.title + 10:
                    check_field = first.text      # validation table sub-header
                    continue
                if last_step is not None and all(s.x >= columns.title for s in row if s.text != "reason"):
                    # wrapped title line
                    extra = " ".join(s.text for s in row if columns.title <= s.x < columns.verdict)
                    last_step.title = f"{last_step.title} {extra}".strip()

        return SourceData(
            self.source, path, TimeBase(TimeReference.MEASUREMENT),
            test_cases=self._finish(cases, case_starts, path.name),
            metadata=self._metadata(metadata, cases),
        )

    def _finish(self, cases: list[_CaseDraft], starts: dict[str, float], file: str) -> list[TestCaseResult]:
        results = []
        for i, case in enumerate(cases):
            steps = [
                TestStep(s.time, s.step, s.title, s.verdict, s.section, s.group, tuple(s.checks),
                         EvidenceRef(self.source, file, f"page {s.page}"))
                for s in case.steps
                if not (s.step == "Resume" and _POLLING.match(s.title))
            ]
            start = starts.get(case.name, steps[0].time if steps else 0.0)
            if i + 1 < len(cases) and cases[i + 1].name in starts:
                end = starts[cases[i + 1].name]
            else:
                end = max((s.time for s in case.steps), default=start)
            results.append(TestCaseResult(case.name, case.verdict, start, end, case.version, steps,
                                          EvidenceRef(self.source, file, f"page {case.page}")))
        return results

    @staticmethod
    def _metadata(raw: dict[str, str], cases: list[_CaseDraft]) -> dict[str, Any]:
        meta: dict[str, Any] = {
            "test_begin": _wall_time(raw.get("Test Begin", "")),
            "test_end": _wall_time(raw.get("Test End", "")),
            "tester": raw.get("Login Name"),
            "computer": raw.get("Computer Name"),
            "canoe_version": raw.get("Version"),
            "test_case_wall_times": {c.name: (c.wall_begin, c.wall_end) for c in cases},
        }
        return meta
