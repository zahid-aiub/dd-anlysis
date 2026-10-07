"""The analysis as one JSON document, for visualization outside the analyzer.

Layout and field meanings: docs/report_json.md. Times are CANoe measurement time in seconds (`t`); `clock` is the
test bench wall-clock time. Findings have ids (`F001` ...); `test_case` fields are test case ids.
"""

import json
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

from trace_analyzer import __version__
from trace_analyzer.model import (
    Belegung,
    Direction,
    EventKind,
    EvidenceRef,
    FailureCategory,
    Finding,
    RastaType,
    Severity,
    TraceEvent,
    Verdict,
    split_test_name,
)
from trace_analyzer.pipeline import AnalysisResult
from trace_analyzer.rules.common import gfma_status

from .build import AREA, SOURCE_NAMES, area

SCHEMA = "trace-analyzer.report"
SCHEMA_VERSION = 1
FIELDS_HIDDEN = ("protocol_type", "checksum")


def _t(t: float | None) -> float | None:
    return None if t is None else round(t, 6)


def _case_id(name: str | None) -> str | None:
    """Test case id without the variant: all references to test cases in the JSON use it."""
    return split_test_name(name)[0] if name else None


def _plain(value: Any) -> Any:
    """JSON-safe copy of finding details and event fields."""
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(k): _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_plain(v) for v in value]
    if isinstance(value, float):
        return round(value, 6)
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, (datetime, Path)):
        return str(value)
    return value


class _Exporter:
    def __init__(self, result: AnalysisResult):
        self.result = result
        self.ctx = result.context
        self.time_of = {}
        for e in self.ctx.events:
            self.time_of.setdefault((e.ref.file, e.ref.locator), e.time)
        ordered = sorted(result.findings, key=lambda f: (f.time is None, f.time or 0.0, f.category.value))
        self.ids = {id(f): f"F{i:03d}" for i, f in enumerate(ordered, 1)}
        self.ordered = ordered

    def clock(self, t: float | None) -> str | None:
        absolute = self.result.timeline.absolute(t) if t is not None else None
        return absolute.isoformat(timespec="milliseconds") if absolute else None

    def evidence(self, ref: EvidenceRef, t: float | None = None) -> dict:
        return {"source": ref.source.value, "file": ref.file, "locator": ref.locator, "t": _t(t), "clock": self.clock(t)}

    def finding_evidence(self, f: Finding) -> list[dict]:
        out = []
        for ref in f.evidence:
            if ref.source.value in ("pdf_report", "test_spec"):
                t = f.time
            else:
                t = self.time_of.get((ref.file, ref.locator), f.time)
            out.append(self.evidence(ref, t))
        return out

    def finding(self, f: Finding, roles: dict[int, str]) -> dict:
        return {
            "id": self.ids[id(f)],
            "t": _t(f.time),
            "clock": self.clock(f.time),
            "test_case": _case_id(f.test_case),
            "category": f.category.value,
            "area": area(f.category),
            "severity": f.severity.value,
            "confidence": round(f.confidence, 3),
            "role": roles.get(id(f), "run" if f.test_case is None else "contributing"),
            "summary": f.summary,
            "evidence": self.finding_evidence(f),
            "details": _plain(dict(f.details)),
        }

    def case_of(self, t: float) -> str | None:
        tc = self.ctx.test_case_at(t)
        return tc.test_id if tc else None

    def telegram(self, e: TraceEvent) -> dict:
        fields = {k: v for k, v in e.fields.items() if k not in FIELDS_HIDDEN and k not in ("duplicate_ref", "differs_from")}
        return {"t": _t(e.time), "clock": self.clock(e.time), "test_case": self.case_of(e.time),
                "direction": e.direction.value, "from": e.sender, "to": e.receiver,
                "message": e.name, "code": f"0x{e.msg_type:04X}" if isinstance(e.msg_type, int) else e.msg_type,
                "command": e.name.startswith("KOMMANDO_"), "length": e.length, "fields": _plain(fields),
                "evidence": self.evidence(e.ref, e.time),
                "duplicate": e.fields.get("duplicate_ref"), "differs_from": e.fields.get("differs_from")}

    def timeline(self) -> dict:
        events = self.ctx.events
        states = []
        for s in gfma_status(self.ctx):
            belegung = s.fields["belegung"]
            try:
                name = Belegung(belegung).name.lower()
            except ValueError:
                name = f"unknown_{belegung}"
            states.append({"t": _t(s.time), "clock": self.clock(s.time), "test_case": self.case_of(s.time),
                           "element": s.sender, "belegung": belegung, "belegung_name": name,
                           "grundstellbar": s.fields["grundstellbar"],
                           "achszaehlfuellstand": s.fields["achszaehlfuellstand"],
                           "source": s.source.value, "evidence": self.evidence(s.ref, s.time)})
        sessions = []
        for s in self.ctx.sessions:
            inside = [e for e in events if e.kind is EventKind.RASTA and s.start <= e.time <= s.end]
            sessions.append({"index": s.index, "start": _t(s.start), "end": _t(s.end), "test_case": _case_id(s.test_case),
                             "established": s.established,
                             "closed_by": s.closed_by.value if s.closed_by else None,
                             "disconnect_reason": s.disconnect_reason,
                             "messages": {d.value: sum(e.direction is d for e in inside) for d in (Direction.TX, Direction.RX)},
                             "heartbeats": sum(e.msg_type == RastaType.HEARTBEAT for e in inside)})
        return {
            "gfma_states": states,
            "telegrams": [self.telegram(e) for e in events if e.kind is EventKind.SCI_TELEGRAM],
            "sessions": sessions,
            "operator_actions": [{"t": _t(e.time), "clock": self.clock(e.time), "test_case": self.case_of(e.time),
                                  "name": e.name, "command": e.fields.get("command"), "value": e.fields.get("value"),
                                  "evidence": self.evidence(e.ref, e.time)}
                                 for e in events if e.kind is EventKind.OPERATOR_ACTION],
            "log": [{"t": _t(e.time), "clock": self.clock(e.time), "test_case": self.case_of(e.time),
                     "level": e.fields.get("level"), "text": e.fields["text"], "evidence": self.evidence(e.ref, e.time)}
                    for e in events if e.kind is EventKind.LOG and "text" in e.fields],
        }

    def run(self) -> dict:
        ctx, events = self.ctx, self.ctx.events
        start = ctx.metadata.get("measurement_start")
        files = {}
        for e in events:
            files.setdefault(e.source, e.ref.file)
        for tc in ctx.test_cases:
            if tc.ref:
                files.setdefault(tc.ref.source, tc.ref.file)
        sources = [{"source": s.value, "name": SOURCE_NAMES.get(s, s.value), "file": files.get(s),
                    "alignment": {"method": a.method, "offset_s": round(a.offset, 6), "spread_ms": round(a.spread * 1000, 3),
                                  "drift_ppm": round(a.drift_ppm, 3), "samples": a.samples, "note": a.note}}
                   for s, a in ctx.alignments.items()]
        m = ctx.merge
        return {
            "configuration": ctx.metadata.get("configuration"),
            "canoe_version": ctx.metadata.get("canoe_version"),
            "measurement_start": start.isoformat(timespec="milliseconds") if start else None,
            "time_base": "CANoe measurement time in seconds since the measurement start",
            "duration": _t(max((e.time for e in events), default=0.0)),
            "sources": sources,
            "consistency_checks": [{"name": c.name, "sources": [s.value for s in c.sources], "matched": c.matched,
                                    "max_difference_ms": round(c.max_difference * 1000, 3), "unmatched": c.unmatched}
                                   for c in ctx.checks],
            "network_merge": None if m is None else {
                "primary": m.primary.value, "secondary": m.secondary.value if m.secondary else None,
                "identical_frames": m.matched_frames, "differing_frames": len(m.differing),
                "only_in_primary": len(m.only_in_primary), "only_in_secondary": len(m.only_in_secondary)},
        }


def _compact(x: "_Exporter", f: Finding) -> dict:
    return {"category": f.category.value, "area": area(f.category), "severity": f.severity.value, "t": _t(f.time),
            "clock": x.clock(f.time), "test_case": _case_id(f.test_case), "summary": f.summary,
            "evidence": x.finding_evidence(f)}


def _brief(f: Finding | None) -> dict | None:
    return None if f is None else {"category": f.category.value, "t": _t(f.time), "summary": f.summary}


def _key(f: Finding) -> tuple:
    return f.category, f.test_case, f.summary


def _outcome(scenario, found: list[Finding]) -> str:
    """failure: the scenario's failure was found as an error; warning: reported, but not a failure;
    ruled_out: the real run was checked and the failure is not there; check: a run-level check only."""
    if any(e.role == "ruled_out" for e in scenario.expectations):
        return "ruled_out"
    if not scenario.expectations:
        return "check"
    return "failure" if any(f.severity is Severity.ERROR for f in found) else "warning"


def scenario_json(results, base: AnalysisResult) -> list[dict]:
    """Per scenario: what was edited, the failure the analyzer found, its verdicts, and whether that is what the
    scenario expects."""
    before = {_key(f) for f in base.findings}
    out = []
    for r in results:
        s, x = r.scenario, _Exporter(r.result)
        ids = list(dict.fromkeys(e.test_id for e in s.expectations if e.test_id))
        target = s.expectations[0].category if s.expectations else None
        found = [f for f in r.result.findings if f.category is target
                 and (_case_id(f.test_case) in ids or (not ids and f.test_case is None))
                 and (not s.expectations[0].contains or s.expectations[0].contains in f.summary)] if target else []
        results_by_case = []
        for d in r.result.diagnoses:
            if d.test_case.test_id not in ids:
                continue
            own = [f for f in r.result.findings if f.test_case == d.test_case.name]
            results_by_case.append({
                "test_case": d.test_case.test_id,
                "report_verdict": d.test_case.verdict.value,
                "verdict": d.verdict.value,
                "verdict_differs": d.verdict is not d.test_case.verdict,
                "symptom": _brief(d.symptom),
                "cause": _brief(d.cause),
                # findings this scenario added to the real run (synthetic edits); all findings for real scenarios
                "findings": [dict(_compact(x, f), introduced=_key(f) not in before) for f in own
                             if f.severity is not Severity.INFO and (not s.synthetic or _key(f) not in before)],
            })
        out.append({
            "number": s.number, "key": s.key, "title": s.title, "detection": s.detection, "sources": s.sources,
            "data": "synthetic" if s.synthetic else "real",
            "capture": Path(r.capture).name if r.capture else None, "edit": r.changes,
            "outcome": _outcome(s, found),
            "failure": _compact(x, found[0]) if found else None,
            "results": results_by_case,
            "expected": [{"test_case": e.test_id, "category": e.category.value, "role": e.role,
                          "verdict": e.verdict.value if e.verdict else None, "contains": e.contains}
                         for e in s.expectations],
            "check": {"as_expected": r.passed, "problems": r.problems},
        })
    return out


def to_json(result: AnalysisResult, test_ids: list[str] | None = None, scenarios=None) -> dict:
    """The whole analysis as a JSON-ready dict (see docs/report_json.md)."""
    x = _Exporter(result)
    diagnoses = [d for d in result.diagnoses if not test_ids or any(t in d.test_case.name for t in test_ids)]
    names = {d.test_case.name for d in diagnoses}
    roles = {}
    for d in result.diagnoses:
        for f in d.contributing:
            roles[id(f)] = "contributing"
        if d.symptom is not None:
            roles[id(d.symptom)] = "symptom"
        if d.cause is not None:
            roles[id(d.cause)] = "cause" if d.cause is not d.symptom else "cause_and_symptom"
    findings = [x.finding(f, roles) for f in x.ordered if f.test_case is None or f.test_case in names]
    verdicts = [d.verdict.value for d in diagnoses]
    doc = {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "generator": f"trace-analyzer {__version__}",
        "generated": datetime.now().astimezone().isoformat(timespec="seconds"),
        "run": x.run(),
        "summary": {
            "test_cases": len(diagnoses),
            "verdicts": {v.value: verdicts.count(v.value) for v in Verdict if verdicts.count(v.value)},
            "verdict_differs_from_report": sum(d.verdict is not d.test_case.verdict for d in diagnoses),
            "findings": {s.value: sum(f["severity"] == s.value for f in findings) for s in Severity},
        },
        "findings": findings,
        "timeline": x.timeline(),
        "vocabulary": {
            "belegung": {b.value: b.name.lower() for b in Belegung},
            "grundstellbar": {0: "nicht grundstellbar", 1: "grundstellbar"},
            "severity": [s.value for s in Severity],
            "categories": {c.value: area(c) for c in FailureCategory},
            "areas": sorted(set(AREA.values()) | {"SCI-TDS protocol"}),
            "roles": ["cause", "symptom", "cause_and_symptom", "contributing", "run"],
            "scenario_outcomes": {"failure": "the scenario's failure was found as an error",
                                  "warning": "reported, but not a failure",
                                  "ruled_out": "checked on the real run: the failure is not there",
                                  "check": "run-level check without a finding"},
        },
    }
    if scenarios is not None:
        doc["scenarios"] = scenario_json(scenarios, result)
        outcomes = [sc["outcome"] for sc in doc["scenarios"]]
        doc["summary"]["scenarios"] = {
            "total": len(scenarios), "as_expected": sum(r.passed for r in scenarios),
            "outcome": {o: outcomes.count(o) for o in ("failure", "warning", "ruled_out", "check")},
        }
    return doc


def write_json(result: AnalysisResult, path: Path, test_ids: list[str] | None = None, scenarios=None) -> Path:
    path = Path(path)
    path.write_text(json.dumps(to_json(result, test_ids, scenarios), ensure_ascii=False, indent=2) + "\n",
                    encoding="utf-8")
    return path
