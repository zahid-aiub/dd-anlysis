"""End-to-end analysis: read sources → align → correlate → rules → diagnoses."""

from dataclasses import dataclass

from trace_analyzer.correlate import Timeline, build_context, build_timeline
from trace_analyzer.model import AnalysisContext, Diagnosis, Finding
from trace_analyzer.readers import load_sources
from trace_analyzer.rules import diagnose, run_rules


@dataclass(slots=True)
class AnalysisResult:
    timeline: Timeline
    context: AnalysisContext
    findings: list[Finding]
    diagnoses: list[Diagnosis]


def analyze(cfg: dict) -> AnalysisResult:
    timeline = build_timeline(load_sources(cfg), cfg)
    context = build_context(timeline, cfg)
    findings = run_rules(context)
    return AnalysisResult(timeline, context, findings, diagnose(context, findings))
