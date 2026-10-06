"""Generate the synthetic captures and run the analyzer on every scenario."""

import copy
import re
from pathlib import Path

from trace_analyzer.model import Source
from trace_analyzer.pipeline import AnalysisResult, analyze

from .capture import Capture
from .scenarios import SCENARIOS, Scenario, ScenarioResult, evaluate


def scenario_config(cfg: dict, pcapng: Path, blf_ethernet: bool) -> dict:
    variant = copy.deepcopy(cfg)
    variant["data"]["pcapng"] = Path(pcapng)
    variant.setdefault("sources", {})["blf_ethernet"] = blf_ethernet
    return variant


def build_capture(scenario: Scenario, cfg: dict, base: AnalysisResult, out_dir: Path) -> tuple[Path, list[str]]:
    offset = base.context.alignments[Source.PCAPNG].offset
    capture = Capture.load(cfg["data"]["pcapng"], cfg["nodes"], offset, cfg["protocol"]["sci_tds_baseline"])
    scenario.mutate(capture, base)
    digits, suffix = re.fullmatch(r"(\d+)(\w*)", scenario.number).groups()
    path = capture.save(Path(out_dir) / f"S{int(digits):02d}{suffix}_{scenario.key}.pcapng")
    return path, capture.changes


def run_scenario(scenario: Scenario, cfg: dict, base: AnalysisResult, out_dir: Path) -> ScenarioResult:
    if not scenario.synthetic:
        return ScenarioResult(scenario, base, problems=evaluate(scenario, base))
    path, changes = build_capture(scenario, cfg, base, out_dir)
    result = analyze(scenario_config(cfg, path, scenario.blf_ethernet))
    return ScenarioResult(scenario, result, changes, evaluate(scenario, result), str(path))


def run_all(cfg: dict, out_dir: Path | None = None, scenarios=SCENARIOS) -> list[ScenarioResult]:
    out_dir = Path(out_dir or cfg["base_dir"] / "data" / "synthetic")
    base = analyze(cfg)
    return [run_scenario(s, cfg, base, out_dir) for s in scenarios]


def _conclusion(r: ScenarioResult) -> str:
    """What the analyzer concluded for the test cases the scenario is about."""
    ids = list(dict.fromkeys(e.test_id for e in r.scenario.expectations if e.test_id))
    parts = []
    for d in r.result.diagnoses:
        if d.test_case.test_id in ids:
            cause = f", cause {d.cause.category.value}" if d.cause else ""
            parts.append(f"{d.test_case.test_id.rsplit('.', 2)[-2]}: {d.verdict.value}{cause}")
    return "; ".join(parts) or "-"


def results_table(results: list[ScenarioResult]) -> str:
    rows = ["| # | Scenario | Data | Edit | Analyzer | Expected |", "|---|---|---|---|---|---|"]
    for r in results:
        s = r.scenario
        data = "synthetic" if s.synthetic else "real"
        edit = "; ".join(r.changes) or "-"
        rows.append(f"| {s.number} | {s.title} | {data} | {edit} | {_conclusion(r)} | "
                    f"{'yes' if r.passed else 'NO'} |")
    return "\n".join(rows)
