"""Command line: analyze a test run and write the reports.

    python analyze.py --config config/config.yaml [--out output] [--format md html] [--test-case 02288]
    python analyze.py --pcapng data/synthetic/S03s_unexpected_response.pcapng --no-blf-ethernet
    python analyze.py --format json --with-scenarios       # one JSON file with everything, for visualization
"""

import argparse
import sys
from pathlib import Path

from trace_analyzer.config import DEFAULT_CONFIG, ConfigError, load_config
from trace_analyzer.pipeline import analyze
from trace_analyzer.report import FORMATS, write_reports


def summary(result) -> str:
    rows = [("Test case", "Report", "Analyzer", "Root cause")]
    for d in result.diagnoses:
        cause = f"{d.cause.category.value}: {d.cause.summary}" if d.cause else "-"
        rows.append((d.test_case.name, d.test_case.verdict.value, d.verdict.value, cause))
    widths = [max(len(r[i]) for r in rows) for i in range(3)]
    return "\n".join(f"{r[0]:<{widths[0]}}  {r[1]:<{widths[1]}}  {r[2]:<{widths[2]}}  {r[3]}" for r in rows)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="analyze.py", description="Multi-source trace failure analysis: "
                                     "correlates PCAPNG, BLF, CANoe report/log and Test_Description and explains "
                                     "each failed test case.")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG, help="YAML configuration (data paths, nodes, limits)")
    parser.add_argument("--out", type=Path, help="output directory (default: output.dir of the configuration)")
    parser.add_argument("--format", nargs="+", choices=FORMATS, default=list(FORMATS), help="report formats")
    parser.add_argument("--test-case", action="append", dest="test_cases", metavar="ID",
                        help="only report test cases whose name contains ID (repeatable), e.g. 02288")
    parser.add_argument("--name", default="report", help="report file name without extension")
    parser.add_argument("--pcapng", type=Path, help="analyze this capture instead of the configured one, "
                        "e.g. a synthetic scenario from data/synthetic/")
    parser.add_argument("--no-blf-ethernet", action="store_true",
                        help="use the BLF only for its CANoe objects (needed with an edited pcapng)")
    parser.add_argument("--with-scenarios", action="store_true",
                        help="also run the 15 analysis scenarios and add their results to the JSON report")
    args = parser.parse_args(argv)

    try:
        cfg = load_config(args.config)
    except (OSError, ConfigError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.pcapng:
        cfg["data"]["pcapng"] = args.pcapng.resolve()
    if args.no_blf_ethernet:
        cfg.setdefault("sources", {})["blf_ethernet"] = False
    missing = [k for k, p in cfg["data"].items() if not Path(p).exists()]
    if missing:
        print(f"warning: not found, skipped: {', '.join(missing)}", file=sys.stderr)

    result = analyze(cfg)
    if args.test_cases and not any(any(t in d.test_case.name for t in args.test_cases) for d in result.diagnoses):
        print(f"error: no test case matches {args.test_cases}", file=sys.stderr)
        return 2
    scenarios = None
    if args.with_scenarios:
        from trace_analyzer.synthetic.runner import run_all
        scenarios = run_all(cfg)
    paths = write_reports(result, args.out or cfg["output"]["dir"], tuple(args.format), args.test_cases, args.name,
                          scenarios)
    print(summary(result))
    if scenarios is not None:
        print(f"\nscenarios: {sum(r.passed for r in scenarios)}/{len(scenarios)} as expected")
    print("\nwritten:", *(f"  {p}" for p in paths if p.suffix in (".md", ".html", ".json")), sep="\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
