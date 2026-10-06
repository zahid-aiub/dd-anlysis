"""python -m trace_analyzer.synthetic [--config config.yaml] [--out data/synthetic]

Writes one edited pcapng per synthetic scenario and prints, for every scenario, the edit and whether the
analyzer reached the expected conclusion. Exit code 1 if any scenario fails.
"""

import argparse
import sys
from pathlib import Path

from trace_analyzer.config import DEFAULT_CONFIG, load_config

from .runner import results_table, run_all


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m trace_analyzer.synthetic", description=__doc__.split("\n\n")[1])
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--out", type=Path, help="directory for the synthetic pcapng files (default data/synthetic)")
    args = parser.parse_args(argv)
    results = run_all(load_config(args.config), args.out)
    print(results_table(results))
    failed = [r for r in results if not r.passed]
    for r in failed:
        print(f"\nS{r.scenario.number} {r.scenario.title}:", *(f"  - {p}" for p in r.problems), sep="\n")
    print(f"\n{len(results) - len(failed)}/{len(results)} scenarios as expected")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
