#!/usr/bin/env bash
# End-to-end demo (docs/demo.md): tests, analysis of the RealOC run, synthetic scenarios, one synthetic report.
# Usage: scripts/demo.sh [--no-open]
# Output in output/demo/: report.md, report.html, report.json (all data, incl. the scenarios) and
# data-anlysis-report.json (flat summary) for visualization; formats in docs/report_json.md.
set -euo pipefail

cd "$(dirname "$0")/.."
PY=.venv/bin/python
OUT=output/demo
OPEN=1
[[ "${1:-}" == "--no-open" ]] && OPEN=0

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

step "1/4  Test suite"
.venv/bin/pytest -q

step "2/4  Analysis of the RealOC run, with the 15 scenarios in the JSON"
$PY analyze.py --out "$OUT" --format md html json --with-scenarios

step "3/4  Synthetic scenarios (data/synthetic/S*.pcapng)"
$PY -m trace_analyzer.synthetic

step "4/4  Report on a synthetic capture: status telegram within 500 ms after the AZGH of 02284"
$PY analyze.py --pcapng data/synthetic/S03s_unexpected_response.pcapng --no-blf-ethernet \
    --test-case 02284 --out "$OUT" --name synthetic_unexpected_response --format html

if [[ $OPEN == 1 && "$(uname)" == "Darwin" ]]; then
    open "$OUT/report.html" "$OUT/synthetic_unexpected_response.html"
fi
printf '\nReports in %s/\n' "$OUT"
printf 'JSON for visualization: %s/report.json (complete), %s/data-anlysis-report.json (flat summary)\n' "$OUT" "$OUT"
