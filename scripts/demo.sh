#!/usr/bin/env bash
# End-to-end demo (docs/demo.md): tests, analysis of the RealOC run, synthetic scenarios, one synthetic report.
# Usage: scripts/demo.sh [--no-open]    reports go to output/demo/
set -euo pipefail

cd "$(dirname "$0")/.."
PY=.venv/bin/python
OUT=output/demo
OPEN=1
[[ "${1:-}" == "--no-open" ]] && OPEN=0

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

step "1/4  Test suite"
.venv/bin/pytest -q

step "2/4  Analysis of the RealOC run"
$PY analyze.py --out "$OUT"

step "3/4  Synthetic scenarios (data/synthetic/S*.pcapng)"
$PY -m trace_analyzer.synthetic

step "4/4  Report on a synthetic capture: status telegram within 500 ms after the AZGH of 02284"
$PY analyze.py --pcapng data/synthetic/S03s_unexpected_response.pcapng --no-blf-ethernet \
    --test-case 02284 --out "$OUT" --name synthetic_unexpected_response --format html

if [[ $OPEN == 1 && "$(uname)" == "Darwin" ]]; then
    open "$OUT/report.html" "$OUT/synthetic_unexpected_response.html"
fi
printf '\nReports in %s/\n' "$OUT"
