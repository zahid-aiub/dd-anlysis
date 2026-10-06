# Multi-Source Trace Failure Analysis

Correlates a CANoe SCI-TDS test run from several sources (PCAPNG capture, BLF log, CANoe PDF test report)
to find the most probable root cause of a failed test case.

Status: Phase 0 (environment setup), Phase 1 (data understanding, see
[docs/data_understanding.md](docs/data_understanding.md)), Phase 2 (architecture and data model, see
[docs/architecture.md](docs/architecture.md)), Phase 3 (readers for all five sources), Phase 4 (time alignment
and network deduplication), Phase 5 (correlation, 16 rules, diagnosis per test case) and Phase 6 (15 analysis
scenarios on real and synthetic data, see [docs/scenarios.md](docs/scenarios.md)) done. Reporting follows.

Synthetic scenarios (writes the edited captures to `data/synthetic/` and checks the analyzer's conclusions):

```bash
.venv/bin/python -m trace_analyzer.synthetic
```

```python
from trace_analyzer.config import load_config
from trace_analyzer.pipeline import analyze

result = analyze(load_config())
for d in result.diagnoses:
    print(d.test_case.name, d.test_case.verdict, d.symptom and d.symptom.summary, d.cause and d.cause.summary)
```

## Layout

```
config/config.yaml        data paths, SCI-TDS baseline, nodes, timeouts
src/trace_analyzer/
  readers/                PCAPNG, BLF, PDF report, CANoe log, test description readers
  model/                  common data structures
  correlate/              time alignment and correlation
  rules/                  root-cause rules
  report/                 report generation
  synthetic/              capture editor and the 15 analysis scenarios
tests/                    pytest suite
data/synthetic/           generated failure scenarios (pcapng, not committed)
docs/                     project documentation
output/                   generated reports (not committed)
TDS_Task/                 original input data (not committed, confidential)
```

## Setup (macOS)

The analyzer itself only needs Python. Wireshark and the NeuPro dissectors (steps 1–3) are needed to view
the traces and for the test suite, which cross-checks the decoder against the Lua dissectors.

1. Wireshark 4.6+: `brew install --cask wireshark-app` (provides `tshark`).
2. NeuPro Lua dissectors: copy the `1_RaSTA` and `2_SCI` folders from `TDS_Task/Wireshark/LUA.zip` into the
   personal Lua plugin folder (Wireshark: Help → About Wireshark → Folders → Personal Lua Plugins), for example
   `~/.local/lib/wireshark/plugins/neupro/`. Wireshark 4.x loads them automatically; `init.lua.neupro` is only
   needed for Wireshark 3.x and older.
3. SCI-TDS baseline: Edit → Preferences → Protocols → SCI → TDS Protokoll = **BL 5**, or add
   `sci.tds_bl: BL 5` to `~/.config/wireshark/preferences`. BL5 is the version that matches the RealOC capture.
4. Python environment:

   ```bash
   python3.11 -m venv .venv
   .venv/bin/pip install -e ".[dev]"
   ```

5. Check the environment:

   ```bash
   .venv/bin/pytest
   ```

## Confidentiality

The input data and dissectors are DB InfraGO internal material. See [docs/CONFIDENTIALITY.md](docs/CONFIDENTIALITY.md).
