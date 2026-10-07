# Important to Know

The essentials of this project on one page: where it came from, how to set it up, the decisions taken, and what
is still open. Updated at the end of every phase. Details are in [README.md](README.md) and [docs/](docs/).

## 1. Initiation

- **Task.** `project-task.docx` lists seven assignments; this is **#7, Data Analysis: Multi-Source Trace Failure
  Analysis** (Zahidul Islam). The goal is to correlate one test run from several sources and find the most
  probable root cause of each failed test case. The common task of all seven, 10–15 analysis scenarios, is
  covered here too.
- **Plan.** `TDS_Task_Analysis_Checklist.pdf` (repo root, not committed): phases 0–8, worked one at a time,
  each started with "Phase N start". Some numbers in it predate Phase 1 and are wrong: the BLF has 2,159
  Ethernet frames (not ~1,083), the heartbeat is ~0.3 s (not ~0.46 s), and scenario 15 is about different zero
  points, not a clock mismatch.
- **Input data** (`TDS_Task/TDS_Task/`, confidential, never committed): one CANoe SCI-TDS run of 2026-10-02
  against the real axle-counter controller (RealOC).

| Source | What it tells | Role in the analysis |
|---|---|---|
| `Test_Description/TC_*.txt` | precondition, steps, expected/forbidden telegrams, 500 ms limit, expected bytes | 1. what should happen |
| `Real_SCI-TDS_2026-10-02_12-24-11.pdf` | 5 test cases, verdicts, step log, "Sollzustand", byte checks | 2. what CANoe did |
| `RealOCWorking_TDS_21026.pcapng` | 2,159 frames (RaSTA, SCI-TDS BL5) | 3. why: telegrams |
| `RealOCWorking_TDS_21026.blf` | the same 2,159 frames + CANoe variables, panel actions, test structure | 3. why: state, operator, windows |
| `TDS_Report_21026.txt` | CANoe write window: decoded GFM-A status, stop message | 3. why: cross-check |
| `SCI_TDS_Telegrams_3.4.6_to_3.4.16 1.xlsx` | telegram catalogue, developer use cases | reference |

- There are Test_Description files for 02283, 02284, 02288 and 00525, but **none for 00522**. The suffixes
  `(O)`, `(F)`, `(F-ReZE)`, `(O-ReZE)` are in the PDF test case names, not in the .txt files.

## 2. Setup (macOS)

- Python **3.11** venv in `.venv` (pyenv 3.11.11; the pyenv global 3.8 does not work):
  `python3.11 -m venv .venv && .venv/bin/pip install -e ".[dev]"`.
- Wireshark 4.6 (`brew install --cask wireshark-app`). The NeuPro Lua dissectors from `TDS_Task/Wireshark/LUA.zip`
  go in `~/.local/lib/wireshark/plugins/neupro/`, and `sci.tds_bl: BL 5` goes in
  `~/.config/wireshark/preferences`. Wireshark is only needed to view the traces and for the tests that
  cross-check the decoder; the analyzer itself does not need it.
- Wireshark profile **SCI-TDS**: columns for RaSTA type, SCI message, sender, Belegung, Grundstellbarkeit and
  Achszähler, plus filter buttons.

## 3. How to run

```bash
.venv/bin/python analyze.py --config config/config.yaml   # report of all test cases → output/report.{md,html}
.venv/bin/python analyze.py --test-case 02288              # only test cases whose name contains 02288
.venv/bin/python -m trace_analyzer.synthetic              # synthetic scenarios → data/synthetic/S*.pcapng
scripts/demo.sh                                           # demo; output/demo/report.json = all data for the frontend
.venv/bin/pytest                                          # 168 tests
```

In Python: `trace_analyzer.pipeline.analyze(load_config())` returns timeline, context, findings and one diagnosis
per test case; `trace_analyzer.report.write_reports(result, out_dir)` writes the reports. Example report:
[docs/example_report/TC_NPRO.295.02288.01.md](docs/example_report/TC_NPRO.295.02288.01.md).

## 4. Status

| Phase | Content | State |
|---|---|---|
| 0 | environment | done |
| 1 | data understanding, manual root cause ([docs/data_understanding.md](docs/data_understanding.md)) | done |
| 2 | architecture, data model ([docs/architecture.md](docs/architecture.md)) | done |
| 3 | readers for all sources | done |
| 4 | time alignment, PCAPNG/BLF deduplication | done |
| 5 | correlation, rules, diagnosis | done |
| 6 | 15 scenarios, real and synthetic ([docs/scenarios.md](docs/scenarios.md)) | done, committed `394ef67` |
| 7 | CLI (`analyze.py`), Markdown/HTML report with timeline, example report 02288 | done |
| 8 | README, architecture diagram ([docs/architecture.svg](docs/architecture.svg)), demo ([docs/demo.md](docs/demo.md), `scripts/demo.sh`, [docs/presentation.html](docs/presentation.html)), review sheet ([docs/review.md](docs/review.md)) | done; supervisor review pending |

Git: branch `main`, no remote. Commits only when asked.

## 5. Results on the RealOC run

| Test case | Report | Analyzer | Root cause |
|---|---|---|---|
| 02283 (O) | pass | pass | - |
| 02284 (F) | pass | pass | - |
| 02288 (O) | fail | fail | GFM-A 34W1 went disturbed at 186.953 s, 102 ms after "occupied" with Achszählfüllstand 0x0000. A reset was possible for 50 s, but no AZG/AZGH was sent. The precondition timed out at 300.288 s. Also an `incorrect_length` failure: step 2 expects 48 bytes, the RealOC sends 47 |
| 00525 (F-ReZE) | fail | fail | cascade: it started disturbed because the cleanup of 02288 failed. Manual panel AZGH/AZG (forbidden) had no effect |
| 00522 (O-ReZE) | inconclusive | inconclusive | test unit stopped by the user at 488.32 s |

There are no connection, sequence, payload or timing faults in the real data.

## 6. Decisions

| Date | Decision | Why |
|---|---|---|
| Phase 3 | RaSTA/SCI-TDS decoded in Python, tshark only as test oracle | the Lua dissector drops malformed telegrams; Wireshark shifts BLF times by the analysing PC's time zone |
| Phase 4 | master timeline = CANoe measurement time; pcapng offset by frame match with the BLF | three of five sources already use it; µs exact |
| Phase 4 | pcapng is the primary network source, BLF duplicates dropped | Wireshark frame numbers in the evidence |
| Phase 5 | symptom (what the test reported) is separated from cause (deepest explanation) | a precondition timeout is a symptom, the disturbed GFM-A is the cause |
| 2026-10-06 | analysis order: Test_Description → PDF → traces; the .txt precondition is the target state | agreed with the user |
| 2026-10-06 | **every length mismatch is a failure**: BL5 layout, spec layout vs. device (48 vs. 47), sender vs. receiver capture | decided by the user |
| 2026-10-06 | analyzer verdict: report pass + error finding → fail | synthetic and future runs |
| 2026-10-06 | a rejected command is an error, except as the answer to the trigger of a negative test | xlsx use case 4 allows the rejection there |
| 2026-10-06 | synthetic data: edit the pcapng only; RaSTA safety code kept | MD4 initial values of the link unknown; BLF writing not implemented |
| 2026-10-06 | report timeline as own SVG instead of plotly (dependency removed) | self-contained, offline, small, prints; tooltips via SVG titles, event table as table view |
| 2026-10-06 | report leaves out user and computer names from the CANoe metadata | not needed for the analysis |
| 2026-10-06 | presentation as a local HTML file, not published online | the slides quote confidential test data |
| 2026-10-06 | JSON export (`report.json`, schema v1, docs/report_json.md) for a frontend developer | data visualization outside the analyzer |

## 7. Open questions for the team

1. Target SCI-TDS baseline: BL5 (RealOC) or BL6/BL7 (Test_Description)? The length mismatch counts as a
   failure either way.
2. Physical cause of the disturbance at 186.953 s.
3. Is 11.2 s from AZGH to "resettable" expected, given the 500 ms requirement of 02288?
4. AZGH in state frei / not resettable: `0x0006` rejection (xlsx) or no telegram (RealOC)?
5. Meaning of Achszählfüllstand `0x0000`.
6. Test_Description for 00522.
7. Which test case version is authoritative (the report shows 5; the Test_Description files have 7, 5, 4 and 5).
8. RealOC RaSTA T_max (config assumes 750 ms).
9. Meaning of the `ReZE` suffix.

## 8. Confidentiality

The `TDS_Task/` data, the Lua dissectors, `data/synthetic/*.pcapng`, `output/` reports and
`docs/example_report/` (quotes real telegrams) are DB InfraGO internal material. Do not upload them to public tools or push them to a public repository. See
[docs/CONFIDENTIALITY.md](docs/CONFIDENTIALITY.md).

## 9. Known limitations

- Confidence values are heuristic.
- The precondition and cascade rules assume one GFM-A.
- The RaSTA gap limit is an assumption (750 ms).
- Synthetic captures keep the original RaSTA safety code, and only the pcapng changes; PDF, log and BLF
  objects stay real.
- Not covered for lack of data: a missing AZGH-Quittung, and a spec response timeout in a main part.
