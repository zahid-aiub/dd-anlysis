# Review

This page is for the supervisor and the team: what Task #7 delivers, where to look to check it, which decisions
need confirmation, and room for feedback. Running `scripts/demo.sh` (about 15 s) produces everything shown
here.

## 1. Delivered against the task

| Asked for (project-task.docx, Task #7) | Delivered | Where |
|---|---|---|
| Correlate PCAPNG, BLF and the CANoe PDF report | Readers for all three, plus the CANoe log and the Test_Description; one timeline in CANoe measurement time | `src/trace_analyzer/readers/`, `correlate/` |
| Find the most probable root cause of a failed test case | Diagnosis per test case: symptom, cause, contributing findings, ruled out, analyzer verdict, confidence | `rules/engine.py`, [example report](example_report/TC_NPRO.295.02288.01.md) |
| Failure types: missing message, wrong order, invalid payload, incorrect length, timeout, connection interruption, unexpected response, configuration mismatch | One rule each, plus 8 more (sequence, precondition, disturbed GFM-A, cascade, abort, rejection, time alignment, manual action) | [architecture.md §6](architecture.md) |
| Evidence for each conclusion | File, frame/page/line and time for every finding | report "Evidence" sections |
| 10–15 analysis scenarios (common task) | 15 scenarios, 21 checks, on the real run or on synthetic captures | [scenarios.md](scenarios.md) |
| Report | Markdown and HTML with a timeline chart per test case | `analyze.py`, `report/` |

## 2. How to check the results

1. **Manual analysis vs. tool.** [data_understanding.md §7](data_understanding.md) holds the Phase 1 manual
   root-cause analysis of 02288. `tests/fixtures/ground_truth.yaml` encodes it, and `tests/test_diagnosis.py`
   requires the tool to reproduce it for all five test cases.
2. **Decoder vs. NeuPro dissector.** `tests/test_readers.py` compares every decoded telegram with the BL5 Lua
   dissector output (tshark).
3. **Spot check in Wireshark.** Every evidence line names a frame. For example, frames 423, 425, 504 and 837
   show the 02288 state sequence 2/0 → 3/0 → 3/1 → 3/0.
4. **Scenarios.** `python -m trace_analyzer.synthetic` regenerates every synthetic capture and checks the
   expected cause and verdict of each scenario.

## 3. Decisions to confirm

| # | Decision | Effect | Confirm? |
|---|---|---|---|
| D1 | The Test_Description precondition is the target state; the report's "Sollzustand" is the fallback and a cross-check | A test that reaches its main part in another state fails | |
| D2 | Every length mismatch is a failure, including spec layout vs. device (48-byte BL6/BL7 status vs. RealOC BL5 47 bytes) | 02288 also shows an `incorrect_length` error; the cause stays the disturbed GFM-A | |
| D3 | Analyzer verdict: a test the report passes is `fail` if an error finding belongs to it | On the real run, analyzer and report agree; synthetic runs show the difference | |
| D4 | A rejected command is a failure, except as the answer to the trigger of a negative test (only `NOT` steps) | Follows xlsx use case 4 | |
| D5 | The cause is the earliest error finding up to the symptom; ties are broken by precedence (cascade → connection → … → unexpected) | Inherited states win over later symptoms | |
| D6 | RaSTA silence above 750 ms is a connection interruption | Assumption until the RealOC T_max is known | |

## 4. Open questions for the team

1. Target SCI-TDS baseline: BL5 (RealOC) or BL6/BL7 (Test_Description)?
2. Physical cause of the disturbance at 186.953 s in 02288 (handling of the metal object at the wheel sensor?).
3. Is 11.2 s from AZGH to "resettable" expected, given the 500 ms requirement of 02288?
4. AZGH in state frei / not resettable: `0x0006` rejection (xlsx) or no telegram (RealOC)?
5. Meaning of Achszählfüllstand `0x0000`.
6. Test_Description for 00522.
7. Authoritative test case version (the report shows 5; the Test_Description files have 7, 5, 4 and 5).
8. RaSTA T_max of the RealOC.
9. Meaning of the `ReZE` suffix.

## 5. Known limits

- Only one baseline (BL5) and one GFM-A per run are implemented; confidence values are heuristic.
- Synthetic captures edit only the pcapng and keep the original RaSTA safety code.
- There is only one real run. More runs, especially ones with real communication faults, would test the rules
  beyond the synthetic captures.
- Not covered for lack of data: a missing AZGH-Quittung, and a spec response timeout in a main part.

## 6. Feedback

| Date | From | Topic | Feedback | Action |
|---|---|---|---|---|
| | | | | |
