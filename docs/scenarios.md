# Phase 6: Analysis Scenarios

The 15 scenarios from the task checklist, each with the data that shows it and the conclusion the analyzer must
reach. Scenarios the RealOC run contains are checked on the real data; the others on synthetic captures built
from the RealOC pcapng. The catalogue and the expected conclusions are code
(`src/trace_analyzer/synthetic/scenarios.py`), and every scenario is a test (`tests/test_synthetic.py`).

```bash
.venv/bin/python -m trace_analyzer.synthetic     # writes data/synthetic/S*.pcapng, prints the table below
```

## 1. How the analysis reads the sources

1. **Test_Description (.txt)**: what should happen. The precondition gives the target GFM-A state
   (`"GFM-A occupied and cannot be primed"` → Belegung 2 / Grundstellbarkeit 0). The steps give the trigger
   command, expected or forbidden telegrams, the 500 ms limit and expected bytes.
2. **PDF report**: what CANoe did: test case windows, verdicts, the failed step, the report's "Sollzustand".
3. **Traces (pcapng, BLF, CANoe log)**: why. These are telegrams and GFM-A states on one timeline (CANoe
   measurement time), plus the BLF's panel actions and CANoe variables.

The target state comes from the Test_Description; the report's "Sollzustand" is the fallback (00522 has no
Test_Description) and a cross-check (a difference is a `configuration_mismatch`). A test that reaches its main
part in a state other than the Test_Description precondition is `precondition_not_reached` even if CANoe did
not notice.

**Length mismatches are failures** (decision 2026-10-06):

- telegram length vs. its BL5 layout (what the receiver decodes),
- Test_Description layout vs. the telegram the device sends (BL6/BL7 48-byte status vs. RealOC BL5 47 bytes),
- the same frame with different length in the two captures (BLF = CANoe side, pcapng = wire).

**Analyzer verdict.** A test the report passes is `fail` if an `error` finding belongs to it
(`Diagnosis.verdict`). On the real run the analyzer agrees with the report for all five test cases.

## 2. Synthetic captures

`Capture` (`synthetic/capture.py`) edits a copy of the RealOC pcapng at RaSTA level, so the result stays a
consistent capture:

| Edit | Used for |
|---|---|
| data message ↔ heartbeat, same sequence number | remove or inject telegrams without a sequence gap |
| move application data to a later heartbeat | delay a response, change the order |
| edit or truncate one telegram | invalid payload, incorrect length |
| drop frames | connection interruption, sequence gap |
| shift frame timestamps | clock step |

Lengths and IPv4/UDP checksums are recomputed (rebuilding all 2,159 frames unchanged reproduces them byte for
byte). The synthetic files decode with the NeuPro Lua dissectors (BL5) without errors.

Limitations:

- **Safety code.** The RaSTA safety code is a half MD4 with the link's own initial values (it does not match
  standard MD4), so edited frames keep the original code. A real receiver would reject them; neither the
  analyzer nor the dissector verifies the code.
- **Only the network trace changes.** The PDF report, CANoe log and BLF objects are those of the real run. The
  report therefore still says "pass" where the analyzer finds a failure; the analyzer's verdict is what the
  scenario checks. When a status telegram moves or changes, the consistency check between pcapng and CANoe log
  or BLF variables reports a `time_alignment` warning, which is correct for the data it is given.
- **BLF frames.** Synthetic runs use the BLF only for its CANoe objects (`sources.blf_ethernet: false`). If they
  kept its frames, those frames would undo the edit. The pcapng is then aligned with the RaSTA timestamps
  (offset within 1 ms of the frame match). Scenarios 6c and 15s keep the BLF frames on purpose, to compare the
  two captures.

## 3. Scenarios and results

Test cases: 02283 (O, pass), 02284 (F, pass), 02288 (O, fail), 00525 (F-ReZE, fail), 00522 (O-ReZE,
inconclusive). Synthetic edits are in the 02283 session unless the scenario needs a test step (02284).

| # | Scenario | How it is detected | Sources | Data | Edit | Analyzer conclusion |
|---|---|---|---|---|---|---|
| 1 | TDS response timeout | Response later than 500 ms after the request (start-up: Aufrüstanforderung → Aufrüstbeginn) | pcapng, Test_Description | synthetic | frame 56: Aufrüstbeginn/status/Aufrüstende sent 0.607 s later, in frame 60 | 02283: fail, cause timeout ("MELDUNG_AUFRUESTBEGINN after 908 ms (limit 500 ms)") |
| 2 | Missing message | Expected response never arrives (Aufrüstende after Aufrüstbeginn) | pcapng | synthetic | frame 56: Meldung Aufrüstende removed | 02283: fail, cause missing_message; contributing wrong_order (AZGH before Aufrüstende) |
| 3 | Unexpected response (real check) | NOT step: no Meldung GFM-A Belegungszustand within 500 ms after the AZGH | pcapng, Test_Description | real | - | 02283, 02284: pass, unexpected_response ruled out |
| 3s | Unexpected response | A status telegram arrives within the 500 ms the NOT step forbids | pcapng, Test_Description | synthetic | frame 326: heartbeat replaced by status 1/1, 299 ms after the AZGH | 02284: fail, cause unexpected_response |
| 4 | Wrong message order | Start-up order: version check → Aufrüstanforderung → Aufrüstbeginn → reports → Aufrüstende | pcapng | synthetic | frames 51/54: Aufrüstanforderung sent before the BTP version check | 02283: fail, cause wrong_order |
| 5 | Invalid payload | Field value outside its BL5 range, wrong identifiers, same frame with other bytes in the two captures | pcapng, PDF | synthetic | frame 132: Belegungszustand 0x09 (valid 1-5) | 02283: fail, cause invalid_payload |
| 6 | Incorrect length: Test_Description vs. device | Test_Description expects a 48-byte BL6/BL7 status, the RealOC sends 47 bytes (BL5) | Test_Description, pcapng | real | - | 02288: incorrect_length error (step 2 cannot pass), contributing; cause stays device_disturbed |
| 6s | Incorrect length | Telegram shorter than its BL5 layout | pcapng, PDF | synthetic | frame 132: status telegram 46 bytes instead of 47 | 02283: fail, cause incorrect_length |
| 6c | Incorrect length: sender vs. receiver side | Same frame with different length in the two captures | pcapng, BLF | synthetic | frame 219: AZGH 42 bytes on the wire, the BLF (sender side) keeps 43 | 02283: fail, cause incorrect_length ("88 bytes in …pcapng frame 219, 89 bytes in …blf object 1183") |
| 7 | Connection interruption (real check) | RaSTA gap above 750 ms, disconnect reason other than user request, disconnect by the device | pcapng, BLF | real | - | 02288, 00525: connection_interruption ruled out |
| 7s | Connection interruption | No RaSTA message for 2 s | pcapng | synthetic | 12 frames between 70.0 s and 72.0 s removed | 02283: fail, cause connection_interruption; contributing sequence_error |
| 8 | RaSTA sequence gap / retransmission | Sequence number skipped or repeated | pcapng | synthetic | frame 102: one RX heartbeat removed | 02283: fail, cause sequence_error (gap 0.6 s, below the connection limit) |
| 9 | Precondition not reached | GFM-A not in the Test_Description target state | PDF, Test_Description, BLF, pcapng | real | - | 02288 (target 2/0, actual 3/0) and 00525 (target 1/0, actual 3/0): symptom precondition_not_reached |
| 10 | GFM-A disturbed | Belegungszustand 3; precursor occupied with Achszählfüllstand 0x0000 | pcapng, BLF, CANoe log | real | - | 02288: fail, cause device_disturbed (102 ms after the precursor, 50 s reset window unused) |
| 11 | Cleanup failure cascade | Cleanup of test N failed, test N+1 starts disturbed | PDF, pcapng | real | - | 00525: fail, cause cascade_failure (left by 02288) |
| 12 | Test aborted / inconclusive | Test unit stopped by the user | PDF, BLF, CANoe log | real | - | 00522: inconclusive, cause test_aborted |
| 13 | Configuration mismatch | Spec value invalid for BL5, precondition or version report vs. Test_Description | Test_Description, PDF | real | - | warnings: 02288 BTP[44] = 0x02 not a BL5 Grundstellbarkeit; versions 02283 (5 vs. 7), 02288 (5 vs. 4) |
| 14 | Command rejected | Meldung Kommando abgewiesen + reason + the command it answers; error if the test relied on the command | pcapng | synthetic | frame 135: rejection (technisch) 301 ms after the preparatory AZGH | 02283: fail, cause command_rejected |
| 14n | Command rejected in a negative test | Rejection of the trigger of a test that only forbids telegrams is an allowed answer (xlsx use case 4) | pcapng, Test_Description | synthetic | frame 326: rejection (betrieblich) 299 ms after the AZGH of the test step | 02284: pass, command_rejected warning |
| 15 | Source clock offset | Offset pcapng → CANoe time from identical frames, spread and drift | pcapng, BLF | real | - | frame_match, 2,159 frames, spread < 1 µs, no time_alignment finding |
| 15s | Source clock mismatch | Offset between pcapng and BLF changes during the run | pcapng, BLF | synthetic | timestamps from 139.5 s on shifted by +20 ms | run-level time_alignment warning "pcapng offset varies by 20.0 ms" |

All 21 checks (15 scenarios, some with a real and a synthetic variant) give the expected conclusion.

## 4. Not covered

- **Missing AZGH-Quittung (0x0009)**: no Test_Description step expects it, so there is no rule input. It
  needs a test case that lists it.
- **Spec response timeout in a main part**: the only test with an expected response (02288 step 2) never
  reached its main part. The rule (`SpecExpectationRule`) is unit-tested; scenario 1 uses the start-up response
  instead.
- **Edited BLF**: synthetic edits change the pcapng only; writing BLF files is not implemented.
