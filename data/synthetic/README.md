# Synthetic scenario captures

The `S*.pcapng` files here are edited copies of the RealOC capture `RealOCWorking_TDS_21026.pcapng`. Each one
adds the failure of one analysis scenario. They are generated, not committed, and confidential like the
original (they contain real element IDs).

```bash
.venv/bin/python -m trace_analyzer.synthetic          # regenerate all and check the analyzer's conclusions
.venv/bin/python analyze.py --pcapng data/synthetic/S07s_connection_interruption.pcapng --no-blf-ethernet
```

`--no-blf-ethernet` uses the BLF only for its CANoe objects (variables, panel, test structure). Without it, the
BLF's copy of the unedited frames would undo the edit. S06c and S15s are the exception: they compare the two
captures on purpose, so analyze them without the flag.

| File | Scenario | Edit | Expected analyzer conclusion |
|---|---|---|---|
| `S01_response_timeout` | 1 | start-up report (Aufrüstbeginn/status/Aufrüstende) 0.6 s later | 02283 fail, cause `timeout` |
| `S02_missing_message` | 2 | Meldung Aufrüstende removed | 02283 fail, cause `missing_message` |
| `S03s_unexpected_response` | 3 | status telegram 299 ms after the AZGH of 02284 | 02284 fail, cause `unexpected_response` |
| `S04_wrong_order` | 4 | Aufrüstanforderung before the BTP version check | 02283 fail, cause `wrong_order` |
| `S05_invalid_payload` | 5 | Belegungszustand 0x09 | 02283 fail, cause `invalid_payload` |
| `S06s_incorrect_length` | 6 | status telegram 46 instead of 47 bytes | 02283 fail, cause `incorrect_length` |
| `S06c_length_sender_receiver` | 6 | AZGH 42 bytes on the wire, 43 in the BLF | 02283 fail, cause `incorrect_length` (capture difference) |
| `S07s_connection_interruption` | 7 | 2 s without any RaSTA message | 02283 fail, cause `connection_interruption` |
| `S08_sequence_gap` | 8 | one RX heartbeat removed | 02283 fail, cause `sequence_error` |
| `S14_command_rejected` | 14 | preparatory AZGH rejected (technisch) | 02283 fail, cause `command_rejected` |
| `S14n_command_rejected_allowed` | 14 | AZGH of the negative test 02284 rejected | 02284 pass, `command_rejected` warning |
| `S15s_clock_step` | 15 | pcapng timestamps +20 ms from 139.5 s on | run-level `time_alignment` warning |

How the edits are made, their limits, and the real-data scenarios are covered in
[docs/scenarios.md](../../docs/scenarios.md).
