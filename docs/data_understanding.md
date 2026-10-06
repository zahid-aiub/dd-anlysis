# Phase 1: Data Understanding

SCI-TDS RealOC test run of 2026-10-02 (CANoe test configuration `TDS-Test`, test unit `SCI-TDS`).
All times below are **CANoe measurement time** in seconds (time base of BLF, CANoe log and PDF report) unless
marked as pcapng time. Frame numbers refer to the pcapng.

## 1. Sources

| File | Format | Content | Time base |
|---|---|---|---|
| `RealOCWorking_TDS_21026.pcapng` | PCAP-NG, 1 interface, VLAN-tagged Ethernet | 2,159 frames, 12:24:03.416 – 12:32:07.267. **Same frames as the BLF Ethernet objects**: all 2,150 UDP payloads match 1:1 with a constant +0.8 ms offset (stdev 0). | Absolute; pcapng relative time starts at first frame |
| `RealOCWorking_TDS_21026.blf` | Vector BLF (CANoe 20.0), zlib log containers | 2,159 Ethernet frames (obj 120), 8,915 CANoe distributed-object member events (obj 130), 13 test-structure events (obj 118), 4 app-text/metadata (obj 65), 3 Ethernet status (obj 103), 3 misc (obj 115, 135). Wireshark only shows the Ethernet frames and metadata. | Measurement start 12:23:59.953 |
| `Real_SCI-TDS_2026-10-02_12-24-11.pdf` | CANoe Test Report Viewer 20.0, 65 pages, text-based (German/English) | Verdicts, step logs, byte-level BTP validation tables | Measurement time |
| `TDS_Report_21026.txt` | CANoe Write window, tab-separated | 12 decoded GFM-A status reports, test stop message | Measurement time |
| `Test_Description/TC_*.txt` | TSV export (26 columns, quoted multi-line cells) | Spec for 02283, 02284, 02288, 00525. **No file for 00522.** | Relative (`t1`, `t-t1 < 500 ms`) |
| `SCI_TDS_Telegrams_3.4.6_to_3.4.16 1.xlsx` | Excel, 2 sheets | Telegram catalogue 3.4.6–3.4.16, 5 developer use cases | – |
| `Wireshark/LUA.zip` | Lua dissectors | RaSTA redundancy/safety layer, SCI common, SCI-TDS BL5/BL6/BL7 and other SCI protocols | – |

### BLF distributed-object events (obj 130)

Each event is logged twice, under `SCITDS::ElectronicInterlockings[0].BTPConnection.*` and the alias
`SCITDS::IL.BTPConnection.*`. Unique members (alias excluded):

| Count | Member | Meaning |
|---|---|---|
| 1090 / 1057 | `RedSendMonitor` / `RedReceiveMonitor.redundancyMessage` | RaSTA redundancy layer, sent / received |
| 1062 / 1035 | `SRSendMonitor` / `SRReceiveMonitor.heartbeatMessage` | RaSTA heartbeats |
| 18 / 17 | `SRSendMonitor` / `SRReceiveMonitor.dataMessage` | RaSTA data messages |
| 12 | `SCIDataReceiveMonitor.sciTelegram`, `GFMAs[0].meldungGFMABelegungszustand` | Received SCI-TDS telegrams / decoded GFM-A status |
| 6 | `GFMAs[0].kommandoAchszaehlgrundstellungHilfsbedienung` | AZGH sent |
| 2 | `GFMAs[0].kommandoAchzaehlgrundstellung` | AZG sent |
| 5 each | `connectionRequestMessage`, `connectionResponseMessage`, `disconnectionRequestMessage`, `OnRaSTAConnectionEstablished`, `OnBTPConnectionEstablished`, `OnRaSTAConnectionTerminated`, `OnBTPConnectionTerminated`, version check, Aufrüstung | Connection life cycle |
| 26 / 16 | `OnSCIStateTransition` / `OnRaSTAStateTransition` | Protocol state machines |
| 23, 12, 3, 2, 2, 2, 1 | `Panel::Panel_ZE.connectionState`, `.trackState`, `.panelTextOutput`, `.connectButton`, `.disconnectButton`, `.kdSelection`, `.lastCommandStatus` | **Operator panel**, records manual interventions |

Simple members (12-byte values such as `Panel_ZE.trackState`) end with a little-endian int32 holding the value
(for `trackState` it equals Belegungszustand). Structured members (telegram monitors) need their layout
reverse-engineered against the matching Ethernet frame.

## 2. Communication setup

| IP | ID in telegrams | Role |
|---|---|---|
| `1.208.188.16` | `DETHMM ZE 35##0001` | ESTW-ZE (interlocking central unit), simulated by CANoe |
| `10.129.15.2` | `DETHMM AZA34##0001` | Az-System, the real axle counter object controller (RealOC) |
| – | `34W1` | GFM-A (axle-counter track section) inside the Az-System |

Protocol stack: Ethernet (VLAN) → IPv4 → UDP 24001 → RaSTA redundancy layer → RaSTA safety & retransmission
layer → SCI/BTP (protocol type `0x20` = TDS) → SCI-TDS payload.

**SCI-TDS baseline is BL5.** With the BL5 dissector all telegrams decode without errors. BL6 and BL7 each
raise 12 Lua "Range is out of bounds" errors, because the RealOC status telegram is 47 bytes and BL6/BL7
expect 48 bytes. Multi-byte fields are little-endian.

## 3. Telegram catalogue: spec vs. observed

| Spec | Code | Telegram | Direction | BL5 length | Observed |
|---|---|---|---|---|---|
| 3.4.6 | `0x0001` | Kommando AZG (+ Grundstellungsart, here `0x02` AZEG) | ZE → AZ | 44 | 2 |
| 3.4.7 | `0x0002` | Kommando Achszählfüllstand-Aktualisierung | ZE → AZ | 43 | 0 |
| 3.4.8 | `0x0003` | Kommando AZGH | ZE → AZ | 43 | 6 |
| 3.4.9 | `0x000a` | Kommando ZDP-Aktivierung | ZE → AZ | – | 0 |
| 3.4.10 | `0x0006` | Meldung Kommando abgewiesen | AZ → ZE | – | 0 |
| 3.4.11 | `0x0007` | Meldung GFM-A Belegungszustand | AZ → ZE | 47 | 12 |
| 3.4.12 | `0x0009` | Meldung AZGH-Quittung | AZ → ZE | – | 0 |
| 3.4.13 | `0x000b` | Meldung ZDP-Befahrungszustand | AZ → ZE | – | 0 |
| 3.4.14–16 | `0x0010`–`0x0012` | AZVG/AZVGQ failed, additional info | AZ → ZE | not in BL5 | 0 |
| common | `0x0024` / `0x0025` | BTP version check command / report | ZE → AZ / AZ → ZE | | 5 / 5 |
| common | `0x0021` | Aufrüstanforderung (status request) | ZE → AZ | | 5 |
| common | `0x0022` / `0x0023` | Aufrüstbeginn / Aufrüstende | AZ → ZE | | 5 / 5 |

`0x0007` layout (BL5): `[0]` protocol type, `[1..2]` message type, `[3..22]` sender, `[23..42]` receiver,
`[43]` Belegungszustand (1 frei, 2 belegt, 3 gestört, 4/5 waiting states), `[44]` Grundstellungsfähigkeit
(0 not resettable, 1 resettable), `[45..46]` Achszählfüllstand.

RaSTA message types observed: connection request `0x1838` (5), connection response `0x1839` (5), disconnection
request `0x1848` (5, all reason 0 "User Request"), heartbeat `0x184c` (2,100), data `0x1860` (35).
No retransmission messages.

## 4. Time model

- Master timeline: CANoe measurement time `t` (BLF, CANoe log, PDF).
- `t = t_pcapng_relative + 3.4623 s`. The absolute clocks of pcapng and BLF agree within 0.8 ms with no drift;
  the 3.46 s only comes from the different zero points (measurement start vs. first captured frame).
- Check points: frame 207 (pcapng 72.293) = CANoe log 75.755; frame 423 (183.389) = 186.851; frame 1222
  (303.328) = PDF cleanup AZGH 306.789.
- The test system's (ZE, CANoe) RaSTA timestamp field holds measurement time in µs (e.g. disconnect at 8.510 s
  carries `8510059`); it is on average 0.8 ms ahead of the frame (send delay). The Az-System's RaSTA timestamps
  are its own millisecond counter and cannot be used for alignment.
- CANoe logs a command (PDF step "Sende …", BLF `kommando*` variable) up to ~3 ms before the frame appears on
  the wire, e.g. AZGH logged at 64.546 s, on the wire at 64.549 s.
- Measurement start in UTC (from the PCAPNG offset): 2026-10-02 10:23:59.954 Z = 12:23:59.954 at the test
  bench (UTC+02:00).

## 5. RaSTA sessions and test cases

| Session | RaSTA/BTP up → down | Test case | Test case window (BLF obj 118) | Verdict |
|---|---|---|---|---|
| 1 | 3.46 → 8.51 | none: manual connect/disconnect via Panel buttons before the fixture started | – | – |
| 2 | 52.40 → 91.35 | TC_NPRO.295.02283.01(O) | 12.402 – 91.548 | Pass |
| 3 | 131.55 → 139.32 | TC_NPRO.295.02284.01(F) | 91.548 – 139.515 | Pass |
| 4 | 179.51 → 313.29 | TC_NPRO.295.02288.01(O) | 139.515 – 313.489 | Fail |
| 5 | 353.49 → 487.30 | TC_NPRO.295.00525.01(F-ReZE) | 313.489 – 487.504 | Fail |
| – | none | TC_NPRO.295.00522.01(O-ReZE) | 487.504 – 488.322 | Inconclusive (test unit stopped during the 40 s wait) |

Every session follows the same pattern: RaSTA connect → BTP version check (~302 ms) → Aufrüstung (~302 ms,
reports the current GFM-A state) → test-specific commands/reports → RaSTA disconnect. Each test case waits
40 s before connecting.

Connection health in all sessions: 0 sequence-number gaps, no retransmissions, max interval between
consecutive RaSTA messages 0.306 s, every disconnect has reason "User Request".

## 6. Per-test-case timelines

GFM-A state notation: `Belegungszustand/Grundstellungsfähigkeit/Achszählfüllstand`.

**TC1 02283 (Pass)**: precondition "belegt und grundstellbar".

| t | Frame | Event |
|---|---|---|
| 53.133 | 56 | Aufrüstung: `1/0/0x0000` |
| 64.545 | 132 | `2/0/0x0001`: operator occupied the section with the metal object |
| 64.546 | 133 | Preparatory AZGH (not a test step) |
| 75.755 | 207 | `2/1/0x0001`: resettable, **11.21 s after the AZGH** |
| 77.546 | 219 | Step 1: AZGH |
| 78.047 | – | Step 2: no `0x0007` within 500 ms → Pass |
| 84.548 → 84.845 | 267 → 268 | Cleanup AZG (AZEG) → `1/0/0x0000` after 297 ms |

**TC2 02284 (Pass)**: precondition "frei und nicht grundstellbar".

| t | Frame | Event |
|---|---|---|
| 132.314 | 323 | Aufrüstung: `1/0/0x0000` |
| 132.315 | 324 | Step 1: AZGH |
| 132.815 | – | Step 2: no `0x0007` within 500 ms → Pass (no `0x0006` either) |

**TC3 02288 (Fail)**: see section 7.

**TC4 00525 (Fail)**: precondition "frei und nicht grundstellbar".

| t | Frame / source | Event |
|---|---|---|
| 354.303 | 1276 | Aufrüstung: `3/0/0x0000`, GFM-A still disturbed from TC3 |
| 354.303 | PDF | Operator asked to free the section with the metal object within 120 s, "Kein AZG/AZGH am Panel senden" |
| 381.611 | 1458, BLF `Panel_ZE.kdSelection=3` | **Manual AZGH from the panel**: no status change |
| 391.386 | 1523, BLF `Panel_ZE.kdSelection=1` | **Manual AZG from the panel**: no status change |
| 474.303 | PDF | 120 s preparation timeout `3/0` → Fail (BreakOnFail) |
| 480.804 → 487.304 | 2117, PDF | Cleanup AZGH: no change → cleanup Fail |

**TC5 00522 (Inconclusive)**: started 487.504, aborted 488.322 ("Test execution aborted due to stop of the
test unit"), measurement stopped 491.109. No connection was opened.

## 7. Manual root-cause analysis: TC_NPRO.295.02288.01 (ground truth)

Expected (Test_Description v4): precondition "GFM-A belegt und nicht grundstellbar" → Step 1 ZE sends AZGH →
Step 2 Az-System sends `0x0007` "belegt und grundstellbar" within 500 ms → Step 3 postcondition.

| t | Source | Event |
|---|---|---|
| 179.515 → 180.287 | PDF, pcapng 372–380 | RaSTA + BTP connection established |
| 180.287 | pcapng 380, BLF, log | Aufrüstung: `1/0/0x0000` (frei, nicht grundstellbar) |
| 180.287 | PDF | Operator: free the section, then occupy it with the metal object and keep it occupied (20 s stable) |
| 186.851 | pcapng 423, BLF, log | `2/0/0x0000`: occupied, but **Achszählfüllstand 0x0000** (TC1 occupied state had `0x0001`) |
| 186.953 | pcapng 425, BLF, log | `3/0/0x0000`: **GFM-A disturbed**, 102 ms later |
| 198.870 | pcapng 504 | `3/1/0x0000`: reset possible, window lasts 49.99 s |
| 248.862 | pcapng 837 | `3/0/0x0000`: window closed; no AZG/AZGH was sent while resettable |
| 300.288 | PDF | 120 s preparation timeout → Fail (BreakOnFail). Test steps 1–3 never executed |
| 306.789 | pcapng 1222, PDF | Cleanup AZGH while not resettable: no reaction |
| 313.289 | PDF | Cleanup Fail: "Technische/physische Ursache am Prüfstand beheben" |

Ruled out:
- Connection problems: no sequence gaps, no retransmissions, heartbeats ≤ 0.306 s, normal disconnects.
- Telegram format problems: every telegram decodes cleanly under BL5, lengths 43/44/47 as expected.
- Missing response: the state changes at 186.851 and 186.953 are not responses to a command (last command
  54.5 s earlier).

Conclusion:

```
Test Result:      FAILED (TC_NPRO.295.02288.01)
Detected failure: Precondition not reached. GFM-A 34W1 went to DISTURBED (Belegungszustand 3) at 186.953 s,
                  102 ms after an "occupied" report with Achszählfüllstand 0x0000, during manual occupation.
Category:         Field element / test bench state. Not a protocol or connection fault.
Consequence:      Cleanup failed, so TC_NPRO.295.00525.01 started with GFM-A disturbed (cascade failure).
Confidence:       High for the failure mechanism (pcapng, BLF, CANoe log and PDF agree). The physical reason
                  for the disturbance needs confirmation at the test bench.
```

## 8. Further findings

1. **Spec byte layout differs from the RealOC.** TC 02288 expects `BTP[44] = 0x02` (resettable),
   `BTP[45..46] = 0xFFFF`, `BTP[47] = 0xFF`, i.e. a 48-byte BL6/BL7 telegram. The RealOC sends BL5
   (47 bytes, resettable = `0x01`). The CANoe test script already uses BL5 coding ("Grundstellbarkeit=1").
2. **Timing risk for 02288.** In TC1 the same transition (`2/0` → AZGH → `2/1`) took 11.21 s. Step 2 of 02288
   requires < 500 ms, so 02288 may fail on timing even with a correct precondition.
3. **Behaviour differs from developer use case 4.** The xlsx says AZGH in state frei/not resettable returns
   `Meldung Kommando abgewiesen` (`0x0006`). In TC2 (same state) the RealOC sent nothing. 02284 only checks
   that no `0x0007` arrives, so it passes either way.
4. **Manual panel commands during TC4** despite the instruction not to use the panel. They had no effect
   (GFM-A not resettable), but the analysis tool has to flag manual interventions.
5. **Test case versions differ.** Test_Description versions: 02283 v7, 02284 v5, 02288 v4, 00525 v5. The PDF
   shows "Version: 5" for 02283/02284/02288 and no version for 00525.
6. **Achszählfüllstand `0x0000` is ambiguous.** The xlsx describes it as a signed fill level (entered − exited
   axles). The BL5 dissector and the CANoe log label `0x0000` as "invalid / disturbed or after restart". Free
   states also report `0x0000`.
7. **Harmless ICMP.** Three "port unreachable" messages from the ZE side right after disconnects (t ≈ 91.51,
   313.40, 487.31): the OC sent one more datagram after CANoe closed its socket. Not an error.

## 9. Open questions for the team

1. Target SCI-TDS baseline: the RealOC runs BL5, the test descriptions use the BL6/BL7 byte layout.
   *Decision (2026-10-06):* a test description that expects bytes beyond the telegram the device sends is a
   failure (`incorrect_length`, error): step 2 of 02288 could not pass with the RealOC's 47-byte status. Which
   baseline is the target is still open.
2. Physical cause of the disturbance at 186.953 s (handling of the metal object at the wheel sensor?).
3. Is 11.2 s from AZGH to "resettable" expected, given the 500 ms requirement in 02288?
4. AZGH in state frei/not resettable: `0x0006` (xlsx use case 4) or no telegram (02284)?
5. Meaning of Achszählfüllstand `0x0000`.
6. Test description for TC_NPRO.295.00522.01.
7. Which test case version is authoritative (description vs. implemented)?

## 10. Reproducing in Wireshark

Profile **SCI-TDS** (Edit → Configuration Profiles) sets baseline BL5, adds the columns RaSTA type, SCI msg,
Sender, Belegung, Grundst., Achszaehler, and the filter buttons:

| Button | Filter | Frames |
|---|---|---|
| SCI telegrams | `sci` | 35 |
| GFM-A status | `sci.messageType == 0x0007` | 12 |
| Commands | `sci.messageType in {0x0001, 0x0003}` | 8 |
| RaSTA connect/disconnect | `rasta.type in {0x1838, 0x1839, 0x1848}` | 15 |
| GFM-A disturbed | `scitds5.belegung == 3` | 4 |

To compare with the PDF or CANoe log, add 3.462 s to the pcapng relative time.
