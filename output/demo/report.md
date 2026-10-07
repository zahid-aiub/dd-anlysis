# Trace failure analysis

CANoe configuration `ZE_RealOC_Stimulation.cfg` · CANoe.CAN.Ethernet.BasicEthernet 20.0.195 /pro
Measurement start 2026-10-02 12:23:59 +0200 · report generated 2026-10-07 23:04

All times are CANoe measurement time in seconds; wall-clock times are test bench local time.

## Summary

| Test case | Report | Analyzer | Detected failure | Root cause | Confidence |
|---|---|---|---|---|---|
| [TC_NPRO.295.02283.01(O)](#tc_npro-295-02283-01) | pass | **pass** | - | - | - |
| [TC_NPRO.295.02284.01(F)](#tc_npro-295-02284-01) | pass | **pass** | - | - | - |
| [TC_NPRO.295.02288.01(O)](#tc_npro-295-02288-01) | fail | **fail** | Precondition not reached: target Belegung/Grundstellbarkeit 2/0 (Test_Description), actual 3/0 | 34W1 became disturbed (Belegungszustand 3) 102 ms after an occupied report with Achszählfüllstand 0x0000; reset possible for 50 s but no AZG/AZGH sent | high (0.95) |
| [TC_NPRO.295.00525.01(F-ReZE)](#tc_npro-295-00525-01) | fail | **fail** | Precondition not reached: target Belegung/Grundstellbarkeit 1/0 (Test_Description), actual 3/0 | Started in state 3/0 left by TC_NPRO.295.02288.01(O) (its cleanup failed) | high (0.90) |
| [TC_NPRO.295.00522.01(O-ReZE)](#tc_npro-295-00522-01) | inconclusive | **inconclusive** | Test execution stopped: test unit stopped by the user | Test execution stopped: test unit stopped by the user | high (1.00) |


<a id="tc_npro-295-02283-01"></a>

## TC_NPRO.295.02283.01(O)

```
Test Result:       PASSED (TC_NPRO.295.02283.01)
Detected failure:  none
```

Test window 12.402 s – 91.548 s · target GFM-A state 2/1 (Belegung/Grundstellbarkeit) · Test_Description precondition: OC: REGELBETRIEB; BP: GFM-A ist im Zustand "GFM-A belegt und grundstellbar"

![Timeline of TC_NPRO.295.02283.01(O)](timeline_tc_npro-295-02283-01.svg)
![Legend](timeline_legend.svg)



**Further findings**

| Severity | Time | Category | Finding | Evidence |
|---|---|---|---|---|
| warning | – | configuration_mismatch | Test case version 5 in the report, 7 in the Test_Description | PDF report: Real_SCI-TDS_2026-10-02_12-24-11.pdf page 2; Test_Description: TC_NPRO.295.02283.01_xcel.txt row 1 |


**Checked and ruled out:** missing_message, wrong_order, invalid_payload, incorrect_length, timeout, connection_interruption, unexpected_response, sequence_error, command_rejected, device_disturbed

<details><summary>Events in the test window (47)</summary>

| Time | Clock | Event | Evidence |
|---|---|---|---|
| 52.402 s | 12:24:52.355 | Preparation 1: Waited for 40000.000 ms | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 3 |
| 52.402 s | 12:24:52.355 | Preparation Init: RaSTA und BTP Verbindung wird aufgebaut | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 3 |
| 52.404 s | 12:24:52.357 | RaSTA connection request (TX) | RealOCWorking_TDS_21026.pcapng frame 48 |
| 52.527 s | 12:24:52.480 | RaSTA connection response (RX) | RealOCWorking_TDS_21026.pcapng frame 49 |
| 52.530 s | 12:24:52.483 | ZE → AZ KOMMANDO_BTP_VERSIONSABGLEICH (44 bytes) btp_version=1 | RealOCWorking_TDS_21026.pcapng frame 51 telegram 1 |
| 52.831 s | 12:24:52.784 | AZ → ZE MELDUNG_BTP_VERSIONSABGLEICH (62 bytes) ergebnis=2, btp_version=1, checksum_length=16 | RealOCWorking_TDS_21026.pcapng frame 53 telegram 1 |
| 52.832 s | 12:24:52.785 | ZE → AZ KOMMANDO_AUFRUESTANFORDERUNG (43 bytes) | RealOCWorking_TDS_21026.pcapng frame 54 telegram 1 |
| 53.133 s | 12:24:53.086 | AZ → ZE MELDUNG_AUFRUESTBEGINN (43 bytes) | RealOCWorking_TDS_21026.pcapng frame 56 telegram 1 |
| 53.133 s | 12:24:53.086 | AZ → ZE MELDUNG_GFMA_BELEGUNGSZUSTAND (47 bytes) 1/0/0x0000 (Belegung/Grundstellbarkeit/Achszählfüllstand) | RealOCWorking_TDS_21026.pcapng frame 56 telegram 2 |
| 53.133 s | 12:24:53.086 | AZ → ZE MELDUNG_AUFRUESTENDE (43 bytes) | RealOCWorking_TDS_21026.pcapng frame 56 telegram 3 |
| 53.133 s | 12:24:53.086 | [pass] Preparation Init: BTP-Verbindung wurde erfolgreich aufgebaut | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 3 |
| 53.133 s | 12:24:53.086 | Preparation Init: Manuelle Vorbereitung: Raeder ein=0, aus=0 (Bedienvorgabe; keine simulierten Zaehler schreiben). | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 3 |
| 53.133 s | 12:24:53.086 | Preparation Init: Sollzustand: Belegungszustand=2, Grundstellbarkeit=1. | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 3 |
| 53.133 s | 12:24:53.086 | Preparation Init: GFM-A innerhalb von 120000 ms manuell belegen. Kein AZG/AZGH am Panel senden. | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 3 |
| 64.545 s | 12:25:04.498 | AZ → ZE MELDUNG_GFMA_BELEGUNGSZUSTAND (47 bytes) 2/0/0x0001 (Belegung/Grundstellbarkeit/Achszählfüllstand) | RealOCWorking_TDS_21026.pcapng frame 132 telegram 1 |
| 64.545 s | 12:25:04.498 | Preparation Init: Vorbereitende AZGH: Grundstellungsfaehigkeit herstellen (kein Pruefschritt). | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 3 |
| 64.545 s | 12:25:04.498 | Preparation Init: Sende 'Kommando AchszaehlgrundstellungHilfsbedienung' | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 3 |
| 64.546 s | 12:25:04.499 | [pass] Preparation Init: Validiere BTP-Nachricht | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 3 |
| 64.549 s | 12:25:04.502 | ZE → AZ KOMMANDO_AZGH (43 bytes) | RealOCWorking_TDS_21026.pcapng frame 133 telegram 1 |
| 75.755 s | 12:25:15.709 | AZ → ZE MELDUNG_GFMA_BELEGUNGSZUSTAND (47 bytes) 2/1/0x0001 (Belegung/Grundstellbarkeit/Achszählfüllstand) | RealOCWorking_TDS_21026.pcapng frame 207 telegram 1 |
| 77.546 s | 12:25:17.499 | [pass] Preparation Init: Vorbereitung abgeschlossen: Belegungszustand=2, Grundstellungsfaehigkeit=1. | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 5 |
| 77.546 s | 12:25:17.499 | Preparation Init: Pruefe Vorbedingung: Verbindungsstatus und GFM-A-Zustand | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 5 |
| 77.546 s | 12:25:17.499 | [pass] Preparation Init: BTP-Verbinding ist offen | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 5 |
| 77.546 s | 12:25:17.499 | [pass] Preparation Init: GFMA hat erwarteten Belegungszustand 2 | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 5 |
| 77.546 s | 12:25:17.499 | [pass] Preparation Init: GFMA hat erwartete Grundstellungsfaehigkeit 1 | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 5 |
| 77.546 s | 12:25:17.499 | Main Part 1: Sende 'Kommando AchszaehlgrundstellungHilfsbedienung' | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 5 |
| 77.547 s | 12:25:17.500 | [pass] Main Part 1: Validiere BTP-Nachricht | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 5 |
| 77.548 s | 12:25:17.502 | ZE → AZ KOMMANDO_AZGH (43 bytes) | RealOCWorking_TDS_21026.pcapng frame 219 telegram 1 |
| 78.047 s | 12:25:18.000 | Main Part 2: AZG/AZGH-Empfang im Prueffenster (500 ms): SCI-Monitor=0, dekodierte GFM-A-Meldungen=0. | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 6 |
| 78.047 s | 12:25:18.000 | [pass] Main Part 2: AZG/AZGH-Antwort geprueft: 0 erwartete Belegungsmeldungen innerhalb von 500 ms. | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 6 |
| 78.047 s | 12:25:18.000 | Main Part 3: Pruefe Nachbedingung: Verbindungsstatus und GFM-A-Zustand | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 6 |
| 78.047 s | 12:25:18.000 | [pass] Main Part 3: BTP-Verbinding ist offen | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 6 |
| 78.047 s | 12:25:18.000 | [pass] Main Part 3: GFMA hat erwarteten Belegungszustand 2 | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 6 |
| 78.047 s | 12:25:18.000 | [pass] Main Part 3: GFMA hat erwartete Grundstellungsfaehigkeit 1 | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 6 |
| 78.047 s | 12:25:18.000 | Completion Warten: Hintergrundueberpruefung bis alle Timer abgelaufen sind | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 6 |
| 84.547 s | 12:25:24.500 | Completion: Waited for 6500 ms. | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 6 |
| 84.547 s | 12:25:24.500 | [pass] Completion Warten: Hintergrundueberpruefung ohne Vorfall abgeschlossen | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 6 |
| 84.547 s | 12:25:24.500 | Completion Cleanup: Nachbereitung ausserhalb der Testschritte; bestehendes Testurteil bleibt erhalten. | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 7 |
| 84.547 s | 12:25:24.500 | Completion Cleanup: Cleanup GFM-A 0: Zustand=2, Grundstellbarkeit=1; Ziel frei/nicht grundstellbar. | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 7 |
| 84.547 s | 12:25:24.500 | Completion Cleanup: Cleanup: einmal AZG mit Grundstellungsart AZEG (0x02) senden. | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 7 |
| 84.548 s | 12:25:24.501 | Completion Cleanup: Sende 'Kommando AchzaehlGrundstellung' mit Grundstellungsart 0x02 | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 7 |
| 84.548 s | 12:25:24.501 | [pass] Completion Cleanup: Validiere BTP-Nachricht | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 7 |
| 84.549 s | 12:25:24.503 | ZE → AZ KOMMANDO_AZG (44 bytes) grundstellungsart=2 | RealOCWorking_TDS_21026.pcapng frame 267 telegram 1 |
| 84.845 s | 12:25:24.798 | AZ → ZE MELDUNG_GFMA_BELEGUNGSZUSTAND (47 bytes) 1/0/0x0000 (Belegung/Grundstellbarkeit/Achszählfüllstand) | RealOCWorking_TDS_21026.pcapng frame 268 telegram 1 |
| 91.348 s | 12:25:31.301 | [pass] Completion Cleanup: Cleanup abgeschlossen: GFM-A 0 frei und nicht grundstellbar. | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 8 |
| 91.348 s | 12:25:31.301 | Completion Reset: RaSTA- und BTP-Verbindung werden abgebaut | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 8 |
| 91.350 s | 12:25:31.303 | RaSTA disconnection request (TX), reason 0 | RealOCWorking_TDS_21026.pcapng frame 312 |

</details>

<a id="tc_npro-295-02284-01"></a>

## TC_NPRO.295.02284.01(F)

```
Test Result:       PASSED (TC_NPRO.295.02284.01)
Detected failure:  none
```

Test window 91.548 s – 139.515 s · target GFM-A state 1/0 (Belegung/Grundstellbarkeit) · Test_Description precondition: OC: Normal operation; BP: GFM-A is in the state "GFM-A free and not primeable"

![Timeline of TC_NPRO.295.02284.01(F)](timeline_tc_npro-295-02284-01.svg)
![Legend](timeline_legend.svg)



**Checked and ruled out:** missing_message, wrong_order, invalid_payload, incorrect_length, timeout, connection_interruption, unexpected_response, configuration_mismatch, sequence_error, command_rejected, device_disturbed, cascade_failure

<details><summary>Events in the test window (36)</summary>

| Time | Clock | Event | Evidence |
|---|---|---|---|
| 131.548 s | 12:26:11.501 | Preparation 1: Waited for 40000.000 ms | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 8 |
| 131.548 s | 12:26:11.501 | Preparation Init: RaSTA und BTP Verbindung wird aufgebaut | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 8 |
| 131.549 s | 12:26:11.503 | RaSTA connection request (TX) | RealOCWorking_TDS_21026.pcapng frame 315 |
| 131.707 s | 12:26:11.661 | RaSTA connection response (RX) | RealOCWorking_TDS_21026.pcapng frame 316 |
| 131.709 s | 12:26:11.663 | ZE → AZ KOMMANDO_BTP_VERSIONSABGLEICH (44 bytes) btp_version=1 | RealOCWorking_TDS_21026.pcapng frame 318 telegram 1 |
| 132.011 s | 12:26:11.965 | AZ → ZE MELDUNG_BTP_VERSIONSABGLEICH (62 bytes) ergebnis=2, btp_version=1, checksum_length=16 | RealOCWorking_TDS_21026.pcapng frame 320 telegram 1 |
| 132.012 s | 12:26:11.965 | ZE → AZ KOMMANDO_AUFRUESTANFORDERUNG (43 bytes) | RealOCWorking_TDS_21026.pcapng frame 321 telegram 1 |
| 132.314 s | 12:26:12.267 | AZ → ZE MELDUNG_AUFRUESTBEGINN (43 bytes) | RealOCWorking_TDS_21026.pcapng frame 323 telegram 1 |
| 132.314 s | 12:26:12.267 | AZ → ZE MELDUNG_GFMA_BELEGUNGSZUSTAND (47 bytes) 1/0/0x0000 (Belegung/Grundstellbarkeit/Achszählfüllstand) | RealOCWorking_TDS_21026.pcapng frame 323 telegram 2 |
| 132.314 s | 12:26:12.267 | AZ → ZE MELDUNG_AUFRUESTENDE (43 bytes) | RealOCWorking_TDS_21026.pcapng frame 323 telegram 3 |
| 132.314 s | 12:26:12.267 | [pass] Preparation Init: BTP-Verbindung wurde erfolgreich aufgebaut | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 9 |
| 132.314 s | 12:26:12.267 | Preparation Init: Manuelle Vorbereitung: Raeder ein=0, aus=0 (Bedienvorgabe; keine simulierten Zaehler schreiben). | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 9 |
| 132.314 s | 12:26:12.267 | Preparation Init: Sollzustand: Belegungszustand=1, Grundstellbarkeit=0. | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 9 |
| 132.314 s | 12:26:12.267 | Preparation Init: GFM-A innerhalb von 120000 ms mit dem Metallobjekt manuell freifahren. Beim geforderten Sollzustand geht der Test automatisch weiter. Kein AZG/AZGH am Panel senden. | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 9 |
| 132.314 s | 12:26:12.267 | [pass] Preparation Init: Vorbereitung abgeschlossen: Belegungszustand=1, Grundstellungsfaehigkeit=0. | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 9 |
| 132.314 s | 12:26:12.267 | Preparation Init: Pruefe Vorbedingung: Verbindungsstatus und GFM-A-Zustand | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 9 |
| 132.314 s | 12:26:12.267 | [pass] Preparation Init: BTP-Verbinding ist offen | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 9 |
| 132.314 s | 12:26:12.267 | [pass] Preparation Init: GFMA hat erwarteten Belegungszustand 1 | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 9 |
| 132.314 s | 12:26:12.267 | [pass] Preparation Init: GFMA hat erwartete Grundstellungsfaehigkeit 0 | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 9 |
| 132.314 s | 12:26:12.267 | Main Part 1: Sende 'Kommando AchszaehlgrundstellungHilfsbedienung' | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 9 |
| 132.315 s | 12:26:12.268 | [pass] Main Part 1: Validiere BTP-Nachricht | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 9 |
| 132.317 s | 12:26:12.271 | ZE → AZ KOMMANDO_AZGH (43 bytes) | RealOCWorking_TDS_21026.pcapng frame 324 telegram 1 |
| 132.815 s | 12:26:12.768 | Main Part 2: AZG/AZGH-Empfang im Prueffenster (500 ms): SCI-Monitor=0, dekodierte GFM-A-Meldungen=0. | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 10 |
| 132.815 s | 12:26:12.768 | [pass] Main Part 2: AZG/AZGH-Antwort geprueft: 0 erwartete Belegungsmeldungen innerhalb von 500 ms. | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 10 |
| 132.815 s | 12:26:12.768 | Main Part 3: Pruefe Nachbedingung: Verbindungsstatus und GFM-A-Zustand | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 10 |
| 132.815 s | 12:26:12.768 | [pass] Main Part 3: BTP-Verbinding ist offen | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 10 |
| 132.815 s | 12:26:12.768 | [pass] Main Part 3: GFMA hat erwarteten Belegungszustand 1 | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 10 |
| 132.815 s | 12:26:12.768 | [pass] Main Part 3: GFMA hat erwartete Grundstellungsfaehigkeit 0 | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 10 |
| 132.815 s | 12:26:12.768 | Completion Warten: Hintergrundueberpruefung bis alle Timer abgelaufen sind | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 11 |
| 139.315 s | 12:26:19.268 | Completion: Waited for 6500 ms. | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 11 |
| 139.315 s | 12:26:19.268 | [pass] Completion Warten: Hintergrundueberpruefung ohne Vorfall abgeschlossen | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 11 |
| 139.315 s | 12:26:19.268 | Completion Cleanup: Nachbereitung ausserhalb der Testschritte; bestehendes Testurteil bleibt erhalten. | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 11 |
| 139.315 s | 12:26:19.268 | Completion Cleanup: Cleanup GFM-A 0: Zustand=1, Grundstellbarkeit=0; Ziel frei/nicht grundstellbar. | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 11 |
| 139.315 s | 12:26:19.268 | [pass] Completion Cleanup: Cleanup abgeschlossen: GFM-A 0 frei und nicht grundstellbar. | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 11 |
| 139.315 s | 12:26:19.268 | Completion Reset: RaSTA- und BTP-Verbindung werden abgebaut | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 11 |
| 139.317 s | 12:26:19.270 | RaSTA disconnection request (TX), reason 0 | RealOCWorking_TDS_21026.pcapng frame 371 |

</details>

<a id="tc_npro-295-02288-01"></a>

## TC_NPRO.295.02288.01(O)

```
Test Result:       FAILED (TC_NPRO.295.02288.01)
Detected failure:  300.288 s  Precondition not reached: target Belegung/Grundstellbarkeit 2/0 (Test_Description), actual 3/0
Root cause:        186.953 s  34W1 became disturbed (Belegungszustand 3) 102 ms after an occupied report with Achszählfüllstand 0x0000; reset possible for 50 s but no AZG/AZGH sent
Category:          Field element / test bench state (device_disturbed)
Consequence:       Cleanup failed, so TC_NPRO.295.00525.01(F-ReZE) started in the state this test case left (cascade failure).
Confidence:        high (0.95); evidence from BLF, CANoe log, pcapng
```

Test window 139.515 s – 313.489 s · target GFM-A state 2/0 (Belegung/Grundstellbarkeit) · Test_Description precondition: OC: Normal operation; BP: GFM-A is in the state "GFM-A occupied and cannot be primed"

![Timeline of TC_NPRO.295.02288.01(O)](timeline_tc_npro-295-02288-01.svg)
![Legend](timeline_legend.svg)


**Evidence for the cause** (device_disturbed)

- pcapng: RealOCWorking_TDS_21026.pcapng frame 423 telegram 1 at 186.851 s (12:27:06.804)
- pcapng: RealOCWorking_TDS_21026.pcapng frame 425 telegram 1 at 186.953 s (12:27:06.906)


**Evidence for the symptom** (precondition_not_reached)

- PDF report: Real_SCI-TDS_2026-10-02_12-24-11.pdf page 56 at 300.288 s (12:29:00.241)
- pcapng: RealOCWorking_TDS_21026.pcapng frame 837 telegram 1 at 248.862 s (12:28:08.815)



**Further findings**

| Severity | Time | Category | Finding | Evidence |
|---|---|---|---|---|
| error | 180.287 s | incorrect_length | Test_Description step 2 expects a 48-byte MELDUNG_GFMA_BELEGUNGSZUSTAND, the device sends 47 bytes: the step cannot pass | Test_Description: TC_NPRO.295.02288.01_xcel.txt row 1 at 180.287 s (12:27:00.241); pcapng: RealOCWorking_TDS_21026.pcapng frame 380 telegram 2 at 180.287 s (12:27:00.241) |
| warning | – | configuration_mismatch | Test_Description step 2 does not match SCI-TDS BL5: BTP[44] = 0x02 is not a valid BL5 grundstellbar | Test_Description: TC_NPRO.295.02288.01_xcel.txt row 1 |
| warning | – | configuration_mismatch | Test case version 5 in the report, 4 in the Test_Description | PDF report: Real_SCI-TDS_2026-10-02_12-24-11.pdf page 11; Test_Description: TC_NPRO.295.02288.01_xcel.txt row 1 |


**Checked and ruled out:** missing_message, wrong_order, invalid_payload, timeout, connection_interruption, sequence_error, command_rejected, cascade_failure

<details><summary>Events in the test window (37)</summary>

| Time | Clock | Event | Evidence |
|---|---|---|---|
| 179.515 s | 12:26:59.468 | Preparation 1: Waited for 40000.000 ms | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 11 |
| 179.515 s | 12:26:59.468 | Preparation Init: RaSTA und BTP Verbindung wird aufgebaut | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 11 |
| 179.517 s | 12:26:59.470 | RaSTA connection request (TX) | RealOCWorking_TDS_21026.pcapng frame 372 |
| 179.680 s | 12:26:59.633 | RaSTA connection response (RX) | RealOCWorking_TDS_21026.pcapng frame 373 |
| 179.681 s | 12:26:59.634 | ZE → AZ KOMMANDO_BTP_VERSIONSABGLEICH (44 bytes) btp_version=1 | RealOCWorking_TDS_21026.pcapng frame 375 telegram 1 |
| 179.984 s | 12:26:59.937 | AZ → ZE MELDUNG_BTP_VERSIONSABGLEICH (62 bytes) ergebnis=2, btp_version=1, checksum_length=16 | RealOCWorking_TDS_21026.pcapng frame 377 telegram 1 |
| 179.985 s | 12:26:59.938 | ZE → AZ KOMMANDO_AUFRUESTANFORDERUNG (43 bytes) | RealOCWorking_TDS_21026.pcapng frame 378 telegram 1 |
| 180.287 s | 12:27:00.241 | AZ → ZE MELDUNG_AUFRUESTBEGINN (43 bytes) | RealOCWorking_TDS_21026.pcapng frame 380 telegram 1 |
| 180.287 s | 12:27:00.241 | AZ → ZE MELDUNG_GFMA_BELEGUNGSZUSTAND (47 bytes) 1/0/0x0000 (Belegung/Grundstellbarkeit/Achszählfüllstand) | RealOCWorking_TDS_21026.pcapng frame 380 telegram 2 |
| 180.287 s | 12:27:00.241 | AZ → ZE MELDUNG_AUFRUESTENDE (43 bytes) | RealOCWorking_TDS_21026.pcapng frame 380 telegram 3 |
| 180.287 s | 12:27:00.241 | [pass] Preparation Init: BTP-Verbindung wurde erfolgreich aufgebaut | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 11 |
| 180.287 s | 12:27:00.241 | Preparation Init: Manuelle Vorbereitung: Raeder ein=0, aus=0 (Bedienvorgabe; keine simulierten Zaehler schreiben). | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 11 |
| 180.287 s | 12:27:00.241 | Preparation Init: Sollzustand: Belegungszustand=2, Grundstellbarkeit=0. | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 11 |
| 180.287 s | 12:27:00.241 | Preparation Init: GFM-A innerhalb von 120000 ms manuell belegen. Kein AZG/AZGH am Panel senden. | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 11 |
| 180.287 s | 12:27:00.241 | Preparation Init: GFM-A zuerst vollstaendig freifahren (frei, nicht grundstellbar), danach belegen und belegt lassen. Automatische Fortsetzung nach 20000 ms stabilem Sollzustand; keine Bestaetigung erforderlich. | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 11 |
| 180.287 s | 12:27:00.241 | Preparation Init: Freizustand erkannt. Jetzt GFM-A belegen, Bewegung abschliessen und belegt lassen. | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 11 |
| 186.851 s | 12:27:06.804 | AZ → ZE MELDUNG_GFMA_BELEGUNGSZUSTAND (47 bytes) 2/0/0x0000 (Belegung/Grundstellbarkeit/Achszählfüllstand) | RealOCWorking_TDS_21026.pcapng frame 423 telegram 1 |
| 186.953 s | 12:27:06.906 | AZ → ZE MELDUNG_GFMA_BELEGUNGSZUSTAND (47 bytes) 3/0/0x0000 (Belegung/Grundstellbarkeit/Achszählfüllstand) | RealOCWorking_TDS_21026.pcapng frame 425 telegram 1 |
| 198.870 s | 12:27:18.823 | AZ → ZE MELDUNG_GFMA_BELEGUNGSZUSTAND (47 bytes) 3/1/0x0000 (Belegung/Grundstellbarkeit/Achszählfüllstand) | RealOCWorking_TDS_21026.pcapng frame 504 telegram 1 |
| 248.862 s | 12:28:08.815 | AZ → ZE MELDUNG_GFMA_BELEGUNGSZUSTAND (47 bytes) 3/0/0x0000 (Belegung/Grundstellbarkeit/Achszählfüllstand) | RealOCWorking_TDS_21026.pcapng frame 837 telegram 1 |
| 300.288 s | 12:29:00.241 | [fail] Preparation Init: Vorbereitung frei -> belegt nicht abgeschlossen: stabilen Sollzustand und BTP-Verbindung innerhalb von 120000 ms erforderlich. | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 56 |
| 300.288 s | 12:29:00.241 | Preparation: Test aborted due to BreakOnFail behavior. | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 56 |
| 300.288 s | 12:29:00.241 | Completion Warten: Hintergrundueberpruefung bis alle Timer abgelaufen sind | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 56 |
| 306.788 s | 12:29:06.741 | Completion: Waited for 6500 ms. | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 56 |
| 306.788 s | 12:29:06.741 | [pass] Completion Warten: Hintergrundueberpruefung ohne Vorfall abgeschlossen | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 56 |
| 306.788 s | 12:29:06.741 | Completion Cleanup: Nachbereitung ausserhalb der Testschritte; bestehendes Testurteil bleibt erhalten. | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 56 |
| 306.788 s | 12:29:06.741 | Completion Cleanup: Cleanup GFM-A 0: Zustand=3, Grundstellbarkeit=0; Ziel frei/nicht grundstellbar. | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 56 |
| 306.788 s | 12:29:06.741 | Completion Cleanup: Cleanup: einmal AZGH senden und Grundstellbarkeit abwarten. | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 56 |
| 306.788 s | 12:29:06.741 | Completion Cleanup: Sende 'Kommando AchszaehlgrundstellungHilfsbedienung' | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 56 |
| 306.789 s | 12:29:06.742 | [pass] Completion Cleanup: Validiere BTP-Nachricht | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 56 |
| 306.790 s | 12:29:06.743 | ZE → AZ KOMMANDO_AZGH (43 bytes) | RealOCWorking_TDS_21026.pcapng frame 1222 telegram 1 |
| 313.289 s | 12:29:13.242 | [fail] Completion Cleanup: Cleanup-Ziel nach 6500 ms nicht erreicht (frei erforderlich=0): Zustand=3, Grundstellbarkeit=0. Technische/ physische Ursache am Pruefstand beheben. | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 58 |
| 313.289 s | 12:29:13.242 | [fail] Completion Cleanup: Cleanup fehlgeschlagen; definierter Ausgangszustand fuer den naechsten Test nicht garantiert. | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 58 |
| 313.289 s | 12:29:13.242 | Completion Cleanup: RaSTA- und BTP-Verbindung werden abgebaut | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 58 |
| 313.290 s | 12:29:13.243 | RaSTA disconnection request (TX), reason 0 | RealOCWorking_TDS_21026.pcapng frame 1265 |
| 313.489 s | 12:29:13.442 | Completion Reset: RaSTA- und BTP-Verbindung werden abgebaut | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 58 |
| 313.489 s | 12:29:13.442 | [pass] Completion Reset: RaSTA- und BTP-Verbindung sind bereits abgebaut | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 58 |

</details>

<a id="tc_npro-295-00525-01"></a>

## TC_NPRO.295.00525.01(F-ReZE)

```
Test Result:       FAILED (TC_NPRO.295.00525.01)
Detected failure:  474.303 s  Precondition not reached: target Belegung/Grundstellbarkeit 1/0 (Test_Description), actual 3/0
Root cause:        313.489 s  Started in state 3/0 left by TC_NPRO.295.02288.01(O) (its cleanup failed)
Category:          Test sequence: state left by the previous test case (cascade_failure)
Consequence:       Cleanup failed, so TC_NPRO.295.00522.01(O-ReZE) started in the state this test case left (cascade failure).
Confidence:        high (0.90); evidence from PDF report, pcapng
```

Test window 313.489 s – 487.504 s · target GFM-A state 1/0 (Belegung/Grundstellbarkeit) · Test_Description precondition: OC: Normal operation; BP: GFM-A is in the state "GFM-A free and not primeable"

![Timeline of TC_NPRO.295.00525.01(F-ReZE)](timeline_tc_npro-295-00525-01.svg)
![Legend](timeline_legend.svg)


**Evidence for the cause** (cascade_failure)

- pcapng: RealOCWorking_TDS_21026.pcapng frame 1276 telegram 2 at 354.303 s (12:29:54.256)
- PDF report: Real_SCI-TDS_2026-10-02_12-24-11.pdf page 58 at 313.489 s (12:29:13.442)


**Evidence for the symptom** (precondition_not_reached)

- PDF report: Real_SCI-TDS_2026-10-02_12-24-11.pdf page 63 at 474.303 s (12:31:54.256)
- pcapng: RealOCWorking_TDS_21026.pcapng frame 1276 telegram 2 at 354.303 s (12:29:54.256)



**Further findings**

| Severity | Time | Category | Finding | Evidence |
|---|---|---|---|---|
| error | 354.303 s | device_disturbed | 34W1 still disturbed (Belegungszustand 3) at 354.303 s, inherited from earlier | pcapng: RealOCWorking_TDS_21026.pcapng frame 1276 telegram 2 at 354.303 s (12:29:54.256) |
| warning | 381.611 s | manual_intervention | Manual KOMMANDO_AZGH from the CANoe panel although the test instruction says not to use the panel; no GFM-A status change followed | BLF: RealOCWorking_TDS_21026.blf object 7550 at 381.611 s (12:30:21.565); pcapng: RealOCWorking_TDS_21026.pcapng frame 1458 telegram 1 at 381.613 s (12:30:21.566) |
| warning | 391.386 s | manual_intervention | Manual KOMMANDO_AZG from the CANoe panel although the test instruction says not to use the panel; no GFM-A status change followed | BLF: RealOCWorking_TDS_21026.blf object 7879 at 391.386 s (12:30:31.339); pcapng: RealOCWorking_TDS_21026.pcapng frame 1523 telegram 1 at 391.388 s (12:30:31.341) |


**Checked and ruled out:** missing_message, wrong_order, invalid_payload, incorrect_length, timeout, connection_interruption, configuration_mismatch, sequence_error, command_rejected

<details><summary>Events in the test window (35)</summary>

| Time | Clock | Event | Evidence |
|---|---|---|---|
| 353.489 s | 12:29:53.442 | Preparation 1: Waited for 40000.000 ms | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 58 |
| 353.489 s | 12:29:53.442 | Preparation Init: RaSTA und BTP Verbindung wird aufgebaut | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 58 |
| 353.491 s | 12:29:53.444 | RaSTA connection request (TX) | RealOCWorking_TDS_21026.pcapng frame 1268 |
| 353.696 s | 12:29:53.649 | RaSTA connection response (RX) | RealOCWorking_TDS_21026.pcapng frame 1269 |
| 353.697 s | 12:29:53.650 | ZE → AZ KOMMANDO_BTP_VERSIONSABGLEICH (44 bytes) btp_version=1 | RealOCWorking_TDS_21026.pcapng frame 1271 telegram 1 |
| 353.999 s | 12:29:53.953 | AZ → ZE MELDUNG_BTP_VERSIONSABGLEICH (62 bytes) ergebnis=2, btp_version=1, checksum_length=16 | RealOCWorking_TDS_21026.pcapng frame 1273 telegram 1 |
| 354.000 s | 12:29:53.954 | ZE → AZ KOMMANDO_AUFRUESTANFORDERUNG (43 bytes) | RealOCWorking_TDS_21026.pcapng frame 1274 telegram 1 |
| 354.303 s | 12:29:54.256 | AZ → ZE MELDUNG_AUFRUESTBEGINN (43 bytes) | RealOCWorking_TDS_21026.pcapng frame 1276 telegram 1 |
| 354.303 s | 12:29:54.256 | AZ → ZE MELDUNG_GFMA_BELEGUNGSZUSTAND (47 bytes) 3/0/0x0000 (Belegung/Grundstellbarkeit/Achszählfüllstand) | RealOCWorking_TDS_21026.pcapng frame 1276 telegram 2 |
| 354.303 s | 12:29:54.256 | AZ → ZE MELDUNG_AUFRUESTENDE (43 bytes) | RealOCWorking_TDS_21026.pcapng frame 1276 telegram 3 |
| 354.303 s | 12:29:54.256 | [pass] Preparation Init: BTP-Verbindung wurde erfolgreich aufgebaut | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 58 |
| 354.303 s | 12:29:54.256 | Preparation Init: Manuelle Vorbereitung: Raeder ein=0, aus=0 (Bedienvorgabe; keine simulierten Zaehler schreiben). | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 58 |
| 354.303 s | 12:29:54.256 | Preparation Init: Sollzustand: Belegungszustand=1, Grundstellbarkeit=0. | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 58 |
| 354.303 s | 12:29:54.256 | Preparation Init: GFM-A innerhalb von 120000 ms mit dem Metallobjekt manuell freifahren. Beim geforderten Sollzustand geht der Test automatisch weiter. Kein AZG/AZGH am Panel senden. | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 58 |
| 381.611 s | 12:30:21.565 | Manual action on the CANoe panel: KOMMANDO_AZGH | RealOCWorking_TDS_21026.blf object 7550 |
| 381.613 s | 12:30:21.566 | ZE → AZ KOMMANDO_AZGH (43 bytes) | RealOCWorking_TDS_21026.pcapng frame 1458 telegram 1 |
| 391.386 s | 12:30:31.339 | Manual action on the CANoe panel: KOMMANDO_AZG | RealOCWorking_TDS_21026.blf object 7879 |
| 391.388 s | 12:30:31.341 | ZE → AZ KOMMANDO_AZG (44 bytes) grundstellungsart=2 | RealOCWorking_TDS_21026.pcapng frame 1523 telegram 1 |
| 474.303 s | 12:31:54.256 | [fail] Preparation Init: Zeitlimit 120000 ms fuer manuelle Vorbereitung abgelaufen: Belegungszustand=3, Grundstellungsfaehigkeit=0. | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 63 |
| 474.303 s | 12:31:54.256 | Preparation: Test aborted due to BreakOnFail behavior. | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 63 |
| 474.303 s | 12:31:54.256 | Completion Warten: Hintergrundueberpruefung bis alle Timer abgelaufen sind | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 63 |
| 480.803 s | 12:32:00.756 | Completion: Waited for 6500 ms. | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 63 |
| 480.803 s | 12:32:00.756 | [pass] Completion Warten: Hintergrundueberpruefung ohne Vorfall abgeschlossen | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 63 |
| 480.803 s | 12:32:00.756 | Completion Cleanup: Nachbereitung ausserhalb der Testschritte; bestehendes Testurteil bleibt erhalten. | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 63 |
| 480.803 s | 12:32:00.756 | Completion Cleanup: Cleanup GFM-A 0: Zustand=3, Grundstellbarkeit=0; Ziel frei/nicht grundstellbar. | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 63 |
| 480.803 s | 12:32:00.756 | Completion Cleanup: Cleanup: einmal AZGH senden und Grundstellbarkeit abwarten. | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 63 |
| 480.803 s | 12:32:00.756 | Completion Cleanup: Sende 'Kommando AchszaehlgrundstellungHilfsbedienung' | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 63 |
| 480.804 s | 12:32:00.757 | [pass] Completion Cleanup: Validiere BTP-Nachricht | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 63 |
| 480.805 s | 12:32:00.758 | ZE → AZ KOMMANDO_AZGH (43 bytes) | RealOCWorking_TDS_21026.pcapng frame 2117 telegram 1 |
| 487.304 s | 12:32:07.257 | [fail] Completion Cleanup: Cleanup-Ziel nach 6500 ms nicht erreicht (frei erforderlich=0): Zustand=3, Grundstellbarkeit=0. Technische/ physische Ursache am Pruefstand beheben. | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 64 |
| 487.304 s | 12:32:07.257 | [fail] Completion Cleanup: Cleanup fehlgeschlagen; definierter Ausgangszustand fuer den naechsten Test nicht garantiert. | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 64 |
| 487.304 s | 12:32:07.257 | Completion Cleanup: RaSTA- und BTP-Verbindung werden abgebaut | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 64 |
| 487.305 s | 12:32:07.258 | RaSTA disconnection request (TX), reason 0 | RealOCWorking_TDS_21026.pcapng frame 2160 |
| 487.504 s | 12:32:07.457 | Completion Reset: RaSTA- und BTP-Verbindung werden abgebaut | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 64 |
| 487.504 s | 12:32:07.457 | [pass] Completion Reset: RaSTA- und BTP-Verbindung sind bereits abgebaut | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 65 |

</details>

<a id="tc_npro-295-00522-01"></a>

## TC_NPRO.295.00522.01(O-ReZE)

```
Test Result:       INCONCLUSIVE (TC_NPRO.295.00522.01)
Detected failure:  488.321 s  Test execution stopped: test unit stopped by the user
Category:          Test execution (test_aborted)
Confidence:        high (1.00); evidence from BLF, CANoe log, PDF report
```

Test window 487.504 s – 488.322 s

![Timeline of TC_NPRO.295.00522.01(O-ReZE)](timeline_tc_npro-295-00522-01.svg)
![Legend](timeline_legend.svg)


**Evidence for the cause** (test_aborted)

- CANoe log: TDS_Report_21026.txt line 38 at 488.321 s (12:32:08.274)
- PDF report: Real_SCI-TDS_2026-10-02_12-24-11.pdf page 65 at 488.321 s (12:32:08.274)
- BLF: RealOCWorking_TDS_21026.blf object 11095 at 488.322 s (12:32:08.275)
- PDF report: Real_SCI-TDS_2026-10-02_12-24-11.pdf page 65 at 488.321 s (12:32:08.274)



**Further findings**

| Severity | Time | Category | Finding | Evidence |
|---|---|---|---|---|
| warning | 487.504 s | cascade_failure | Started in state unknown left by TC_NPRO.295.00525.01(F-ReZE) (its cleanup failed) | PDF report: Real_SCI-TDS_2026-10-02_12-24-11.pdf page 64 at 487.504 s (12:32:07.457) |



<details><summary>Events in the test window (3)</summary>

| Time | Clock | Event | Evidence |
|---|---|---|---|
| 488.321 s | 12:32:08.274 | CANoe log (error): [Help 09-0013] Test unit 'SCI-TDS': Execution stop forced. Test is incomplete! | TDS_Report_21026.txt line 38 |
| 488.322 s | 12:32:08.275 | [inconclusive] Preparation: Test execution aborted due to stop of the test unit. Test is incomplete! | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 65 |
| 491.109 s | 12:32:11.063 | [inconclusive] Preparation: Measurement stop forced. Test is incomplete! | Real_SCI-TDS_2026-10-02_12-24-11.pdf page 65 |

</details>


## Findings outside the test cases

| Severity | Time | Category | Finding |
|---|---|---|---|
| info | 3.461 s | manual_intervention | Manual connectButton from the CANoe panel |
| info | 8.510 s | manual_intervention | Manual disconnectButton from the CANoe panel |


## Sources and alignment

| Source | File | Time base |
|---|---|---|
| pcapng | RealOCWorking_TDS_21026.pcapng | frame_match, offset -1790936639.953799 s, spread 0.001 ms, 2159 samples |
| BLF | RealOCWorking_TDS_21026.blf | native measurement time |
| PDF report | Real_SCI-TDS_2026-10-02_12-24-11.pdf | native measurement time |
| CANoe log | TDS_Report_21026.txt | native measurement time |
| Test_Description | Test_Description/ | native measurement time |

- gfma_status: pcapng vs. canoe_log, 12 matched, max difference 0.005 ms, 0 unmatched
- gfma_status: pcapng vs. blf, 12 matched, max difference 0.001 ms, 0 unmatched
- test_case_start: pdf_report vs. blf, 5 matched, max difference 0.000 ms, 0 unmatched
- network merge: 2159 identical frames in pcapng and blf, 0 recorded differently, 0 only in pcapng, 0 only in blf

