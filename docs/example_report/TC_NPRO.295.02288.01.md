# Trace failure analysis

CANoe configuration `ZE_RealOC_Stimulation.cfg` · CANoe.CAN.Ethernet.BasicEthernet 20.0.195 /pro
Measurement start 2026-10-02 12:23:59 +0200 · report generated 2026-10-06 15:59

All times are CANoe measurement time in seconds; wall-clock times are test bench local time.

## Summary

| Test case | Report | Analyzer | Detected failure | Root cause | Confidence |
|---|---|---|---|---|---|
| [TC_NPRO.295.02288.01(O)](#tc_npro-295-02288-01) | fail | **fail** | Precondition not reached: target Belegung/Grundstellbarkeit 2/0 (Test_Description), actual 3/0 | 34W1 became disturbed (Belegungszustand 3) 102 ms after an occupied report with Achszählfüllstand 0x0000; reset possible for 50 s but no AZG/AZGH sent | high (0.95) |


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

