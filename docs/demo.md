# Demo: 10 minutes

A walkthrough for presenting the analyzer. Each step has the command to run, what to show, and the one point to
make. `scripts/demo.sh` runs steps 2, 5 and 6 in one go (about 15 s) and opens the reports. The slides are in
[presentation.html](presentation.html).

Before the demo:

- Run `scripts/demo.sh --no-open` once, so that `output/demo/` and `data/synthetic/` exist.
- Open Wireshark with the **SCI-TDS** profile and `RealOCWorking_TDS_21026.pcapng`.
- Have `Real_SCI-TDS_2026-10-02_12-24-11.pdf` open at page 56.

## 1. The problem (1 min)

Show the CANoe report for TC_NPRO.295.02288.01: *"Vorbereitung frei → belegt nicht abgeschlossen"* after 120 s
(page 56). The report says *that* the precondition failed, not *why*. Answering that by hand means opening four
tools with four time bases: Wireshark in epoch time, the BLF in measurement time, the PDF in measurement time,
and the Test_Description relative to t1.

**Point:** the evidence is spread over five files that do not share a clock.

## 2. One command (1 min)

```bash
.venv/bin/python analyze.py --out output/demo
```

Show the verdict table in the terminal. For all five test cases, the analyzer's verdict matches CANoe's, and
each failure has a cause.

**Point:** one run explains the whole test unit, including the inconclusive test case at the end.

## 3. The 02288 report (3 min)

Open `output/demo/report.html` and go to TC_NPRO.295.02288.01:

- **Result block.** The symptom (precondition not reached, 300.288 s) is kept apart from the cause: GFM-A 34W1
  disturbed at 186.953 s, 102 ms after an "occupied" report with Achszählfüllstand 0x0000. A reset was
  possible for 50 s, but nobody sent AZG/AZGH.
- **Timeline.** Follow the GFM-A state line: frei → belegt → gestört, the shaded "resettable" window, the
  cause rule, and the failed preparation step at the symptom rule. Hover a dot to see the frame number.
- **Further findings.** Step 2 could never have passed anyway: the Test_Description expects a 48-byte
  BL6/BL7 status, while the RealOC sends 47 bytes (BL5). This is reported as a failure of its own, not as the
  cause.
- **Ruled out.** Connection, sequence, payload, timing.

**Point:** it is a test bench / field element problem, not a protocol fault, and the report shows why that
conclusion holds.

## 4. Check it in Wireshark (1 min)

In Wireshark, apply the filter `frame.number in {423, 425, 504, 837}`. The Belegung column reads 2 → 3 → 3 (resettable) → 3.
These are the same frames and times the report lists.

**Point:** every claim points to a frame, page or line that an engineer can open.

## 5. The cascade (1 min)

In the report, open TC_NPRO.295.00525.01. The cause is the cascade: the test started disturbed because the
cleanup of 02288 failed. The manual panel AZGH/AZG at 381.6 s and 391.4 s were forbidden by the test instruction
and had no effect; the BLF is the only source that shows them.

**Point:** the second failure is a consequence of the first, and the report says so.

## 6. Failures the real run does not contain (2 min)

```bash
.venv/bin/python -m trace_analyzer.synthetic
```

Show the table: 15 scenarios, 21 checks, all as expected. Each synthetic capture is a copy of the RealOC
pcapng with one failure edited in at RaSTA level: sequence numbers kept, lengths and checksums recomputed.
Open `output/demo/synthetic_unexpected_response.html`: CANoe passed 02284, but the edited capture has a status
telegram 299 ms after the AZGH, which the NOT step forbids. The analyzer says **FAILED (report: passed)**.

Optionally, open `data/synthetic/S03s_unexpected_response.pcapng` in Wireshark, frame 326.

**Point:** the rules are tested on every failure type in the task, and they disagree with CANoe when the trace
does.

## 7. Limits and open questions (1 min)

Show the last slide, or §7 of [IMPORTANT_TO_KNOW.md](../IMPORTANT_TO_KNOW.md):

- The baseline question (BL5 vs. BL6/BL7) is open.
- The physical cause of the disturbance needs the test bench.
- The 750 ms RaSTA limit is an assumption.
- Synthetic captures keep the original safety code.

**Point:** these are the questions for the team, and the tool's conclusions do not depend on guessing them.

## Questions people ask

| Question | Answer |
|---|---|
| Why not just use Wireshark/tshark? | The Lua dissector stops on malformed telegrams, which the length and payload rules need. Wireshark also shifts BLF times by the analysing PC's time zone. tshark checks the decoder in the tests instead. |
| How exact is the time alignment? | The pcapng is matched to the BLF frame by frame: 2,159 of 2,159 frames, spread below 1 µs. Without the BLF, the RaSTA timestamps give the offset within 1 ms. |
| What if a different test bench is used? | Change the paths, nodes and limits in `config/config.yaml`. A different SCI-TDS baseline needs its layout added. |
| How is "confidence" computed? | It is set per rule and is heuristic. The report also names the sources that back the cause. |
| Can it run on a new test run? | Yes, if the run has the same file types: `analyze.py --config <new config>`. |
