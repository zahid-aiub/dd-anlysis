# report.json and data-anlysis-report.json: formats for visualization

`report.json` holds everything the analyzer found in one test run, as plain data for a frontend: the
findings with evidence, the timeline of the run, and, with `--with-scenarios`, the 15 analysis scenarios with
the failure each one produced.

Ways to get it:

```bash
scripts/demo.sh                                       # → output/demo/report.json (with the scenarios)
.venv/bin/python analyze.py --format json --with-scenarios
.venv/bin/python analyze.py --format json --test-case 02288     # one test case
```

An example generated from the real run is in
[example_report/report.json](example_report/report.json) (about 160 KB, `schema_version` 1).

> The file quotes real test data (DB InfraGO internal). Use it only in internal tools, and do not upload it
> to public services.

`--format json` writes two files next to each other:

| File | Use |
|---|---|
| `report.json` | the complete data model (this page, from "Top level" on) |
| `data-anlysis-report.json` | a flat summary in the agreed dashboard structure ([below](#data-anlysis-reportjson)) |

## Background in five lines

- A **test run** is a sequence of **test cases** (here five), executed by CANoe (the test system, "ZE")
  against a device (the axle counter "AZ", element **GFM-A 34W1**).
- The two talk over a **RaSTA** connection (a **session**) with **telegrams**. `tx` means sent by the test
  system, `rx` sent by the device. Commands (`KOMMANDO_*`) go `tx`, reports (`MELDUNG_*`) come `rx`.
- The device reports the GFM-A state: **belegung** (1 frei = free, 2 belegt = occupied, 3 gestört =
  disturbed, …) and **grundstellbar** (0/1: whether a reset is possible).
- The analyzer explains each test case with a **symptom** (what the test reported), a **cause** (the earliest
  error that explains it) and **contributing** findings.
- **Time** `t` is in seconds since the measurement start (CANoe measurement time); `clock` is the same instant
  as ISO wall-clock time at the test bench.

## Top level

```jsonc
{
  "schema": "trace-analyzer.report", "schema_version": 1,
  "generator": "trace-analyzer 0.1.0", "generated": "2026-10-06T16:39:12+02:00",
  "run":        { ... },     // configuration, measurement start, sources and their alignment
  "summary":    { ... },     // counts for a header / KPI row
  "findings":   [ ... ],     // every finding of the real run, in time order, ids F001...
  "timeline":   { ... },     // events of the whole run: states, telegrams, sessions, panel actions, log
  "vocabulary": { ... },     // display names for codes
  "scenarios":  [ ... ]      // only with --with-scenarios
}
```

Every `test_case` field holds the test case id without its variant (`"TC_NPRO.295.02288.01"`), or `null`
outside any test case. Use it to group findings, timeline events and scenario results.

## `summary`

```json
{ "test_cases": 5, "verdicts": {"pass": 2, "fail": 2, "inconclusive": 1},
  "verdict_differs_from_report": 0,
  "findings": {"error": 7, "warning": 6, "info": 2},
  "scenarios": {"total": 21, "as_expected": 21,
                "outcome": {"failure": 15, "warning": 3, "ruled_out": 2, "check": 1}} }
```

`verdicts` are the analyzer's verdicts of the real run's test cases. The verdict and cause of each test case
come from its findings: the finding with `role` `cause` (or `cause_and_symptom`) is the root cause, the one
with `symptom` is what the test reported.

## `findings[]`

```json
{
  "id": "F004", "t": 186.953046, "clock": "2026-10-02T12:27:06.906+02:00",
  "test_case": "TC_NPRO.295.02288.01",
  "category": "device_disturbed", "area": "Field element / test bench state",
  "severity": "error", "confidence": 0.95, "role": "cause",
  "summary": "34W1 became disturbed (Belegungszustand 3) 102 ms after an occupied report ...",
  "evidence": [ {"source": "pcapng", "file": "RealOCWorking_TDS_21026.pcapng",
                 "locator": "frame 425 telegram 1", "t": 186.953046, "clock": "..."} ],
  "details": { "element": "34W1", "reset_windows": [[198.86993, 248.861888]], "...": "..." }
}
```

| Field | Meaning |
|---|---|
| `t` | when it happened; `null` for findings without a moment (e.g. a spec/version mismatch) |
| `category` | one of `vocabulary.categories` (e.g. `timeout`, `incorrect_length`, `device_disturbed`) |
| `severity` | `error` (failure), `warning`, `info` |
| `role` | `cause`, `symptom`, `cause_and_symptom`, `contributing`, or `run` (not in a test case) |
| `evidence[]` | where to find the proof: source (`pcapng`, `blf`, `pdf_report`, `canoe_log`, `test_spec`), file, locator (frame / object / page / line / row), time |
| `details` | rule-specific extras, free-form; useful ones: `reset_windows` (`[[start, end]]` in s), `precursor`, `expected`/`actual` (lengths), `target`/`actual` (states), `delay_s`, `limit_s` |

## `timeline`

Events of the **whole run**, sorted by `t`. Filter them by `test_case` or by a test case `window`.

| List | Item fields | Typical drawing |
|---|---|---|
| `gfma_states` | `t`, `element`, `belegung`, `belegung_name`, `grundstellbar`, `achszaehlfuellstand`, `test_case`, `evidence` | step line of `belegung` over time; shade spans with `grundstellbar = 1` |
| `telegrams` | `t`, `direction` (`tx`/`rx`), `from`, `to`, `message`, `code`, `command`, `length`, `fields`, `test_case`, `evidence` | dots in two lanes (tx / rx), tooltip with `message` and `fields` |
| `sessions` | `index`, `start`, `end`, `test_case`, `established`, `closed_by`, `disconnect_reason`, `messages`, `heartbeats` | bars (connection up) |
| `operator_actions` | `t`, `name`, `command`, `value`, `test_case` | markers: manual actions on the CANoe panel |
| `log` | `t`, `level`, `text`, `test_case` | markers or a list, e.g. the stop message |

A state is valid from its `t` until the next state of the same `element`. The first state of a test case can be
earlier than its window start; take the last state before `window.start`.

## `scenarios[]` (with `--with-scenarios`)

One entry per analysis scenario. Real scenarios are checked on the real run. Synthetic ones run on a copy of the
capture with one failure edited in, so CANoe's verdict there is still the real one (`pass`), and the analyzer
fails the test.

```jsonc
{
  "number": "3s", "key": "unexpected_response", "title": "Unexpected response",
  "detection": "A status telegram arrives within the 500 ms the NOT step forbids",
  "data": "synthetic", "capture": "S03s_unexpected_response.pcapng",
  "edit": ["frame 326: heartbeat replaced by Meldung GFM-A Belegungszustand 1/1, 299 ms after the AZGH"],
  "outcome": "failure",
  "failure": { "category": "unexpected_response", "severity": "error", "t": 132.615594,
               "test_case": "TC_NPRO.295.02284.01", "summary": "...", "evidence": [ ... ] },
  "results": [ { "test_case": "TC_NPRO.295.02284.01", "report_verdict": "pass", "verdict": "fail",
                 "verdict_differs": true,
                 "symptom": {"category": "...", "t": 132.615594, "summary": "..."},
                 "cause":   {"category": "...", "t": 132.615594, "summary": "..."},
                 "findings": [ { ..., "introduced": true } ] } ],
  "expected": [ {"test_case": "...", "category": "unexpected_response", "role": "cause", "verdict": "fail"} ],
  "check": {"as_expected": true, "problems": []}
}
```

| Field | Meaning |
|---|---|
| `outcome` | `failure`: the scenario's failure was found as an error · `warning`: reported, not a failure (e.g. an allowed rejection) · `ruled_out`: checked on the real run, the failure is not there · `check`: a run-level check without a finding |
| `failure` | the finding the scenario is about, with time and evidence; `null` for `ruled_out` and `check` |
| `results[]` | per affected test case: CANoe vs. analyzer verdict, symptom, cause, and its error/warning findings (`introduced: true` if the edit added it) |
| `edit` | what was changed in the capture (synthetic only) |
| `check.as_expected` | whether the analyzer gave the expected conclusion; this is a test of the analyzer, **not** the test case verdict |

## Suggested views

1. **Run overview**: a KPI row from `summary`; the findings with `role` `cause` as one row per test case
   (category, `area`, summary, confidence).
2. **Timeline**: `timeline` lanes (GFM-A state, tx/rx telegrams, sessions, panel actions) for the whole run or
   one test case window, with markers at the `t` of the cause and symptom findings.
3. **Scenario matrix**: `scenarios` as cards or a grid, colored by `outcome`, showing `report_verdict →
   verdict`, the `failure` summary and time, and `edit` on hover.

Colors used by the analyzer's own report (optional): tx/rx telegrams and the state line `#2a78d6`, panel actions
`#eb6834`; status pass `#0ca30c`, warning `#fab219`, error/cause `#d03b3b`, symptom `#ec835a`.

## data-anlysis-report.json

The same real run as one flat response. The keys follow the agreed structure; the values come from the analysis.
Times are UTC (`...Z`); `time_s` is CANoe measurement time.

```jsonc
{
  "analysis_id": "TRACE-RUN-20261002-102359",      // from the measurement start (UTC)
  "device_id": "DETHMM AZA34##0001",               // device under test (config nodes.dut.id)
  "timestamp": "2026-10-02T10:23:59.953Z",         // measurement start
  "analysis_type": "TRACE_COMMUNICATION",
  "result_status": "FAILED",                       // FAILED if any test case failed, else INCONCLUSIVE / PASSED
  "summary": "2 of 5 test cases failed. TC_NPRO.295.02288.01: 34W1 became disturbed ...",
  "trace_messages": [ {
      "message_id": "frame-425-1", "timestamp": "2026-10-02T10:27:06.906Z", "time_s": 186.953046,
      "sender": "34W1", "receiver": "DETHMM ZE 35##0001", "protocol": "SCI-TDS BL5 over RaSTA",
      "message_type": "MELDUNG_GFMA_BELEGUNGSZUSTAND", "message_code": "0x0007", "direction": "AZ→ZE",
      "length": 47, "fields": {"belegung": 3, "grundstellbar": 0, "achszaehlfuellstand": 0},
      "test_case": "TC_NPRO.295.02288.01", "status": "FAILED", "error_reason": "Device Disturbed" } ],
  "failure_findings": [ {
      "message_id": "frame-380-2", "expected_length": 48, "actual_length": 47, "result": "Message Length Error",
      "test_case": "TC_NPRO.295.02288.01", "timestamp": "...", "time_s": 180.287372,
      "category": "incorrect_length", "description": "...", "confidence": 0.9, "evidence": ["..."] } ],
  "data_comparisons": [
      {"field": "GFM-A state for the precondition", "expected": "2/0 (belegt, nicht grundstellbar)",
       "actual": "3/0 (gestört, nicht grundstellbar)", "result": "Error", "test_case": "TC_NPRO.295.02288.01"},
      {"field": "RaSTA message gap", "expected": "<= 750 ms", "actual": "max 306 ms", "result": "OK", "test_case": null} ]
}
```

| Key | Content |
|---|---|
| `trace_messages[]` | all 45 SCI-TDS telegrams of the run, in time order. `status` is `FAILED` if the telegram is evidence of an error finding, `WARNING` for a warning, otherwise `OK`; `error_reason` names the finding (e.g. `Message Length Error`, `Device Disturbed`) |
| `failure_findings[]` | every error finding. `message_id` points to a `trace_messages[].message_id` (or `null` if no telegram is involved, e.g. an aborted test); `expected_length` / `actual_length` are set for length errors only; `result` is the short reason; `description` the full sentence |
| `data_comparisons[]` | what the analyzer compared: the verdict per test case, each failure as expected vs. actual, and run-wide protocol checks with the measured value (`test_case: null`). `result` is `OK`, `Warning` or `Error` |

The short reasons in `result` / `error_reason`: Message Length Error, Response Timeout, Missing Message,
Unexpected Response, Wrong Message Order, Invalid Payload, Connection Interruption, Sequence Error,
Command Rejected, Configuration Mismatch, Precondition Not Reached, Device Disturbed, Cascade Failure,
Test Aborted, Test Step Failed, Manual Intervention, Time Alignment.

## Stability

Fields are only added in `schema_version` 1; renames or removals raise the version. `details` is not part of
that promise: its keys depend on the rule.
