# Confidentiality

The test data in `TDS_Task/` (PCAPNG, BLF, CANoe report and log, test descriptions, telegram spec) and the
NeuPro Lua dissectors are DB InfraGO corporate information. The dissector README states that it may only be
shared with partners under a confidentiality agreement (Framework Directive 135.2001).

Rules for this project:

- Do not upload any of these files to public websites, online PCAP/BLF/PDF converters or public AI tools.
- Do not push them to a public repository. `.gitignore` already excludes `TDS_Task/`, `*.pcapng`, `*.blf`,
  `*.lua`, `LUA.zip` and generated `output/`.
- Synthetic test data in `data/synthetic/` is derived from the real capture and contains real element IDs
  (e.g. `34W1`, `DETHMM ZE 35##0001`), so it is treated as confidential as well.
- Reports generated in `output/`, and the example report in `docs/example_report/`, quote real telegrams and
  are for internal use only. Keep this repository private.
