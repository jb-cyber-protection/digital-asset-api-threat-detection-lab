# I-004 Rule Engine Overview

## Rule Framework
- Engine entrypoint: `src/digital_asset_lab/detections/engine.py`
- Rule implementations: `src/digital_asset_lab/detections/rules.py`
- Scenario source of truth: `data/scenarios/scenario_library.json`
- CLI runner: `scripts/run_detections.py`

## Implemented Rules
- `RULE-SCN-001-API-KEY-GEO`
  - Detects key replay across countries with auth-failure prelude.
- `RULE-SCN-002-CRED-STUFFING`
  - Detects auth failure bursts across accounts followed by success.
- `RULE-SCN-003-WITHDRAWAL-CHAIN`
  - Detects suspicious withdrawal context (novel geo + risk conditions).
- `RULE-SCN-004-ORDER-BURST`
  - Detects order create/cancel burst inconsistent with baseline behavior.
- `RULE-SCN-005-CLOUD-TOKEN`
  - Detects token misuse via region/user-agent shift and read/write mix.
- `RULE-SCN-006-READ-BURST`
  - Detects read-heavy enumeration burst consistent with exfil-like behavior.

## Reproducibility and Validation
- Rule output is deterministic for the same input events and scenario library.
- Tests prove each injected scenario triggers at least one alert:
  - `tests/test_detection_engine.py`
- Full test suite command:
```bash
python3 -m unittest discover -s tests
```
