# Portfolio Evidence Map

## Digital Asset Knowledge
- Exchange/API operation modeling and custody-sensitive events:
  - `config/simulation_profile.json`
  - `src/digital_asset_lab/simulator/generator.py`
- Threat scenarios specific to digital-asset operations:
  - `data/scenarios/scenario_library.json`
  - `docs/scenarios/SCENARIO_CATALOG.md`

## Algorithmic Trading Knowledge
- Distinct bot profiles (`market_maker`, `momentum`, `arb_like`) with behavior-specific cadence and order dynamics:
  - `config/simulation_profile.json`
  - `docs/SIMULATOR_SPEC.md`
- Manipulation/anomaly detection scenario for bot hijack and burst behavior:
  - `data/scenarios/scenario_library.json` (SCN-004)

## SOC L1 Operations Capability
- Rule detections with ATT&CK mapping + triage context:
  - `src/digital_asset_lab/detections/rules.py`
  - `src/digital_asset_lab/detections/schema.py`
- Alert enrichment and escalation-ready handoff payload:
  - `src/digital_asset_lab/triage/enrichment.py`
  - `scripts/enrich_alerts.py`
- Operational playbooks and containment boundaries:
  - `runbooks/`
  - `runbooks/templates/containment_action_matrix.md`

## Analyst Quality and Improvement Mindset
- Case artifacts with TP/FP outcomes and evidence snapshots:
  - `reports/cases/`
  - `reports/incidents/evidence/`
- Detection tuning and measurable KPI improvements:
  - `scripts/evaluate_tuning.py`
  - `reports/metrics/I-008-tuning-report.md`

## Interview Demo Readiness
- One-command end-to-end walkthrough:
  - `scripts/demo.py`
  - `docs/DEMO_FLOW.md`
