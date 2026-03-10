# Repository Structure and Issue Targets

## Top-Level Layout
- `src/digital_asset_lab/` - Core Python package for simulator, detections, triage, and shared logic.
- `scripts/` - Executable entry points for generation, detection, and demo workflows.
- `config/` - JSON configuration for simulation and detection defaults.
- `data/` - Generated and sample datasets.
- `runbooks/` - SOC SOPs and escalation templates.
- `reports/` - Incident artifacts, metrics output, and portfolio-ready summaries.
- `docs/` - Planning, issue tracking, scenarios, and tuning notes.
- `tests/` - Automated tests and smoke checks.
- `notebooks/` - Optional interview demo notebooks (planned in I-009).

## Issue-to-Path Mapping
- **I-002 Trading/API Activity Simulator**
  - `src/digital_asset_lab/simulator/`
  - `scripts/generate_activity.py`
  - `config/simulation_profile.json`
  - `data/generated/`

- **I-003 Threat Scenario Library + ATT&CK Mapping**
  - `docs/scenarios/`
  - `data/scenarios/`
  - `docs/PROJECT_IDEA.md` (mapping references)

- **I-004 Detection Engine**
  - `src/digital_asset_lab/detections/`
  - `scripts/run_detections.py`
  - `config/detection_defaults.json`

- **I-005 Alert Enrichment + Triage Workflow**
  - `src/digital_asset_lab/triage/`
  - `reports/tickets/`

- **I-006 SOC Runbooks + Escalation Templates**
  - `runbooks/`
  - `runbooks/templates/`

- **I-007 Incident Case Artifacts**
  - `reports/cases/`
  - `reports/incidents/`

- **I-008 Detection Tuning + Metrics**
  - `docs/tuning/`
  - `reports/metrics/`

- **I-009 Demo Interface**
  - `scripts/`
  - `notebooks/`
  - `README.md` (demo instructions)

- **I-010 Portfolio Packaging + Application Answer**
  - `README.md`
  - `reports/portfolio/`
  - `docs/` (final answer/supporting notes)
