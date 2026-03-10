# Digital Asset API Threat Detection Lab

Portfolio project to demonstrate practical knowledge of:
- Digital assets and exchange operations
- Algorithmic trading behavior and risk patterns
- SOC Level 1 alert triage, enrichment, and escalation quality

## Current State
This repository follows an issue-driven implementation workflow.
- Project concept: [docs/PROJECT_IDEA.md](/Users/jibz/Desktop/digital-asset-api-threat-detection-lab/docs/PROJECT_IDEA.md)
- Backlog and execution order: [docs/ISSUES.md](/Users/jibz/Desktop/digital-asset-api-threat-detection-lab/docs/ISSUES.md)
- Structure map and issue targets: [docs/REPO_STRUCTURE.md](/Users/jibz/Desktop/digital-asset-api-threat-detection-lab/docs/REPO_STRUCTURE.md)
- Quality gate/checklist: [docs/DEFINITION_OF_DONE.md](/Users/jibz/Desktop/digital-asset-api-threat-detection-lab/docs/DEFINITION_OF_DONE.md)
- Simulator data contract and profile behavior: [docs/SIMULATOR_SPEC.md](/Users/jibz/Desktop/digital-asset-api-threat-detection-lab/docs/SIMULATOR_SPEC.md)
- Threat scenarios and ATT&CK mapping: [docs/scenarios/SCENARIO_CATALOG.md](/Users/jibz/Desktop/digital-asset-api-threat-detection-lab/docs/scenarios/SCENARIO_CATALOG.md)
- Detection rule engine + alert schema: [docs/detections/RULE_ENGINE.md](/Users/jibz/Desktop/digital-asset-api-threat-detection-lab/docs/detections/RULE_ENGINE.md)
- Triage enrichment workflow: [docs/detections/TRIAGE_WORKFLOW.md](/Users/jibz/Desktop/digital-asset-api-threat-detection-lab/docs/detections/TRIAGE_WORKFLOW.md)
- SOC runbooks and escalation templates: [runbooks/README.md](/Users/jibz/Desktop/digital-asset-api-threat-detection-lab/runbooks/README.md)
- Incident case artifacts: `reports/cases/` and `reports/incidents/evidence/`

## I-002 Delivered
- Config-driven synthetic event simulator for digital-asset API/trading telemetry
- Distinct normal bot profiles: `market_maker`, `momentum`, `arb_like`
- Deterministic generation with seed + fixed start time
- Event families included: auth, order create/cancel, API key usage, withdrawals, and WebSocket heartbeats

## I-003 Delivered
- Scenario library with 6 cloud-first digital-asset threat scenarios
- IOC expectations and triage/escalation response guidance per scenario
- MITRE ATT&CK mappings with rationale for each scenario
- Machine-readable source of truth for upcoming detection implementation in `data/scenarios/scenario_library.json`

## I-004 Delivered
- Scenario-linked rule engine with severity/confidence metadata
- Detection coverage for all I-003 scenarios (SCN-001 to SCN-006)
- Structured alert output schema for SOC L1 triage and escalation

## I-005 Delivered
- Alert enrichment pipeline producing ticket-ready triage records
- Correlated timelines, IOC/entity context, and escalation handoff payloads
- Scenario-specific false-positive hints and severity recommendation logic

## I-006 Delivered
- Five SOC runbooks covering token abuse, suspicious login, key misuse, malware-like endpoint signal, and exfiltration burst events
- Updated L1->L2 handoff template
- Containment action matrix defining L1-authorized vs escalate-only actions

## I-007 Delivered
- Three incident case artifacts with full chronology and escalation notes
- Ticket narratives and evidence snapshots linked to detector outputs
- Includes both true-positive and false-positive outcomes for analyst quality demonstration

## Quick Start
### 1) Create environment (recommended)
```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -e ".[dev]"
```

### 2) Run scaffold smoke workflow
```bash
make smoke
```

Equivalent commands:
```bash
python3 scripts/generate_activity.py --events 250 --output data/generated/smoke_events.jsonl --summary data/generated/smoke_summary.json
python3 scripts/run_detections.py --events data/generated/smoke_events.jsonl --alerts data/generated/smoke_alerts.jsonl
```

### 3) Run tests
```bash
make test
```

### 4) Generate a full 10k event dataset
```bash
python3 scripts/generate_activity.py --events 10000 --seed 7 --start-time "2026-01-01T00:00:00+00:00" --output data/generated/i002_events.jsonl --summary data/generated/i002_summary.json
```

## Intended Outcome
By the end of the backlog, this repo will contain a realistic mini-lab that simulates trading/API activity, generates security detections, and shows SOC-grade incident handling artifacts you can reference in interviews and applications.
