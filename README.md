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
python3 scripts/generate_activity.py --events 25 --output data/generated/smoke_events.jsonl
python3 scripts/run_detections.py --events data/generated/smoke_events.jsonl --alerts data/generated/smoke_alerts.jsonl
```

### 3) Run tests
```bash
python3 -m unittest discover -s tests
```

## Intended Outcome
By the end of the backlog, this repo will contain a realistic mini-lab that simulates trading/API activity, generates security detections, and shows SOC-grade incident handling artifacts you can reference in interviews and applications.
