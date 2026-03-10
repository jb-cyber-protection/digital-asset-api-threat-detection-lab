# I-005 Alert Enrichment and Triage Workflow

## Objective
Transform raw detections into escalation-ready triage records with consistent fields.

## Pipeline
1. Generate events (`scripts/generate_activity.py`)
2. Run detections (`scripts/run_detections.py`)
3. Enrich alerts (`scripts/enrich_alerts.py`)

## Enrichment Outputs
- `reports/tickets/triage_records.jsonl`
  - structured records for SOC/ticketing ingestion
- `reports/tickets/markdown/*.md`
  - human-readable handoff summaries

## Required Triage Fields
- Alert metadata (`alert_id`, `scenario_id`, `rule_id`)
- Severity recommendation and confidence
- Correlated timeline with event excerpts
- Entity context: accounts, API keys, bots, IP/country/region, endpoints
- IOC snapshot and false-positive hints
- Escalation handoff package (window, scope, evidence IDs, actions taken)

## Command Example
```bash
python3 scripts/enrich_alerts.py \
  --events data/generated/smoke_events.jsonl \
  --alerts data/generated/smoke_alerts.jsonl \
  --output reports/tickets/smoke_triage.jsonl \
  --markdown-dir reports/tickets/smoke_markdown
```
