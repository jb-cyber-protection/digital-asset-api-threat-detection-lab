# I-004 Alert Output Schema

Each detection alert emitted by `scripts/run_detections.py` includes:

- `alert_id`: deterministic alert identifier
- `rule_id`: internal detection rule ID
- `scenario_id`: linked threat scenario (SCN-001 to SCN-006)
- `title`: concise analyst-facing alert title
- `severity`: `critical|high|medium|low`
- `confidence`: 0.0 to 1.0 confidence score
- `first_seen`, `last_seen`: alert time bounds
- `event_count`: number of matched events
- `summary`: escalation-ready concise summary
- `affected_entities`:
  - `account_ids`, `api_key_ids`, `bot_ids`, `source_ips`, `countries`, `regions`
- `evidence_event_ids`: representative source event IDs
- `mitre_attack`: ATT&CK mappings inherited from scenario library
- `recommended_actions`: triage/escalation actions for L1 analysts

This schema is defined in `src/digital_asset_lab/detections/schema.py`.
