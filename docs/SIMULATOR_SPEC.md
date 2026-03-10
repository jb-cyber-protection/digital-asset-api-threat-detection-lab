# I-002 Simulator Spec

## Purpose
Generate realistic digital-asset exchange activity with profile-specific bot behavior for SOC analysis.

## Generated Event Families
- `auth.login.success`
- `auth.login.failure`
- `api_key.used`
- `order.create`
- `order.cancel`
- `withdrawal.request`
- `ws.heartbeat`

## Output Schema (JSONL)
Each line contains:
- `event_id`, `timestamp`, `event_type`, `event_category`
- `profile`, `account_id`, `bot_id`, `api_key_id`
- `exchange`, `symbol`
- `ip`, `ip_country`, `region`, `user_agent`
- `request_id`
- `endpoint`, `http_method`
- `details` (event-specific payload)

## Profile Behavior Signals
- `market_maker`
  - Higher cancel-to-create ratio
  - Tight quote offsets
  - Very short event cadence
- `momentum`
  - Higher create ratio and trend-following side bias
  - Larger quote offsets
  - Moderate cadence
- `arb_like`
  - Fast cadence
  - API-key heavy access pattern
  - Medium cancel-to-create ratio

These differences are intentional so triage logic can later separate expected algorithmic behavior from anomalies.

## Reproducibility
Generation is deterministic with fixed:
- `--seed`
- `--start-time`
- same `config/simulation_profile.json`

## Quick Command
```bash
python3 scripts/generate_activity.py \
  --events 10000 \
  --seed 7 \
  --start-time "2026-01-01T00:00:00+00:00" \
  --output data/generated/i002_events.jsonl \
  --summary data/generated/i002_summary.json
```
