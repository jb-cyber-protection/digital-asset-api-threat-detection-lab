# I-009 Demo Flow

## One-Command Demo
```bash
python3 scripts/demo.py --events 1500 --output-dir reports/portfolio/demo
```

## What It Runs
1. Generate synthetic trading/API events.
2. Optionally inject deterministic threat scenarios (enabled by default).
3. Run tuned rule-based detections.
4. Enrich alerts into ticket-ready triage records.
5. Produce a concise markdown summary for presentation.

## Output Artifacts
- `events.jsonl`
- `alerts.jsonl`
- `triage.jsonl`
- `summary.md`

## Presentation Target
Use `summary.md` as the anchor for a 5-8 minute interview walkthrough.
