#!/usr/bin/env python3
"""Enrich detection alerts into ticket-ready triage records."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from digital_asset_lab.common.constants import DEFAULT_ALERT_PATH, DEFAULT_OUTPUT_PATH
from digital_asset_lab.triage.enrichment import enrich_alerts

DEFAULT_TRIAGE_OUTPUT_PATH = "reports/tickets/triage_records.jsonl"
DEFAULT_TRIAGE_MARKDOWN_DIR = "reports/tickets/markdown"


def _load_jsonl(path: Path) -> list[dict[str, object]]:
    loaded: list[dict[str, object]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            loaded.append(json.loads(line))
    return loaded


def _to_markdown(ticket: dict[str, object]) -> str:
    escalation = ticket.get("escalation_handoff", {})
    iocs = ticket.get("iocs", {})
    return "\n".join(
        [
            f"# {ticket['ticket_id']}",
            "",
            "## Summary",
            f"- Alert ID: {ticket['alert_id']}",
            f"- Scenario: {ticket['scenario_id']}",
            f"- Rule: {ticket['rule_id']}",
            f"- Recommended Severity: {ticket['severity_recommendation']}",
            f"- Confidence: {ticket['confidence']}",
            f"- Status: {ticket['status']}",
            "",
            "## Triage Summary",
            str(ticket["triage_summary"]),
            "",
            "## IOC Snapshot",
            f"- IPs: {iocs.get('ip_addresses', [])}",
            f"- API Keys: {iocs.get('api_keys', [])}",
            f"- Accounts: {iocs.get('accounts', [])}",
            f"- Countries: {iocs.get('countries', [])}",
            "",
            "## Escalation Window",
            f"- Start: {escalation.get('timeline_window_utc', {}).get('start')}",
            f"- End: {escalation.get('timeline_window_utc', {}).get('end')}",
        ]
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Enrich alerts for SOC ticket handoff")
    parser.add_argument("--events", default=DEFAULT_OUTPUT_PATH, help="Input events JSONL path")
    parser.add_argument("--alerts", default=DEFAULT_ALERT_PATH, help="Input alerts JSONL path")
    parser.add_argument("--output", default=DEFAULT_TRIAGE_OUTPUT_PATH, help="Output triage JSONL path")
    parser.add_argument(
        "--markdown-dir",
        default=DEFAULT_TRIAGE_MARKDOWN_DIR,
        help="Directory for markdown ticket exports",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    events_path = Path(args.events)
    alerts_path = Path(args.alerts)
    output_path = Path(args.output)
    markdown_dir = Path(args.markdown_dir)

    if not events_path.exists():
        raise FileNotFoundError(f"Events input not found: {events_path}")
    if not alerts_path.exists():
        raise FileNotFoundError(f"Alerts input not found: {alerts_path}")

    events = _load_jsonl(events_path)
    alerts = _load_jsonl(alerts_path)

    tickets = enrich_alerts(alerts=alerts, events=events)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        for ticket in tickets:
            handle.write(json.dumps(ticket) + "\n")

    markdown_dir.mkdir(parents=True, exist_ok=True)
    for ticket in tickets:
        markdown_path = markdown_dir / f"{ticket['ticket_id']}.md"
        markdown_path.write_text(_to_markdown(ticket), encoding="utf-8")

    print(f"Processed {len(alerts)} alerts")
    print(f"Wrote {len(tickets)} enriched triage records to {output_path}")
    print(f"Markdown handoff files written to {markdown_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
