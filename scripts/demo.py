#!/usr/bin/env python3
"""Run an end-to-end SOC demo flow for interview presentation."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from digital_asset_lab.common.constants import DEFAULT_SEED, DEFAULT_START_TIME
from digital_asset_lab.detections.engine import run_detection_engine
from digital_asset_lab.detections.injected_events import build_injected_scenario_events
from digital_asset_lab.simulator.generator import generate_events
from digital_asset_lab.triage.enrichment import enrich_alerts

DEFAULT_OUTPUT_DIR = "reports/portfolio/demo"
DEFAULT_SCENARIO_LIBRARY_PATH = "data/scenarios/scenario_library.json"
DEFAULT_DETECTION_CONFIG_PATH = "config/detection_defaults.json"
DEFAULT_SIMULATION_CONFIG_PATH = "config/simulation_profile.json"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run end-to-end demo flow")
    parser.add_argument("--events", type=int, default=1500)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--start-time", default=DEFAULT_START_TIME)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--scenario-library", default=DEFAULT_SCENARIO_LIBRARY_PATH)
    parser.add_argument("--detection-config", default=DEFAULT_DETECTION_CONFIG_PATH)
    parser.add_argument("--simulation-config", default=DEFAULT_SIMULATION_CONFIG_PATH)
    parser.add_argument("--tuning-profile", default="tuned")
    parser.set_defaults(include_injections=True)
    parser.add_argument("--include-injections", dest="include_injections", action="store_true")
    parser.add_argument("--no-injections", dest="include_injections", action="store_false")
    return parser.parse_args()


def _write_jsonl(path: Path, items: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for item in items:
            handle.write(json.dumps(item) + "\n")


def _build_summary(events: list[dict[str, Any]], alerts: list[dict[str, Any]], tickets: list[dict[str, Any]]) -> str:
    alert_counts = Counter(alert["scenario_id"] for alert in alerts)
    top_tickets = tickets[:5]

    lines: list[str] = [
        "# Demo Summary",
        "",
        "## Dataset",
        f"- Total events: {len(events)}",
        f"- Total alerts: {len(alerts)}",
        f"- Total enriched tickets: {len(tickets)}",
        "",
        "## Alerts By Scenario",
    ]

    if alert_counts:
        for scenario_id, count in sorted(alert_counts.items()):
            lines.append(f"- {scenario_id}: {count}")
    else:
        lines.append("- No alerts generated")

    lines.extend(
        [
            "",
            "## Ticket Preview",
        ]
    )

    if top_tickets:
        for ticket in top_tickets:
            lines.append(
                f"- {ticket['ticket_id']}: {ticket['severity_recommendation']} | {ticket['triage_summary']}"
            )
    else:
        lines.append("- No enriched tickets available")

    lines.extend(
        [
            "",
            "## 5-8 Minute Walkthrough",
            "1. Show generated trading/API telemetry and profile mix.",
            "2. Run rule detections and explain scenario coverage.",
            "3. Open one enriched ticket and walk through timeline/IOCs.",
            "4. Show escalation handoff quality and containment options.",
            "5. End with tuning metrics and case outcomes (TP + FP).",
        ]
    )

    return "\n".join(lines)


def main() -> int:
    args = parse_args()

    events = generate_events(
        total_events=args.events,
        seed=args.seed,
        start_time=args.start_time,
        config_path=args.simulation_config,
    )

    if args.include_injections:
        events.extend(build_injected_scenario_events())
        events.sort(key=lambda item: item["timestamp"])

    alerts = run_detection_engine(
        events=events,
        scenario_library_path=args.scenario_library,
        detection_config_path=args.detection_config,
        tuning_profile=args.tuning_profile,
    )
    tickets = enrich_alerts(alerts=alerts, events=events)

    output_dir = Path(args.output_dir)
    events_path = output_dir / "events.jsonl"
    alerts_path = output_dir / "alerts.jsonl"
    tickets_path = output_dir / "triage.jsonl"
    summary_path = output_dir / "summary.md"

    _write_jsonl(events_path, events)
    _write_jsonl(alerts_path, alerts)
    _write_jsonl(tickets_path, tickets)
    summary_path.write_text(_build_summary(events, alerts, tickets), encoding="utf-8")

    print(f"Demo output directory: {output_dir}")
    print(f"Events: {len(events)} | Alerts: {len(alerts)} | Tickets: {len(tickets)}")
    print(f"Summary: {summary_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
