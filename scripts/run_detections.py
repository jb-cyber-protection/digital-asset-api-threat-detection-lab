#!/usr/bin/env python3
"""Run baseline detections over generated events.

This is intentionally minimal for I-001 scaffolding. Detection rules are added in I-004.
"""

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


ALERT_EVENT_TYPES = {"auth.failure", "withdrawal.create"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run baseline rule checks over events")
    parser.add_argument("--events", default=DEFAULT_OUTPUT_PATH, help="Input events JSONL file path")
    parser.add_argument("--alerts", default=DEFAULT_ALERT_PATH, help="Output alerts JSONL file path")
    return parser.parse_args()


def detect(event: dict[str, object]) -> dict[str, object] | None:
    event_type = event.get("event_type")
    if event_type in ALERT_EVENT_TYPES:
        return {
            "alert_id": f"al-{event.get('event_id', 'unknown')}",
            "source_event_id": event.get("event_id"),
            "severity": "medium",
            "title": f"Suspicious event type: {event_type}",
        }
    return None


def main() -> int:
    args = parse_args()
    events_path = Path(args.events)
    alerts_path = Path(args.alerts)
    alerts_path.parent.mkdir(parents=True, exist_ok=True)

    if not events_path.exists():
        raise FileNotFoundError(f"Events input not found: {events_path}")

    emitted = 0
    with events_path.open("r", encoding="utf-8") as source, alerts_path.open("w", encoding="utf-8") as sink:
        for line in source:
            event = json.loads(line)
            alert = detect(event)
            if alert is None:
                continue
            sink.write(json.dumps(alert) + "\n")
            emitted += 1

    print(f"Wrote {emitted} alerts to {alerts_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
