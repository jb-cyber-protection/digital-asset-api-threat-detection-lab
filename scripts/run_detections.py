#!/usr/bin/env python3
"""Run scenario-based rule detections over generated events."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from digital_asset_lab.common.constants import DEFAULT_ALERT_PATH, DEFAULT_OUTPUT_PATH
from digital_asset_lab.detections.engine import run_detection_engine

DEFAULT_SCENARIO_LIBRARY_PATH = "data/scenarios/scenario_library.json"
DEFAULT_DETECTION_CONFIG_PATH = "config/detection_defaults.json"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run scenario-based detection engine")
    parser.add_argument("--events", default=DEFAULT_OUTPUT_PATH, help="Input events JSONL file path")
    parser.add_argument("--alerts", default=DEFAULT_ALERT_PATH, help="Output alerts JSONL file path")
    parser.add_argument(
        "--scenario-library",
        default=DEFAULT_SCENARIO_LIBRARY_PATH,
        help="Scenario library JSON path",
    )
    parser.add_argument(
        "--detection-config",
        default=DEFAULT_DETECTION_CONFIG_PATH,
        help="Detection tuning config JSON path",
    )
    parser.add_argument(
        "--tuning-profile",
        default="",
        help="Optional tuning profile override (e.g. baseline, tuned)",
    )
    return parser.parse_args()


def _load_events(events_path: Path) -> list[dict[str, object]]:
    loaded: list[dict[str, object]] = []
    with events_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            loaded.append(json.loads(line))
    return loaded


def main() -> int:
    args = parse_args()
    events_path = Path(args.events)
    alerts_path = Path(args.alerts)

    if not events_path.exists():
        raise FileNotFoundError(f"Events input not found: {events_path}")

    alerts_path.parent.mkdir(parents=True, exist_ok=True)
    events = _load_events(events_path)
    alerts = run_detection_engine(
        events=events,
        scenario_library_path=args.scenario_library,
        detection_config_path=args.detection_config,
        tuning_profile=args.tuning_profile,
    )

    with alerts_path.open("w", encoding="utf-8") as handle:
        for alert in alerts:
            handle.write(json.dumps(alert) + "\n")

    counts = Counter(alert["scenario_id"] for alert in alerts)
    print(f"Processed {len(events)} events")
    print(f"Wrote {len(alerts)} alerts to {alerts_path}")
    print(f"Alerts by scenario: {dict(counts)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
