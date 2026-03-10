#!/usr/bin/env python3
"""Generate realistic synthetic exchange activity events."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from digital_asset_lab.common.constants import (
    DEFAULT_EVENTS,
    DEFAULT_OUTPUT_PATH,
    DEFAULT_SEED,
    DEFAULT_SIMULATION_CONFIG_PATH,
    DEFAULT_START_TIME,
)
from digital_asset_lab.simulator.generator import generate_events, summarize_events


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate synthetic digital-asset trading/API events for SOC analysis"
    )
    parser.add_argument(
        "--events",
        type=int,
        default=DEFAULT_EVENTS,
        help="Number of events to emit (default: 10000)",
    )
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED, help="Random seed for reproducibility")
    parser.add_argument(
        "--start-time",
        default=DEFAULT_START_TIME,
        help="ISO8601 start time in UTC for deterministic timestamps",
    )
    parser.add_argument(
        "--config",
        default=DEFAULT_SIMULATION_CONFIG_PATH,
        help="Simulation config JSON path",
    )
    parser.add_argument("--output", default=DEFAULT_OUTPUT_PATH, help="Output JSONL file path")
    parser.add_argument(
        "--summary",
        default="",
        help="Optional JSON summary output path (profile + event distribution)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    events = generate_events(
        total_events=args.events,
        seed=args.seed,
        start_time=args.start_time,
        config_path=args.config,
    )

    with output_path.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event) + "\n")

    summary = summarize_events(events)
    if args.summary:
        summary_path = Path(args.summary)
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print(f"Generated {len(events)} events at {output_path}")
    print(f"Profile distribution: {summary['profile_counts']}")
    print(f"Event type distribution: {summary['event_type_counts']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
