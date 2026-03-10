#!/usr/bin/env python3
"""Generate baseline synthetic exchange activity events.

This is intentionally minimal for I-001 scaffolding. Rich behavior is added in I-002.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from digital_asset_lab.common.constants import DEFAULT_EVENTS, DEFAULT_OUTPUT_PATH, DEFAULT_SEED


EVENT_TYPES = ["auth.success", "order.create", "order.cancel", "ws.heartbeat"]
BOT_PROFILES = ["market_maker", "momentum", "arb_like"]
COUNTRIES = ["GB", "NL", "US", "DE", "FR"]


def build_event(index: int, base_time: datetime, rng: random.Random) -> dict[str, object]:
    return {
        "event_id": f"evt-{index:06d}",
        "timestamp": (base_time + timedelta(seconds=index)).isoformat(),
        "event_type": rng.choice(EVENT_TYPES),
        "bot_profile": rng.choice(BOT_PROFILES),
        "account_id": f"acct-{rng.randint(1000, 9999)}",
        "api_key_id": f"key-{rng.randint(1, 40):03d}",
        "ip_country": rng.choice(COUNTRIES),
    }


def generate_events(total_events: int, seed: int) -> list[dict[str, object]]:
    rng = random.Random(seed)
    start = datetime.now(timezone.utc) - timedelta(minutes=10)
    return [build_event(i, start, rng) for i in range(total_events)]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate baseline synthetic trading/API events")
    parser.add_argument("--events", type=int, default=DEFAULT_EVENTS, help="Number of events to emit")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED, help="Random seed for reproducibility")
    parser.add_argument("--output", default=DEFAULT_OUTPUT_PATH, help="Output JSONL file path")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    events = generate_events(total_events=args.events, seed=args.seed)
    with output_path.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event) + "\n")

    print(f"Generated {len(events)} events at {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
