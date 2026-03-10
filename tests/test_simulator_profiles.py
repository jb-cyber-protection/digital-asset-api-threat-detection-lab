from __future__ import annotations

import sys
import unittest
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from digital_asset_lab.common.constants import DEFAULT_START_TIME
from digital_asset_lab.simulator.generator import generate_events

CONFIG_PATH = ROOT / "config/simulation_profile.json"


class TestSimulatorProfiles(unittest.TestCase):
    def test_seeded_generation_is_reproducible(self) -> None:
        first = generate_events(
            total_events=250,
            seed=21,
            start_time=DEFAULT_START_TIME,
            config_path=CONFIG_PATH,
        )
        second = generate_events(
            total_events=250,
            seed=21,
            start_time=DEFAULT_START_TIME,
            config_path=CONFIG_PATH,
        )
        self.assertEqual(first, second)

    def test_required_event_types_exist_in_10k_dataset(self) -> None:
        events = generate_events(
            total_events=10_000,
            seed=7,
            start_time=DEFAULT_START_TIME,
            config_path=CONFIG_PATH,
        )
        event_types = {event["event_type"] for event in events}
        required = {
            "auth.login.success",
            "auth.login.failure",
            "api_key.used",
            "order.create",
            "order.cancel",
            "withdrawal.request",
            "ws.heartbeat",
        }
        self.assertTrue(required.issubset(event_types))

    def test_profile_behavior_is_distinct(self) -> None:
        events = generate_events(
            total_events=8_000,
            seed=77,
            start_time=DEFAULT_START_TIME,
            config_path=CONFIG_PATH,
        )

        counts: dict[str, dict[str, int]] = {}
        for event in events:
            profile = event["profile"]
            event_type = event["event_type"]
            counts.setdefault(profile, {"order.create": 0, "order.cancel": 0})
            if event_type in {"order.create", "order.cancel"}:
                counts[profile][event_type] += 1

        mm_ratio = counts["market_maker"]["order.cancel"] / max(1, counts["market_maker"]["order.create"])
        mo_ratio = counts["momentum"]["order.cancel"] / max(1, counts["momentum"]["order.create"])
        ar_ratio = counts["arb_like"]["order.cancel"] / max(1, counts["arb_like"]["order.create"])

        self.assertGreater(mm_ratio, ar_ratio)
        self.assertGreater(ar_ratio, mo_ratio)

    def test_timestamps_are_iso8601_and_monotonic(self) -> None:
        events = generate_events(
            total_events=1_500,
            seed=5,
            start_time=DEFAULT_START_TIME,
            config_path=CONFIG_PATH,
        )

        timestamps = [datetime.fromisoformat(event["timestamp"]) for event in events]
        self.assertTrue(all(timestamp.tzinfo is not None for timestamp in timestamps))
        self.assertEqual(timestamps, sorted(timestamps))


if __name__ == "__main__":
    unittest.main()
