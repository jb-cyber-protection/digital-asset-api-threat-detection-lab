from __future__ import annotations

import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from digital_asset_lab.detections.engine import run_detection_engine
from digital_asset_lab.triage.enrichment import enrich_alerts

SCENARIO_LIBRARY_PATH = ROOT / "data/scenarios/scenario_library.json"


class TestTriageEnrichment(unittest.TestCase):
    def _event(
        self,
        idx: int,
        ts: datetime,
        event_type: str,
        details: dict[str, Any] | None = None,
        ip_country: str = "GB",
        region: str = "eu-west-2",
        user_agent: str = "ua-test",
        endpoint: str = "/v1/balance",
    ) -> dict[str, Any]:
        return {
            "event_id": f"evt-triage-{idx:04d}",
            "timestamp": ts.isoformat(),
            "event_type": event_type,
            "event_category": "test",
            "profile": "test",
            "account_id": "acct-triage",
            "bot_id": "bot-triage",
            "api_key_id": "key-triage",
            "exchange": "test",
            "symbol": "BTC-USD",
            "ip": "10.10.10.10",
            "ip_country": ip_country,
            "region": region,
            "user_agent": user_agent,
            "request_id": f"req-triage-{idx:04d}",
            "endpoint": endpoint,
            "http_method": "POST",
            "details": details or {},
        }

    def test_enrichment_generates_ticket_ready_fields(self) -> None:
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        events = [
            self._event(1, start + timedelta(minutes=0), "auth.login.failure", {"failure_reason": "bad_signature"}, "GB"),
            self._event(2, start + timedelta(minutes=1), "api_key.used", {"latency_ms": 12}, "US", "us-east-1", "ua-shift", "/v1/order/create"),
            self._event(3, start + timedelta(minutes=2), "api_key.used", {"latency_ms": 11}, "GB"),
        ]

        alerts = run_detection_engine(events=events, scenario_library_path=SCENARIO_LIBRARY_PATH)
        self.assertTrue(alerts)

        tickets = enrich_alerts(alerts=alerts, events=events)
        self.assertEqual(len(tickets), len(alerts))

        required = {
            "ticket_id",
            "alert_id",
            "rule_id",
            "scenario_id",
            "status",
            "severity_recommendation",
            "triage_summary",
            "timeline",
            "entity_context",
            "iocs",
            "false_positive_hints",
            "escalation_handoff",
        }

        for ticket in tickets:
            self.assertTrue(required.issubset(ticket.keys()))
            self.assertTrue(ticket["timeline"])
            self.assertTrue(ticket["false_positive_hints"])
            self.assertIn(ticket["severity_recommendation"], {"low", "medium", "high", "critical"})

    def test_timeline_is_sorted(self) -> None:
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        events = [
            self._event(10, start + timedelta(minutes=3), "api_key.used", {"latency_ms": 9}, "US", "us-east-1", "ua-a", "/v1/order/create"),
            self._event(11, start + timedelta(minutes=1), "auth.login.failure", {"failure_reason": "expired_nonce"}, "GB"),
            self._event(12, start + timedelta(minutes=2), "api_key.used", {"latency_ms": 10}, "GB", "eu-west-2", "ua-b", "/v1/balance"),
        ]

        alerts = run_detection_engine(events=events, scenario_library_path=SCENARIO_LIBRARY_PATH)
        tickets = enrich_alerts(alerts=alerts, events=events)
        self.assertTrue(tickets)

        timeline = tickets[0]["timeline"]
        timestamps = [entry["timestamp"] for entry in timeline]
        self.assertEqual(timestamps, sorted(timestamps))


if __name__ == "__main__":
    unittest.main()
