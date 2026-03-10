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

SCENARIO_LIBRARY_PATH = ROOT / "data/scenarios/scenario_library.json"


class TestDetectionEngine(unittest.TestCase):
    def _build_event(
        self,
        *,
        idx: int,
        timestamp: datetime,
        event_type: str,
        account_id: str,
        api_key_id: str,
        bot_id: str,
        ip: str,
        country: str,
        region: str,
        user_agent: str,
        endpoint: str,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return {
            "event_id": f"evt-test-{idx:05d}",
            "timestamp": timestamp.isoformat(),
            "event_type": event_type,
            "event_category": "test",
            "profile": "test",
            "account_id": account_id,
            "bot_id": bot_id,
            "api_key_id": api_key_id,
            "exchange": "test-ex",
            "symbol": "BTC-USD",
            "ip": ip,
            "ip_country": country,
            "region": region,
            "user_agent": user_agent,
            "request_id": f"req-test-{idx:05d}",
            "endpoint": endpoint,
            "http_method": "POST",
            "details": details or {},
        }

    def _injected_events(self) -> list[dict[str, Any]]:
        base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        events: list[dict[str, Any]] = []
        idx = 1

        # SCN-001: API key replay with auth failure prelude.
        events.append(
            self._build_event(
                idx=idx,
                timestamp=base + timedelta(minutes=1),
                event_type="auth.login.failure",
                account_id="acct-scn1",
                api_key_id="key-scn1",
                bot_id="bot-scn1",
                ip="10.10.0.1",
                country="GB",
                region="eu-west-2",
                user_agent="ua-normal",
                endpoint="/v1/auth/login",
                details={"failure_reason": "bad_signature"},
            )
        )
        idx += 1
        events.append(
            self._build_event(
                idx=idx,
                timestamp=base + timedelta(minutes=2),
                event_type="api_key.used",
                account_id="acct-scn1",
                api_key_id="key-scn1",
                bot_id="bot-scn1",
                ip="44.10.0.9",
                country="US",
                region="us-east-1",
                user_agent="ua-attacker",
                endpoint="/v1/order/create",
                details={"latency_ms": 18},
            )
        )
        idx += 1
        events.append(
            self._build_event(
                idx=idx,
                timestamp=base + timedelta(minutes=3),
                event_type="api_key.used",
                account_id="acct-scn1",
                api_key_id="key-scn1",
                bot_id="bot-scn1",
                ip="55.10.0.4",
                country="SG",
                region="ap-southeast-1",
                user_agent="ua-attacker",
                endpoint="/v1/order/create",
                details={"latency_ms": 17},
            )
        )
        idx += 1

        # SCN-002: credential stuffing burst + success.
        for attempt in range(20):
            events.append(
                self._build_event(
                    idx=idx,
                    timestamp=base + timedelta(minutes=5, seconds=attempt * 10),
                    event_type="auth.login.failure",
                    account_id=f"acct-target-{attempt % 7}",
                    api_key_id="key-scn2",
                    bot_id="bot-scn2",
                    ip="185.199.110.11",
                    country="DE",
                    region="eu-central-1",
                    user_agent="ua-spray",
                    endpoint="/v1/auth/login",
                    details={"failure_reason": "invalid_token"},
                )
            )
            idx += 1
        events.append(
            self._build_event(
                idx=idx,
                timestamp=base + timedelta(minutes=8),
                event_type="auth.login.success",
                account_id="acct-target-3",
                api_key_id="key-scn2",
                bot_id="bot-scn2",
                ip="185.199.110.11",
                country="DE",
                region="eu-central-1",
                user_agent="ua-spray",
                endpoint="/v1/auth/login",
                details={"mfa_present": False},
            )
        )
        idx += 1

        # SCN-003: suspicious withdrawal from novel geo + failure prelude.
        events.append(
            self._build_event(
                idx=idx,
                timestamp=base + timedelta(minutes=19),
                event_type="api_key.used",
                account_id="acct-scn3",
                api_key_id="key-scn3",
                bot_id="bot-scn3",
                ip="10.0.5.5",
                country="GB",
                region="eu-west-2",
                user_agent="ua-scn3",
                endpoint="/v1/balance",
                details={"latency_ms": 20},
            )
        )
        idx += 1
        events.append(
            self._build_event(
                idx=idx,
                timestamp=base + timedelta(minutes=20),
                event_type="auth.login.failure",
                account_id="acct-scn3",
                api_key_id="key-scn3",
                bot_id="bot-scn3",
                ip="10.0.5.5",
                country="GB",
                region="eu-west-2",
                user_agent="ua-scn3",
                endpoint="/v1/auth/login",
                details={"failure_reason": "expired_nonce"},
            )
        )
        idx += 1
        events.append(
            self._build_event(
                idx=idx,
                timestamp=base + timedelta(minutes=21),
                event_type="withdrawal.request",
                account_id="acct-scn3",
                api_key_id="key-scn3",
                bot_id="bot-scn3",
                ip="52.3.40.2",
                country="US",
                region="us-east-1",
                user_agent="ua-withdraw",
                endpoint="/v1/withdrawals",
                details={"asset": "BTC", "amount": 0.5, "network": "bitcoin"},
            )
        )
        idx += 1

        # SCN-004: order burst with high cancel/create ratio and context shift.
        for order_idx in range(130):
            is_cancel = order_idx >= 50
            events.append(
                self._build_event(
                    idx=idx,
                    timestamp=base + timedelta(minutes=30, seconds=order_idx * 4),
                    event_type="order.cancel" if is_cancel else "order.create",
                    account_id="acct-scn4",
                    api_key_id="key-scn4",
                    bot_id="bot-hijacked",
                    ip="31.5.80.20" if is_cancel else "31.5.80.19",
                    country="NL",
                    region="eu-west-1",
                    user_agent="ua-hijack-a" if order_idx % 2 == 0 else "ua-hijack-b",
                    endpoint="/v1/order/cancel" if is_cancel else "/v1/order/create",
                    details={"order_id": f"ord-scn4-{order_idx:04d}"},
                )
            )
            idx += 1

        # SCN-005: token misuse with region and user-agent shift + read/write mix.
        for token_idx in range(12):
            second_phase = token_idx >= 6
            events.append(
                self._build_event(
                    idx=idx,
                    timestamp=base + timedelta(minutes=50, seconds=token_idx * 50),
                    event_type="api_key.used",
                    account_id="acct-scn5",
                    api_key_id="key-scn5",
                    bot_id="bot-scn5",
                    ip="18.2.1.1" if second_phase else "3.1.1.1",
                    country="US" if second_phase else "GB",
                    region="us-east-1" if second_phase else "eu-west-2",
                    user_agent="ua-cloud-b" if second_phase else "ua-cloud-a",
                    endpoint="/v1/order/create" if second_phase else "/v1/balance",
                    details={"latency_ms": 15},
                )
            )
            idx += 1

        # SCN-006: read-heavy exfil-like enumeration burst.
        read_endpoints = ["/v1/orders/open", "/v1/positions", "/v1/balance"]
        for read_idx in range(160):
            events.append(
                self._build_event(
                    idx=idx,
                    timestamp=base + timedelta(minutes=70, seconds=read_idx * 1),
                    event_type="api_key.used",
                    account_id="acct-scn6",
                    api_key_id="key-scn6",
                    bot_id="bot-scn6",
                    ip="91.10.10.5",
                    country="IE",
                    region="eu-west-1",
                    user_agent="ua-exfil",
                    endpoint=read_endpoints[read_idx % 3],
                    details={"latency_ms": 9},
                )
            )
            idx += 1

        events.sort(key=lambda event: event["timestamp"])
        return events

    def test_all_injected_scenarios_trigger(self) -> None:
        events = self._injected_events()
        alerts = run_detection_engine(events=events, scenario_library_path=SCENARIO_LIBRARY_PATH)
        scenario_ids = {alert["scenario_id"] for alert in alerts}

        expected = {"SCN-001", "SCN-002", "SCN-003", "SCN-004", "SCN-005", "SCN-006"}
        self.assertTrue(expected.issubset(scenario_ids), f"missing scenarios: {expected - scenario_ids}")

    def test_alert_schema_fields(self) -> None:
        events = self._injected_events()
        alerts = run_detection_engine(events=events, scenario_library_path=SCENARIO_LIBRARY_PATH)
        required_fields = {
            "alert_id",
            "rule_id",
            "scenario_id",
            "title",
            "severity",
            "confidence",
            "first_seen",
            "last_seen",
            "event_count",
            "summary",
            "affected_entities",
            "evidence_event_ids",
            "mitre_attack",
            "recommended_actions",
        }

        self.assertTrue(alerts)
        for alert in alerts:
            self.assertTrue(required_fields.issubset(alert.keys()))
            self.assertTrue(alert["mitre_attack"])
            self.assertGreaterEqual(alert["confidence"], 0.0)
            self.assertLessEqual(alert["confidence"], 1.0)


if __name__ == "__main__":
    unittest.main()
