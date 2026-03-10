#!/usr/bin/env python3
"""Evaluate baseline vs tuned detection profiles and output KPI metrics."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timedelta
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

DEFAULT_SCENARIO_LIBRARY_PATH = "data/scenarios/scenario_library.json"
DEFAULT_DETECTION_CONFIG_PATH = "config/detection_defaults.json"
DEFAULT_SIMULATION_CONFIG_PATH = "config/simulation_profile.json"
DEFAULT_OUTPUT_PATH = "reports/metrics/i008_tuning_metrics.json"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate detection tuning profiles")
    parser.add_argument("--scenario-library", default=DEFAULT_SCENARIO_LIBRARY_PATH)
    parser.add_argument("--detection-config", default=DEFAULT_DETECTION_CONFIG_PATH)
    parser.add_argument("--simulation-config", default=DEFAULT_SIMULATION_CONFIG_PATH)
    parser.add_argument("--output", default=DEFAULT_OUTPUT_PATH)
    parser.add_argument("--benign-events", type=int, default=5000)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    return parser.parse_args()


def _benign_event(
    *,
    idx: int,
    timestamp: str,
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
        "event_id": f"evt-bn-{idx:06d}",
        "timestamp": timestamp,
        "event_type": event_type,
        "event_category": "benign_borderline",
        "profile": "benign_borderline",
        "account_id": account_id,
        "bot_id": bot_id,
        "api_key_id": api_key_id,
        "exchange": "test-ex",
        "symbol": "BTC-USD",
        "ip": ip,
        "ip_country": country,
        "region": region,
        "user_agent": user_agent,
        "request_id": f"req-bn-{idx:06d}",
        "endpoint": endpoint,
        "http_method": "POST",
        "details": details or {},
    }


def _build_benign_borderline_events() -> list[dict[str, Any]]:
    start = datetime.fromisoformat(DEFAULT_START_TIME.replace("Z", "+00:00"))
    events: list[dict[str, Any]] = []
    idx = 1

    # Borderline SCN-001 pattern: 2-country key use with one auth failure, but known failover user-agent.
    events.append(
        _benign_event(
            idx=idx,
            timestamp=(start + timedelta(hours=4, minutes=0)).isoformat(),
            event_type="auth.login.failure",
            account_id="acct-bn-001",
            api_key_id="key-bn-001",
            bot_id="bot-bn-001",
            ip="10.50.0.1",
            country="GB",
            region="eu-west-2",
            user_agent="ops-failover/1.0",
            endpoint="/v1/auth/login",
            details={"failure_reason": "expired_nonce"},
        )
    )
    idx += 1
    events.append(
        _benign_event(
            idx=idx,
            timestamp=(start + timedelta(hours=4, minutes=2)).isoformat(),
            event_type="api_key.used",
            account_id="acct-bn-001",
            api_key_id="key-bn-001",
            bot_id="bot-bn-001",
            ip="18.200.1.9",
            country="IE",
            region="eu-west-1",
            user_agent="ops-failover/1.0",
            endpoint="/v1/balance",
            details={"latency_ms": 18},
        )
    )
    idx += 1

    # Borderline SCN-003 pattern: approved medium withdrawal amount from new country during treasury ops.
    events.append(
        _benign_event(
            idx=idx,
            timestamp=(start + timedelta(hours=4, minutes=10)).isoformat(),
            event_type="withdrawal.request",
            account_id="acct-bn-002",
            api_key_id="key-bn-002",
            bot_id="bot-bn-002",
            ip="44.10.3.4",
            country="US",
            region="us-east-1",
            user_agent="treasury-job/3.2",
            endpoint="/v1/withdrawals",
            details={"asset": "BTC", "amount": 0.11, "destination_type": "whitelisted_hot_wallet", "risk_score": 0.02},
        )
    )
    idx += 1

    # Borderline SCN-006 pattern: read burst from reconciliation job, below tuned threshold.
    read_endpoints = ["/v1/orders/open", "/v1/positions"]
    for burst_idx in range(130):
        events.append(
            _benign_event(
                idx=idx,
                timestamp=(start + timedelta(hours=4, minutes=20, seconds=burst_idx)).isoformat(),
                event_type="api_key.used",
                account_id="acct-bn-003",
                api_key_id="key-bn-003",
                bot_id="bot-bn-003",
                ip="34.210.0.8",
                country="GB",
                region="eu-west-2",
                user_agent="reconciliation-job/2.0",
                endpoint=read_endpoints[burst_idx % 2],
                details={"latency_ms": 19},
            )
        )
        idx += 1

    return events


def _quality_proxy(alerts: list[dict[str, Any]]) -> float:
    if not alerts:
        return 1.0

    required = {
        "alert_id",
        "rule_id",
        "scenario_id",
        "severity",
        "summary",
        "evidence_event_ids",
        "mitre_attack",
        "recommended_actions",
    }
    complete = 0
    for alert in alerts:
        has_required = required.issubset(alert.keys())
        has_content = bool(alert.get("summary")) and bool(alert.get("mitre_attack")) and bool(alert.get("evidence_event_ids"))
        if has_required and has_content:
            complete += 1

    return complete / len(alerts)


def _evaluate_profile(
    *,
    profile: str,
    benign_events: list[dict[str, Any]],
    injected_events: list[dict[str, Any]],
    scenario_library_path: str,
    detection_config_path: str,
) -> dict[str, Any]:
    benign_alerts = run_detection_engine(
        events=benign_events,
        scenario_library_path=scenario_library_path,
        detection_config_path=detection_config_path,
        tuning_profile=profile,
    )
    injected_alerts = run_detection_engine(
        events=injected_events,
        scenario_library_path=scenario_library_path,
        detection_config_path=detection_config_path,
        tuning_profile=profile,
    )

    expected_scenarios = {"SCN-001", "SCN-002", "SCN-003", "SCN-004", "SCN-005", "SCN-006"}
    detected_scenarios = {alert["scenario_id"] for alert in injected_alerts}
    true_positive_proxy = len(expected_scenarios.intersection(detected_scenarios))
    false_positive_proxy = len(benign_alerts)

    denominator = true_positive_proxy + false_positive_proxy
    precision_proxy = true_positive_proxy / denominator if denominator else 0.0

    all_alerts = benign_alerts + injected_alerts
    reopen_rate_proxy = false_positive_proxy / max(1, false_positive_proxy + true_positive_proxy)

    return {
        "profile": profile,
        "benign_alert_count": false_positive_proxy,
        "injected_alert_count": len(injected_alerts),
        "detected_injected_scenarios": sorted(detected_scenarios),
        "true_positive_proxy": true_positive_proxy,
        "precision_proxy": round(precision_proxy, 4),
        "escalation_quality_proxy": round(_quality_proxy(all_alerts), 4),
        "reopen_rate_proxy": round(reopen_rate_proxy, 4),
        "benign_alerts_by_scenario": dict(Counter(alert["scenario_id"] for alert in benign_alerts)),
    }


def main() -> int:
    args = parse_args()

    benign_events = generate_events(
        total_events=args.benign_events,
        seed=args.seed,
        start_time=DEFAULT_START_TIME,
        config_path=args.simulation_config,
    )
    benign_events.extend(_build_benign_borderline_events())
    benign_events.sort(key=lambda item: item["timestamp"])
    injected_events = build_injected_scenario_events()

    baseline_metrics = _evaluate_profile(
        profile="baseline",
        benign_events=benign_events,
        injected_events=injected_events,
        scenario_library_path=args.scenario_library,
        detection_config_path=args.detection_config,
    )
    tuned_metrics = _evaluate_profile(
        profile="tuned",
        benign_events=benign_events,
        injected_events=injected_events,
        scenario_library_path=args.scenario_library,
        detection_config_path=args.detection_config,
    )

    baseline_counts = baseline_metrics["benign_alerts_by_scenario"]
    tuned_counts = tuned_metrics["benign_alerts_by_scenario"]

    comparison = {
        "scn_001_benign_reduction": baseline_counts.get("SCN-001", 0) - tuned_counts.get("SCN-001", 0),
        "scn_003_benign_reduction": baseline_counts.get("SCN-003", 0) - tuned_counts.get("SCN-003", 0),
        "scn_006_benign_reduction": baseline_counts.get("SCN-006", 0) - tuned_counts.get("SCN-006", 0),
        "precision_proxy_delta": round(
            tuned_metrics["precision_proxy"] - baseline_metrics["precision_proxy"],
            4,
        ),
        "reopen_rate_proxy_delta": round(
            tuned_metrics["reopen_rate_proxy"] - baseline_metrics["reopen_rate_proxy"],
            4,
        ),
    }

    output = {
        "kpi_definitions": {
            "precision_proxy": "unique_expected_scenarios_detected / (unique_expected_scenarios_detected + benign_alert_count)",
            "escalation_quality_proxy": "alerts_with_complete_handoff_fields / total_alerts",
            "reopen_rate_proxy": "benign_alert_count / (benign_alert_count + true_positive_proxy)",
        },
        "baseline": baseline_metrics,
        "tuned": tuned_metrics,
        "comparison": comparison,
    }

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(output, indent=2), encoding="utf-8")

    print(f"Wrote tuning metrics to {output_path}")
    print(f"Comparison summary: {comparison}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
