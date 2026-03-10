"""Detection rules mapped to I-003 threat scenarios."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any

from digital_asset_lab.detections.schema import Alert

READ_ENDPOINTS = {"/v1/orders/open", "/v1/positions", "/v1/balance", "/v1/market/ticker"}


def _ts(event: dict[str, Any]) -> datetime:
    return datetime.fromisoformat(str(event["timestamp"]))


def _severity_from_priority(priority: str) -> str:
    mapping = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
    }
    return mapping.get(priority.lower(), "medium")


def _collect_entities(events: list[dict[str, Any]]) -> dict[str, Any]:
    account_ids = sorted({event.get("account_id") for event in events if event.get("account_id")})
    api_keys = sorted({event.get("api_key_id") for event in events if event.get("api_key_id")})
    bot_ids = sorted({event.get("bot_id") for event in events if event.get("bot_id")})
    ips = sorted({event.get("ip") for event in events if event.get("ip")})
    countries = sorted({event.get("ip_country") for event in events if event.get("ip_country")})
    regions = sorted({event.get("region") for event in events if event.get("region")})

    return {
        "account_ids": account_ids,
        "api_key_ids": api_keys,
        "bot_ids": bot_ids,
        "source_ips": ips,
        "countries": countries,
        "regions": regions,
    }


def _build_alert(
    *,
    scenario: dict[str, Any],
    rule_id: str,
    title: str,
    summary: str,
    confidence: float,
    matched_events: list[dict[str, Any]],
) -> Alert:
    matched_events = sorted(matched_events, key=_ts)
    first_event = matched_events[0]
    last_event = matched_events[-1]

    return Alert(
        alert_id=f"al-{scenario['scenario_id'].lower()}-{first_event['event_id']}",
        rule_id=rule_id,
        scenario_id=scenario["scenario_id"],
        title=title,
        severity=_severity_from_priority(scenario.get("priority", "medium")),
        confidence=confidence,
        first_seen=str(first_event["timestamp"]),
        last_seen=str(last_event["timestamp"]),
        event_count=len(matched_events),
        summary=summary,
        affected_entities=_collect_entities(matched_events),
        evidence_event_ids=[str(event.get("event_id")) for event in matched_events[:10]],
        mitre_attack=scenario.get("mitre_attack", []),
        recommended_actions=scenario.get("expected_analyst_response", []),
    )


def detect_scn_001(events: list[dict[str, Any]], scenario: dict[str, Any]) -> list[Alert]:
    alerts: list[Alert] = []
    by_key: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for event in events:
        key = event.get("api_key_id")
        if key:
            by_key[str(key)].append(event)

    window = timedelta(minutes=10)
    risky_types = {"api_key.used", "order.create", "order.cancel", "withdrawal.request"}

    for api_key_id, key_events in by_key.items():
        key_events.sort(key=_ts)
        for idx, event in enumerate(key_events):
            end_ts = _ts(event)
            start_ts = end_ts - window
            matched = [
                item
                for item in key_events[: idx + 1]
                if start_ts <= _ts(item) <= end_ts
            ]

            countries = {item.get("ip_country") for item in matched if item.get("ip_country")}
            has_failure = any(item.get("event_type") == "auth.login.failure" for item in matched)
            has_risky = any(item.get("event_type") in risky_types for item in matched)
            if len(countries) < 2 or not has_failure or not has_risky:
                continue

            alerts.append(
                _build_alert(
                    scenario=scenario,
                    rule_id="RULE-SCN-001-API-KEY-GEO",
                    title="API key replay from multiple geographies",
                    summary=(
                        f"api_key_id {api_key_id} appeared across {len(countries)} countries "
                        f"with failed authentication activity in a 10-minute window."
                    ),
                    confidence=0.9,
                    matched_events=matched,
                )
            )
            break

    return alerts


def detect_scn_002(events: list[dict[str, Any]], scenario: dict[str, Any]) -> list[Alert]:
    alerts: list[Alert] = []
    by_ip: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for event in events:
        if event.get("event_type") in {"auth.login.failure", "auth.login.success"} and event.get("ip"):
            by_ip[str(event["ip"])].append(event)

    window = timedelta(minutes=5)

    for ip_addr, ip_events in by_ip.items():
        ip_events.sort(key=_ts)
        failures = [event for event in ip_events if event.get("event_type") == "auth.login.failure"]

        for idx, event in enumerate(failures):
            end_ts = _ts(event)
            start_ts = end_ts - window
            failure_window = [
                item
                for item in failures[: idx + 1]
                if start_ts <= _ts(item) <= end_ts
            ]
            if len(failure_window) < 20:
                continue

            distinct_accounts = {
                item.get("account_id")
                for item in failure_window
                if item.get("account_id")
            }
            if len(distinct_accounts) < 5:
                continue

            success_window = [
                item
                for item in ip_events
                if item.get("event_type") == "auth.login.success"
                and start_ts <= _ts(item) <= end_ts + window
            ]
            if not success_window:
                continue

            matched = failure_window + success_window
            alerts.append(
                _build_alert(
                    scenario=scenario,
                    rule_id="RULE-SCN-002-CRED-STUFFING",
                    title="Credential stuffing pattern detected",
                    summary=(
                        f"IP {ip_addr} generated {len(failure_window)} authentication failures "
                        f"across {len(distinct_accounts)} accounts followed by successful login(s)."
                    ),
                    confidence=0.95,
                    matched_events=matched,
                )
            )
            break

    return alerts


def detect_scn_003(events: list[dict[str, Any]], scenario: dict[str, Any]) -> list[Alert]:
    alerts: list[Alert] = []
    by_key_countries: dict[str, set[str]] = defaultdict(set)
    by_key_withdrawals: dict[str, list[float]] = defaultdict(list)
    recent_failures_by_key: dict[str, list[dict[str, Any]]] = defaultdict(list)

    thresholds = {
        "BTC": 0.12,
        "ETH": 0.8,
        "SOL": 25.0,
        "USDT": 5000.0,
    }

    sorted_events = sorted(events, key=_ts)
    for event in sorted_events:
        key = str(event.get("api_key_id", ""))
        country = str(event.get("ip_country", ""))
        event_type = str(event.get("event_type"))

        if key and country:
            by_key_countries[key].add(country)

        if event_type == "auth.login.failure" and key:
            recent_failures_by_key[key].append(event)
            continue

        if event_type != "withdrawal.request" or not key:
            continue

        details = event.get("details", {})
        asset = str(details.get("asset", "USDT"))
        amount = float(details.get("amount", 0))
        known_threshold = thresholds.get(asset, thresholds["USDT"])
        previous_withdrawals = by_key_withdrawals[key]

        previous_countries = {
            previous_event.get("ip_country")
            for previous_event in sorted_events
            if previous_event.get("api_key_id") == key
            and previous_event.get("event_id") != event.get("event_id")
            and _ts(previous_event) < _ts(event)
            and previous_event.get("ip_country")
        }
        is_new_country = country not in previous_countries

        recent_failures = [
            failure
            for failure in recent_failures_by_key[key]
            if _ts(event) - timedelta(minutes=30) <= _ts(failure) <= _ts(event)
        ]
        first_withdrawal = len(previous_withdrawals) == 0
        is_high_amount = amount >= known_threshold

        if is_new_country and (first_withdrawal or is_high_amount or bool(recent_failures)):
            matched = recent_failures[-3:] + [event]
            alerts.append(
                _build_alert(
                    scenario=scenario,
                    rule_id="RULE-SCN-003-WITHDRAWAL-CHAIN",
                    title="Suspicious withdrawal chain detected",
                    summary=(
                        f"Withdrawal of {amount} {asset} from new country {country} for key {key}; "
                        "context includes unusual amount and/or failed auth prelude."
                    ),
                    confidence=0.92,
                    matched_events=matched,
                )
            )

        previous_withdrawals.append(amount)

    return alerts


def detect_scn_004(events: list[dict[str, Any]], scenario: dict[str, Any]) -> list[Alert]:
    alerts: list[Alert] = []
    by_bot: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for event in events:
        if event.get("event_type") in {"order.create", "order.cancel"} and event.get("bot_id"):
            by_bot[str(event["bot_id"])].append(event)

    window = timedelta(minutes=10)

    for bot_id, bot_events in by_bot.items():
        bot_events.sort(key=_ts)
        start_idx = 0
        for end_idx, end_event in enumerate(bot_events):
            end_ts = _ts(end_event)
            while _ts(bot_events[start_idx]) < end_ts - window:
                start_idx += 1

            matched = bot_events[start_idx : end_idx + 1]
            total = len(matched)
            if total < 120:
                continue

            create_count = sum(1 for event in matched if event.get("event_type") == "order.create")
            cancel_count = sum(1 for event in matched if event.get("event_type") == "order.cancel")
            ratio = cancel_count / max(1, create_count)
            user_agents = {event.get("user_agent") for event in matched if event.get("user_agent")}

            if ratio < 1.3 or len(user_agents) < 2:
                continue

            alerts.append(
                _build_alert(
                    scenario=scenario,
                    rule_id="RULE-SCN-004-ORDER-BURST",
                    title="Order create/cancel burst inconsistent with baseline",
                    summary=(
                        f"bot_id {bot_id} produced {total} order events in 10 minutes "
                        f"with cancel/create ratio {ratio:.2f} and context shift in user-agent."
                    ),
                    confidence=0.88,
                    matched_events=matched,
                )
            )
            break

    return alerts


def detect_scn_005(events: list[dict[str, Any]], scenario: dict[str, Any]) -> list[Alert]:
    alerts: list[Alert] = []
    by_key: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for event in events:
        if event.get("event_type") == "api_key.used" and event.get("api_key_id"):
            by_key[str(event["api_key_id"])].append(event)

    window = timedelta(minutes=20)
    for api_key_id, key_events in by_key.items():
        key_events.sort(key=_ts)
        start_idx = 0

        for end_idx, end_event in enumerate(key_events):
            end_ts = _ts(end_event)
            while _ts(key_events[start_idx]) < end_ts - window:
                start_idx += 1

            matched = key_events[start_idx : end_idx + 1]
            if len(matched) < 12:
                continue

            regions = {event.get("region") for event in matched if event.get("region")}
            user_agents = {event.get("user_agent") for event in matched if event.get("user_agent")}
            has_read = any(event.get("endpoint") in READ_ENDPOINTS for event in matched)
            has_write = any(event.get("endpoint") not in READ_ENDPOINTS for event in matched)

            if len(regions) < 2 or len(user_agents) < 2 or not (has_read and has_write):
                continue

            alerts.append(
                _build_alert(
                    scenario=scenario,
                    rule_id="RULE-SCN-005-CLOUD-TOKEN",
                    title="Cloud/service token misuse signal",
                    summary=(
                        f"api_key_id {api_key_id} used across {len(regions)} regions with user-agent "
                        "shift and mixed read/write behavior inside 20 minutes."
                    ),
                    confidence=0.86,
                    matched_events=matched,
                )
            )
            break

    return alerts


def detect_scn_006(events: list[dict[str, Any]], scenario: dict[str, Any]) -> list[Alert]:
    alerts: list[Alert] = []
    by_key: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for event in events:
        if event.get("event_type") == "api_key.used" and event.get("api_key_id"):
            by_key[str(event["api_key_id"])].append(event)

    window = timedelta(minutes=5)
    for api_key_id, key_events in by_key.items():
        key_events.sort(key=_ts)
        start_idx = 0

        for end_idx, end_event in enumerate(key_events):
            end_ts = _ts(end_event)
            while _ts(key_events[start_idx]) < end_ts - window:
                start_idx += 1

            matched = key_events[start_idx : end_idx + 1]
            read_events = [event for event in matched if event.get("endpoint") in READ_ENDPOINTS]
            if len(read_events) < 150:
                continue

            endpoint_variety = {event.get("endpoint") for event in read_events}
            low_latency = sum(
                1
                for event in read_events
                if isinstance(event.get("details"), dict)
                and float(event.get("details", {}).get("latency_ms", 9999)) <= 20
            )
            if len(endpoint_variety) < 3 or low_latency < int(len(read_events) * 0.4):
                continue

            alerts.append(
                _build_alert(
                    scenario=scenario,
                    rule_id="RULE-SCN-006-READ-BURST",
                    title="Read-heavy API enumeration burst",
                    summary=(
                        f"api_key_id {api_key_id} issued {len(read_events)} read-endpoint requests in 5 minutes "
                        "with repetitive low-latency pattern."
                    ),
                    confidence=0.84,
                    matched_events=read_events,
                )
            )
            break

    return alerts
