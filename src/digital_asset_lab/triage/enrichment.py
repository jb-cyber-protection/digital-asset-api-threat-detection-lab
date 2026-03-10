"""Alert enrichment utilities for SOC L1 triage workflows."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

SEVERITY_ORDER = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

SEVERITY_REVERSE = {value: key for key, value in SEVERITY_ORDER.items()}

FALSE_POSITIVE_HINTS = {
    "SCN-001": [
        "Check whether the key is legitimately used by multi-region failover infrastructure.",
        "Verify if VPN/proxy egress changes are expected from platform operations.",
    ],
    "SCN-002": [
        "Confirm whether source IP belongs to known scanning/QA infrastructure.",
        "Correlate with temporary auth instability that could inflate failure counts.",
    ],
    "SCN-003": [
        "Validate whether withdrawal was part of scheduled treasury rebalancing.",
        "Check if geo shift is due to approved operations travel or bastion routing changes.",
    ],
    "SCN-004": [
        "Confirm whether a strategy rollout or volatility event explains burst behavior.",
        "Compare with exchange outage/retry storms before classifying as malicious.",
    ],
    "SCN-005": [
        "Confirm cloud deployment or autoscaling events for region/user-agent changes.",
        "Check IAM/service-account rotation logs for approved token replacement.",
    ],
    "SCN-006": [
        "Validate whether reconciliation, audit, or reporting jobs caused read bursts.",
        "Exclude maintenance windows with expected high-frequency read polling.",
    ],
}


def _parse_ts(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _shares_alert_entity(event: dict[str, Any], entities: dict[str, Any]) -> bool:
    keys = {
        "account_id": "account_ids",
        "api_key_id": "api_key_ids",
        "bot_id": "bot_ids",
        "ip": "source_ips",
        "ip_country": "countries",
        "region": "regions",
    }

    for event_field, entity_field in keys.items():
        value = event.get(event_field)
        if value and value in set(entities.get(entity_field, [])):
            return True
    return False


def _build_timeline(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    timeline: list[dict[str, Any]] = []
    for event in sorted(events, key=lambda item: item["timestamp"]):
        details = event.get("details") if isinstance(event.get("details"), dict) else {}
        timeline.append(
            {
                "timestamp": event["timestamp"],
                "event_id": event.get("event_id"),
                "event_type": event.get("event_type"),
                "account_id": event.get("account_id"),
                "api_key_id": event.get("api_key_id"),
                "ip": event.get("ip"),
                "ip_country": event.get("ip_country"),
                "endpoint": event.get("endpoint"),
                "detail_excerpt": {
                    "status": details.get("status"),
                    "failure_reason": details.get("failure_reason"),
                    "amount": details.get("amount"),
                    "asset": details.get("asset"),
                },
            }
        )
    return timeline


def _collect_entity_context(events: list[dict[str, Any]]) -> dict[str, list[str]]:
    return {
        "account_ids": sorted({str(event.get("account_id")) for event in events if event.get("account_id")}),
        "api_key_ids": sorted({str(event.get("api_key_id")) for event in events if event.get("api_key_id")}),
        "bot_ids": sorted({str(event.get("bot_id")) for event in events if event.get("bot_id")}),
        "source_ips": sorted({str(event.get("ip")) for event in events if event.get("ip")}),
        "countries": sorted({str(event.get("ip_country")) for event in events if event.get("ip_country")}),
        "regions": sorted({str(event.get("region")) for event in events if event.get("region")}),
        "endpoints": sorted({str(event.get("endpoint")) for event in events if event.get("endpoint")}),
        "user_agents": sorted({str(event.get("user_agent")) for event in events if event.get("user_agent")}),
    }


def _recommend_severity(alert: dict[str, Any], correlated_events: list[dict[str, Any]]) -> str:
    score = SEVERITY_ORDER.get(str(alert.get("severity", "medium")).lower(), 2)
    event_types = [str(event.get("event_type")) for event in correlated_events]

    if "withdrawal.request" in event_types:
        score += 1

    failure_count = event_types.count("auth.login.failure")
    if failure_count >= 10 and "auth.login.success" in event_types:
        score += 1

    if len(correlated_events) <= 3 and score > SEVERITY_ORDER["medium"]:
        score -= 1

    score = min(max(score, 1), 4)
    return SEVERITY_REVERSE[score]


def enrich_alert(
    alert: dict[str, Any],
    events: list[dict[str, Any]],
) -> dict[str, Any]:
    entities = alert.get("affected_entities", {})
    evidence_ids = set(alert.get("evidence_event_ids", []))

    first_seen = _parse_ts(str(alert["first_seen"]))
    last_seen = _parse_ts(str(alert["last_seen"]))
    window_start = first_seen - timedelta(minutes=5)
    window_end = last_seen + timedelta(minutes=5)

    correlated_events: list[dict[str, Any]] = []
    for event in events:
        event_ts = _parse_ts(str(event["timestamp"]))
        if not (window_start <= event_ts <= window_end):
            continue
        if event.get("event_id") in evidence_ids or _shares_alert_entity(event, entities):
            correlated_events.append(event)

    correlated_events = sorted(
        correlated_events,
        key=lambda item: item["timestamp"],
    )

    if not correlated_events:
        correlated_events = [event for event in events if event.get("event_id") in evidence_ids]

    timeline = _build_timeline(correlated_events[:40])
    entity_context = _collect_entity_context(correlated_events)
    severity_recommendation = _recommend_severity(alert, correlated_events)

    scenario_id = str(alert.get("scenario_id"))
    false_positive_hints = FALSE_POSITIVE_HINTS.get(
        scenario_id,
        ["Confirm baseline behavior for the affected entities before escalation."],
    )

    escalation_handoff = {
        "timeline_window_utc": {
            "start": window_start.isoformat(),
            "end": window_end.isoformat(),
        },
        "scope": {
            "accounts": entity_context["account_ids"],
            "api_keys": entity_context["api_key_ids"],
            "bots": entity_context["bot_ids"],
        },
        "iocs": {
            "ips": entity_context["source_ips"],
            "countries": entity_context["countries"],
            "endpoints": entity_context["endpoints"],
            "event_ids": [item.get("event_id") for item in correlated_events[:20]],
        },
        "actions_taken_l1": [
            "Alert validated against scenario rule",
            "Entity and geo context enriched",
            "Prepared escalation summary with evidence IDs",
        ],
    }

    return {
        "ticket_id": f"triage-{alert['alert_id']}",
        "alert_id": alert["alert_id"],
        "rule_id": alert["rule_id"],
        "scenario_id": scenario_id,
        "status": "ready_for_l2_review",
        "severity_recommendation": severity_recommendation,
        "original_severity": alert.get("severity"),
        "confidence": alert.get("confidence"),
        "triage_summary": (
            f"{alert['title']} | {len(correlated_events)} correlated events | "
            f"recommended severity: {severity_recommendation}"
        ),
        "timeline": timeline,
        "entity_context": entity_context,
        "iocs": {
            "ip_addresses": entity_context["source_ips"],
            "api_keys": entity_context["api_key_ids"],
            "accounts": entity_context["account_ids"],
            "countries": entity_context["countries"],
            "regions": entity_context["regions"],
        },
        "false_positive_hints": false_positive_hints,
        "escalation_handoff": escalation_handoff,
    }


def enrich_alerts(alerts: list[dict[str, Any]], events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [enrich_alert(alert, events) for alert in alerts]
