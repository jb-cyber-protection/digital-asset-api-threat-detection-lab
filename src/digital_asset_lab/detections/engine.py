"""Detection engine orchestrator for scenario-based rules."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

from digital_asset_lab.detections.rules import (
    detect_scn_001,
    detect_scn_002,
    detect_scn_003,
    detect_scn_004,
    detect_scn_005,
    detect_scn_006,
)
from digital_asset_lab.detections.schema import Alert

DEFAULT_DETECTION_CONFIG_PATH = "config/detection_defaults.json"

RuleFn = Callable[[list[dict[str, Any]], dict[str, Any], dict[str, Any]], list[Alert]]

RULES: dict[str, RuleFn] = {
    "SCN-001": detect_scn_001,
    "SCN-002": detect_scn_002,
    "SCN-003": detect_scn_003,
    "SCN-004": detect_scn_004,
    "SCN-005": detect_scn_005,
    "SCN-006": detect_scn_006,
}

SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
}


def load_scenario_map(scenario_library_path: str | Path) -> dict[str, dict[str, Any]]:
    payload = json.loads(Path(scenario_library_path).read_text(encoding="utf-8"))
    return {scenario["scenario_id"]: scenario for scenario in payload["scenarios"]}


def load_detection_profile(
    detection_config_path: str | Path = DEFAULT_DETECTION_CONFIG_PATH,
    tuning_profile: str = "",
) -> dict[str, dict[str, Any]]:
    payload = json.loads(Path(detection_config_path).read_text(encoding="utf-8"))
    profile_name = tuning_profile or payload.get("active_profile", "tuned")
    profiles = payload.get("profiles", {})
    return profiles.get(profile_name, {})


def run_detection_engine(
    events: list[dict[str, Any]],
    scenario_library_path: str | Path,
    detection_config_path: str | Path = DEFAULT_DETECTION_CONFIG_PATH,
    tuning_profile: str = "",
) -> list[dict[str, Any]]:
    scenario_map = load_scenario_map(scenario_library_path)
    detection_profile = load_detection_profile(detection_config_path, tuning_profile)

    alerts: list[Alert] = []
    for scenario_id, rule_fn in RULES.items():
        scenario = scenario_map.get(scenario_id)
        if not scenario:
            continue
        rule_config = detection_profile.get(scenario_id, {})
        alerts.extend(rule_fn(events, scenario, rule_config))

    alerts.sort(
        key=lambda alert: (
            SEVERITY_ORDER.get(alert.severity, 10),
            alert.first_seen,
            alert.scenario_id,
            alert.alert_id,
        )
    )
    return [alert.to_dict() for alert in alerts]
