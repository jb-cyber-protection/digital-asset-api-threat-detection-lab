"""Alert schema for the rule-based detection engine."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class Alert:
    alert_id: str
    rule_id: str
    scenario_id: str
    title: str
    severity: str
    confidence: float
    first_seen: str
    last_seen: str
    event_count: int
    summary: str
    affected_entities: dict[str, Any]
    evidence_event_ids: list[str]
    mitre_attack: list[dict[str, str]]
    recommended_actions: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "rule_id": self.rule_id,
            "scenario_id": self.scenario_id,
            "title": self.title,
            "severity": self.severity,
            "confidence": round(self.confidence, 3),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "event_count": self.event_count,
            "summary": self.summary,
            "affected_entities": self.affected_entities,
            "evidence_event_ids": self.evidence_event_ids,
            "mitre_attack": self.mitre_attack,
            "recommended_actions": self.recommended_actions,
        }
