# CASE-002 API Key Replay Across Geographies (True Positive)

## Case Summary
- Case ID: CASE-002
- Source Alert: `al-scn-001-evt-00000026`
- Scenario: SCN-001 API Key Replay From New Geography
- Severity: High
- Final Disposition: **True Positive**

## Investigation Timeline (UTC)
- 2026-01-01T00:00:03.317Z: First suspicious `api_key.used` event for `key-ar-007`.
- 2026-01-01T00:10:00Z: Activity correlated across `NL`, `SG`, `US`, and `IE` in short window.
- 2026-01-01T00:12:00Z: Auth anomalies observed (`auth.login.failure` and unusual session behavior).
- 2026-01-01T00:13:00Z: Key suspended; escalation sent to L2.

## Evidence Snapshot
- Evidence file: `reports/incidents/evidence/CASE-002-evidence.json`
- Key indicators:
  - Countries observed: `NL`, `SG`, `US`, `IE`
  - Mixed endpoint behavior including trading path activity
  - Authentication anomalies in same activity window

## Ticket Narrative
The key showed multi-geo replay with endpoint behavior shift and authentication anomalies. Correlation quality was high and not explained by expected failover or deployment changes, so the case was escalated as confirmed misuse.

## Escalation Notes
- L1 provided sequence of evidence event IDs and context entities.
- L2 tasked with broader key compromise impact analysis and credential reset plan.
