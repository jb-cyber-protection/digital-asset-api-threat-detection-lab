# CASE-003 Withdrawal Alert (False Positive)

## Case Summary
- Case ID: CASE-003
- Source Alert: `al-scn-003-evt-00000091`
- Scenario: SCN-003 Suspicious Withdrawal Request Chain
- Severity: Critical (original alert)
- Final Disposition: **False Positive**

## Investigation Timeline (UTC)
- 2026-01-01T00:12:22.422Z: Withdrawal alert triggered for `key-mo-001` (`SOL` withdrawal).
- 2026-01-01T00:14:00Z: L1 correlated with treasury rebalancing change window.
- 2026-01-01T00:16:00Z: Destination confirmed as approved `whitelisted_hot_wallet`.
- 2026-01-01T00:18:00Z: Incident downgraded and closed as false positive with tuning recommendation.

## Evidence Snapshot
- Evidence file: `reports/incidents/evidence/CASE-003-evidence.json`
- Key indicators:
  - Withdrawal destination type: `whitelisted_hot_wallet`
  - Risk score: `0.039` (low)
  - Operation aligned to planned treasury workflow

## Ticket Narrative
Although the detector raised a critical signal, analyst validation found an approved rebalancing operation with expected destination controls and documented change context. No malicious indicators remained after enrichment and business validation.

## Escalation Notes
- No escalation to IR required after business confirmation.
- Added tuning recommendation: reduce SCN-003 sensitivity for low-risk, whitelisted treasury windows.
