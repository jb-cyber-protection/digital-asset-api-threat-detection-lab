# CASE-001 Suspicious Withdrawal Chain (True Positive)

## Case Summary
- Case ID: CASE-001
- Source Alert: `al-scn-003-evt-00000021`
- Scenario: SCN-003 Suspicious Withdrawal Request Chain
- Severity: Critical
- Final Disposition: **True Positive**

## Investigation Timeline (UTC)
- 2026-01-01T00:00:02.715Z: `withdrawal.request` detected for `key-ar-002` (`acct-ar-002`) from `IE`.
- 2026-01-01T00:02:00Z: L1 validated destination and amount against account baseline.
- 2026-01-01T00:04:00Z: Key was temporarily disabled per authorized containment action.
- 2026-01-01T00:05:00Z: Escalated to L2/IR with full IOC package.

## Evidence Snapshot
- Evidence file: `reports/incidents/evidence/CASE-001-evidence.json`
- Key indicators:
  - Withdrawal amount: `0.121166 BTC`
  - Source geo: `IE` (novel for key)
  - Risk score: `0.162`

## Ticket Narrative
L1 confirmed withdrawal behavior was inconsistent with recent key activity and regional baseline. Given high fund-impact potential and no operational justification, containment was executed and case escalated as critical.

## Escalation Notes
- Handoff complete with timeline, IOC list, scope (`acct-ar-002`, `key-ar-002`), and action log.
- L2 requested to validate downstream transaction controls and expanded account compromise scope.
