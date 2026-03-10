# RB-003 API Key Misuse

## Scope
Use when a key shows abnormal endpoint usage, geo shift, or profile-deviant behavior.

## Triage Steps
1. Retrieve full key activity timeline (`api_key.used`, order, withdrawal, auth events).
2. Compare endpoint mix (read vs write) with historical baseline.
3. Evaluate geographic/user-agent novelty for the key.
4. Check whether key is tied to automated bot profile and expected cadence.
5. Determine blast radius: accounts, symbols, order IDs, withdrawals.

## Decision Gates
- Gate A: Behavior explained by deployment/maintenance window?
  - Yes -> document and close/tune.
  - No -> continue.
- Gate B: Misuse includes write/fund-impacting actions?
  - Yes -> escalate urgently.
  - No -> medium severity with close monitoring.

## Escalation Criteria
- Key performs unauthorized write actions.
- Country/region shift plus key privilege use.
- Correlation with suspicious login/token abuse.

## Authorized Containment Actions (L1)
- Revoke or suspend impacted key if authorized.
- Restrict key to read-only temporarily where controls exist.

## Escalate-Only Actions
- Permanent entitlement redesign.
- Broad credential migration across multiple services.
