# RB-002 Suspicious Login

## Scope
Use when login behavior indicates credential stuffing, brute force, or impossible-travel authentication.

## Triage Steps
1. Pull all auth events for source IP and target accounts over 30 minutes.
2. Count failures, distinct account targets, and success-after-failure patterns.
3. Identify whether MFA presence or bypass indicators appear.
4. Compare source IP/user-agent against known scanner and enterprise allowlists.
5. Tag probable compromised accounts and active sessions.

## Decision Gates
- Gate A: Failure burst only, no successful access?
  - Yes -> likely recon/noise; monitor and tune.
  - No -> continue.
- Gate B: Successful login after stuffing pattern?
  - Yes -> escalate with impacted accounts timeline.
  - No -> monitor and recommend controls.

## Escalation Criteria
- 20+ failures in 5 minutes from one source across multiple accounts.
- Successful login after brute-force indicators.
- Login from impossible travel pattern with privileged account.

## Authorized Containment Actions (L1)
- Temporary source-IP block/rate-limit request.
- Session kill for clearly impacted account(s).
- Mandatory password/API key reset trigger if approved.

## Escalate-Only Actions
- Identity provider policy redesign.
- Global auth control changes affecting production availability.
