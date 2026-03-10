# RB-001 Phishing-Like Token Abuse

## Scope
Use when access tokens/API material appear compromised via phishing-like workflows (unexpected user-agent, geo shift, key replay).

## Triage Steps
1. Validate alert context: affected `api_key_id`, `account_id`, first/last seen, scenario mapping.
2. Build 15-minute timeline around first suspicious event.
3. Correlate token use with `auth.login.failure` and subsequent `api_key.used` write actions.
4. Confirm if IP/country/user-agent are expected from operations baseline.
5. Check if key was used for `order.create`, `withdrawal.request`, or privileged endpoints.

## Decision Gates
- Gate A: Token context expected and verified by owner/on-call?
  - Yes -> close as benign with evidence.
  - No -> continue.
- Gate B: Privileged or fund-impacting endpoint access observed?
  - Yes -> escalate as `high`/`critical`.
  - No -> continue with monitoring decision.

## Escalation Criteria
- Key replay across geographies within short time window.
- Token used for withdrawal or high-risk trade actions.
- Inability to validate session ownership within SLA.

## Authorized Containment Actions (L1)
- Temporarily disable affected API key if policy permits.
- Force session invalidation for impacted user/session IDs.
- Apply temporary source-IP block for observed malicious indicators.

## Escalate-Only Actions
- Long-term credential rotation strategy changes.
- Account permission redesign / IAM policy changes.
- Fund movement reversal workflows.
