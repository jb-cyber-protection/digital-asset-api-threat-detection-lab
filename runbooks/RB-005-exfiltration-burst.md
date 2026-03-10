# RB-005 Exfiltration-Like Traffic Burst

## Scope
Use when read-heavy API patterns suggest unauthorized data collection or extraction.

## Triage Steps
1. Quantify read endpoint burst size and duration per `api_key_id`.
2. Validate endpoint variety (`/positions`, `/balance`, `/orders/open`, etc.).
3. Check latency/repetition patterns indicating scripted extraction.
4. Correlate source context (country/region/user-agent) with baseline.
5. Estimate exposed data scope by account and endpoint.

## Decision Gates
- Gate A: Burst explained by scheduled reconciliation/reporting jobs?
  - Yes -> document expected workload.
  - No -> continue.
- Gate B: New source context + high-volume read extraction?
  - Yes -> escalate as potential exfiltration.
  - No -> medium with tuning recommendation.

## Escalation Criteria
- 150+ read requests in 5 minutes from one key with unusual context.
- Multiple sensitive repository endpoints accessed in burst.
- No approved job or operational explanation.

## Authorized Containment Actions (L1)
- Apply temporary throttle/rate-limit to offending key.
- Disable key if extraction risk is high and playbook permits.

## Escalate-Only Actions
- Legal/regulatory notification decisions.
- Cross-system impact declaration and external stakeholder comms.
