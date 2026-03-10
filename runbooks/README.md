# SOC Runbooks

Runbooks for I-006 SOC L1 operations in digital-asset API/trading environments.

## Available Runbooks
- `RB-001-phishing-token-abuse.md`
- `RB-002-suspicious-login.md`
- `RB-003-api-key-misuse.md`
- `RB-004-malware-like-endpoint-signal.md`
- `RB-005-exfiltration-burst.md`

## Templates
- `templates/escalation_handoff_template.md`
- `templates/containment_action_matrix.md`

## Usage
1. Pick runbook by dominant signal type.
2. Execute triage steps in order.
3. Use decision gates to classify severity and action path.
4. If escalation criteria met, use handoff template with complete evidence.
