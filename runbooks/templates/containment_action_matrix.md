# Containment Action Matrix

| Action | L1 Authorized | Escalate-Only | Notes |
| --- | --- | --- | --- |
| Temporarily disable API key | Yes (policy-bound) |  | Use when compromise confidence is high |
| Kill active sessions | Yes (policy-bound) |  | Coordinate with auth logs for scope |
| Temporary IP block/rate-limit | Yes |  | Apply with expiry + review |
| EDR host isolation | Yes (if delegated) |  | For malware-like endpoint signals |
| Permanent IAM role/key redesign |  | Yes | Requires platform/security engineering approval |
| Withdrawal reversal / financial settlement changes |  | Yes | Requires treasury + legal approval |
| Global auth policy changes |  | Yes | Requires change-management approval |
| Regulatory notification |  | Yes | Compliance/legal owned |
