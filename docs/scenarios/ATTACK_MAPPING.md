# I-003 MITRE ATT&CK Mapping

## Mapping Notes
- Mapping is threat-analyst oriented for cloud/API abuse in trading operations.
- Some financial-loss workflows are represented using ATT&CK-adjacent exfiltration/impact techniques.

## Scenario-to-Technique Mapping
| Scenario | ATT&CK Technique | Why It Fits |
| --- | --- | --- |
| SCN-001 | T1550 Use Alternate Authentication Material | Stolen API keys are reused as alternate credentials. |
| SCN-001 | T1078 Valid Accounts | Activity occurs through legitimate account material. |
| SCN-002 | T1110 Brute Force | Failure burst across accounts from one source. |
| SCN-002 | T1078 Valid Accounts | Successful post-brute-force access path. |
| SCN-003 | T1098 Account Manipulation | Withdrawal abuse often requires account/key config changes. |
| SCN-003 | T1567 Exfiltration Over Web Service | Fund/data movement through API channels. |
| SCN-003 | T1078 Valid Accounts | Abuse performed with valid account context. |
| SCN-004 | T1565 Data Manipulation | Order-flow manipulation affects data integrity and market signals. |
| SCN-004 | T1499 Endpoint Denial of Service | Burst traffic/cancel storms can degrade endpoint availability. |
| SCN-004 | T1078 Valid Accounts | Bot/account credentials remain valid during abuse. |
| SCN-005 | T1528 Steal Application Access Token | Service token theft/use in cloud environments. |
| SCN-005 | T1550 Use Alternate Authentication Material | Reuse of stolen service/API auth artifacts. |
| SCN-005 | T1078 Valid Accounts | Attack traffic uses legitimate identities. |
| SCN-006 | T1213 Data from Information Repositories | Bulk endpoint enumeration targets account/position repositories. |
| SCN-006 | T1567 Exfiltration Over Web Service | Exfil-like behavior via API/web-service channels. |

## Analyst Use in This Lab
- These mappings feed detection metadata in I-004.
- Escalation handoffs should include at least one primary technique and rationale.
