# I-008 False-Positive Analysis

## Observed Root Causes
1. SCN-001 (API key geo replay)
- Root cause: multi-region failover and platform egress shifts can look like replay when only 2-country threshold is used.
- Evidence: borderline benign key activity with expected operations user-agent.

2. SCN-003 (withdrawal chain)
- Root cause: first-withdrawal heuristic over-triggered during approved treasury operations.
- Evidence: CASE-003 (`reports/cases/CASE-003-withdrawal-fp.md`) showed approved whitelisted destination and change-window alignment.

3. SCN-006 (read burst)
- Root cause: reconciliation jobs can generate bursty read patterns with low latency.
- Evidence: borderline benign workload exceeded baseline threshold but was operationally expected.

## Tuning Decisions
- SCN-001: raised minimum distinct countries from 2 to 3.
- SCN-003: disabled first-withdrawal-only trigger in tuned profile; require high amount or auth-failure context.
- SCN-006: increased minimum read request volume and endpoint variety threshold.

## Expected Impact
- Lower benign alert volume for border-case operational behaviors.
- Maintained injected scenario detection coverage across SCN-001..SCN-006.
- Improved precision proxy with lower reopen-rate proxy.
