# I-008 Detection Tuning Report

## Method
- Benign dataset: synthetic normal trading/API activity + borderline operational patterns.
- Injected dataset: deterministic scenario injections covering SCN-001 to SCN-006.
- Profiles compared: `baseline` vs `tuned` from `config/detection_defaults.json`.

## KPI Definitions
- Precision proxy: `unique_expected_scenarios_detected / (unique_expected_scenarios_detected + benign_alert_count)`
- Escalation quality proxy: `alerts_with_complete_handoff_fields / total_alerts`
- Reopen rate proxy: `benign_alert_count / (benign_alert_count + true_positive_proxy)`

## Before/After Metrics
| Metric | Baseline | Tuned | Delta |
| --- | ---: | ---: | ---: |
| Benign alert count | 49 | 44 | -5 |
| True-positive proxy | 6 | 6 | 0 |
| Precision proxy | 0.1091 | 0.1200 | +0.0109 |
| Escalation quality proxy | 1.0000 | 1.0000 | 0 |
| Reopen rate proxy | 0.8909 | 0.8800 | -0.0109 |

## Rule-Level Improvements
- SCN-001 benign alerts: `20 -> 19` (reduction: 1)
- SCN-003 benign alerts: `3 -> 0` (reduction: 3)
- SCN-006 benign alerts: `1 -> 0` (reduction: 1)

At least two rules improved with measurable benign-alert reduction while maintaining injected scenario coverage.

## Reproducible Command
```bash
python3 scripts/evaluate_tuning.py --output reports/metrics/i008_tuning_metrics.json
```
