# Project Idea: Digital Asset API Threat Detection Lab

## 1) Goal
Build a practical SOC-focused lab that proves you understand both:
- Digital-asset exchange/trading workflows
- Security monitoring and incident triage in a high-availability trading environment

## 2) Core Concept
Simulate a crypto trading operation where algorithmic bots interact with exchange APIs (REST/WebSocket).  
Generate both normal and malicious activity, then detect, triage, and escalate threats using SOC L1 workflows.

## 3) Why This Fits the Role
The project directly maps to Keyrock SOC L1 expectations:
- Monitoring and triage of cloud/API/security alerts
- Initial investigation and context enrichment
- Clear escalation handoff quality
- Runbook-driven execution
- Threat-aware analysis using MITRE ATT&CK mapping
- Detection tuning and operational hygiene

## 4) Lab Components
- **Market + Trading Activity Simulator**
  - Synthetic market events (price moves, volatility spikes)
  - Algorithmic bot behavior (market making, momentum, arbitrage-like request patterns)
- **Exchange API Log Generator**
  - Auth events, order placement/cancel, key usage, withdrawal actions, IP/device metadata
- **Threat Scenario Injector**
  - API key abuse, brute-force login attempts, impossible travel, suspicious withdrawal behavior, exfil-like API bursts
- **Detection Layer**
  - Rule-based detections mapped to ATT&CK
  - Severity model and confidence tags
- **SOC Triage Outputs**
  - Alert enrichment, timelines, IOC extraction, escalation notes
- **Runbooks + Handover**
  - SOP playbooks and shift handover templates

## 5) Demonstrated Knowledge Areas
- **Digital assets**
  - Exchange API operations, custody-sensitive actions, key/token misuse impact
  - 24/7 operational risk in global trading environments
- **Algorithmic trading**
  - Distinguishing expected high-frequency bot behavior from malicious anomalies
  - Understanding order/position lifecycle signals in detection context
- **SOC operations**
  - Triage discipline, escalation quality, false-positive management

## 6) Success Criteria
- A runnable demo that produces realistic alerts from simulated trading/API data
- At least 5 threat scenarios with documented detections and ATT&CK mapping
- Example incident tickets with complete L1-to-L2 handoff quality
- Clear portfolio narrative showing what was built, why it matters, and what was learned
