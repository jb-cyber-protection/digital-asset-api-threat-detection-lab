# Issue Backlog

Issues start in `BACKLOG` and move through `IN_PROGRESS` -> `DONE` when executed.

## Execution Order
1. I-001
2. I-002
3. I-003
4. I-004
5. I-005
6. I-006
7. I-007
8. I-008
9. I-009
10. I-010

---

## I-001 - Repo Scaffold and Standards
- **Status:** DONE (2026-03-10)
- **Completion Note:** Repository scaffold, baseline tooling, setup instructions, and issue governance docs added.
- **Goal:** Create clean project structure, tooling baseline, and contribution conventions.
- **Deliverables:**
  - Folder layout for simulator, detections, runbooks, reports, and tests
  - Initial configuration files and README update
  - Definition of done/checklist for future issues
- **Acceptance Criteria:**
  - Project structure is consistent and documented
  - Every next issue has a target location in the repo
  - Basic local run instructions exist

## I-002 - Trading/API Activity Simulator
- **Status:** DONE (2026-03-10)
- **Completion Note:** Added config-driven 10k+ event simulator with distinct bot profiles, reproducible seed/start-time generation, tests, and simulator spec docs.
- **Goal:** Generate realistic digital-asset trading and API logs.
- **Deliverables:**
  - Synthetic event generator for auth, orders, cancels, key usage, and withdrawals
  - Profiles for normal bots (market maker, momentum, arbitrage-like patterns)
  - Repeatable seed-based generation
- **Acceptance Criteria:**
  - Dataset includes at least 10k events with timestamps
  - Normal behavior patterns are distinguishable by profile
  - Output format supports downstream detections

## I-003 - Threat Scenario Library and ATT&CK Mapping
- **Status:** DONE (2026-03-10)
- **Completion Note:** Added a 6-scenario machine-readable library with IOC expectations, analyst response guidance, and ATT&CK mapping documentation + validation tests.
- **Goal:** Define threat scenarios relevant to crypto trading API environments.
- **Deliverables:**
  - Scenario catalog (minimum 5 scenarios)
  - IOC expectations per scenario
  - MITRE ATT&CK mapping per scenario
- **Acceptance Criteria:**
  - Each scenario has trigger conditions and expected analyst response
  - Scenarios are realistic for cloud-first trading operations
  - Mapping and rationale are documented

## I-004 - Detection Engine (Rule-Based)
- **Status:** DONE (2026-03-10)
- **Completion Note:** Implemented 6 scenario-linked detection rules with severity/confidence metadata, ATT&CK-tagged alert schema, and tests proving each injected scenario triggers alerts.
- **Goal:** Build first-pass detections over generated logs.
- **Deliverables:**
  - Rule framework with metadata (severity, confidence, ATT&CK tag)
  - Detections for each scenario in I-003
  - Alert output schema
- **Acceptance Criteria:**
  - Each injected scenario can trigger at least one detection
  - Alerts include enough context for L1 triage
  - Detection results are reproducible

## I-005 - Alert Enrichment and Triage Workflow
- **Status:** DONE (2026-03-10)
- **Completion Note:** Added enrichment pipeline with correlated timelines, entity/IOC context, severity recommendations, false-positive hints, and ticket-ready JSON/markdown outputs.
- **Goal:** Enrich raw alerts with analyst-friendly investigation context.
- **Deliverables:**
  - Timeline builder for alert-correlated events
  - Entity context (user, API key, IP, endpoint, region)
  - Initial severity recommendation + false-positive hints
- **Acceptance Criteria:**
  - Output can be copied into a SOC ticket with minimal edits
  - Enrichment improves signal-to-noise vs raw alert output
  - Triage fields are consistent across alert types

## I-006 - SOC Runbooks and Escalation Templates
- **Status:** BACKLOG
- **Goal:** Create actionable SOPs for common detections.
- **Deliverables:**
  - Runbooks for phishing-like token abuse, suspicious login, key misuse, malware-like endpoint signal, and exfil-like traffic bursts
  - Escalation handoff template for L2/IR
  - Containment action matrix (authorized vs escalate-only)
- **Acceptance Criteria:**
  - Each runbook has triage steps, decision gates, and escalation criteria
  - Handoff template captures timeline, scope, IOCs, actions taken
  - Documents are interview-ready and concise

## I-007 - Incident Case Artifacts
- **Status:** BACKLOG
- **Goal:** Produce realistic case files showing investigation quality.
- **Deliverables:**
  - At least 3 sample incidents from different scenarios
  - Completed ticket narratives and escalation notes
  - Evidence snapshots and final disposition
- **Acceptance Criteria:**
  - Cases show clear analyst reasoning and chronology
  - Cases include at least one true positive and one false positive
  - Handoff quality is complete and unambiguous

## I-008 - Detection Tuning and Metrics
- **Status:** BACKLOG
- **Goal:** Demonstrate continuous improvement mindset.
- **Deliverables:**
  - False-positive analysis with root causes
  - Rule tuning changes with before/after metrics
  - Operational KPIs (precision proxy, escalation quality, reopen rate proxy)
- **Acceptance Criteria:**
  - At least 2 rules improved with measurable impact
  - Metric definitions are explicit and reproducible
  - Tuning decisions are justified with evidence

## I-009 - Demo Interface (CLI or Notebook)
- **Status:** BACKLOG
- **Goal:** Make the lab easy to present in interviews.
- **Deliverables:**
  - Guided demo flow from data generation to incident handoff
  - One-command or short-step execution path
  - Concise output views for alerts and case summaries
- **Acceptance Criteria:**
  - Demo runs successfully on a clean clone with setup steps
  - Output clearly shows end-to-end SOC workflow
  - Presentation time target: 5 to 8 minutes

## I-010 - Portfolio Packaging and Application Answer
- **Status:** BACKLOG
- **Goal:** Convert project output into job-application assets.
- **Deliverables:**
  - Final README portfolio narrative
  - Resume bullet points linked to project evidence
  - Draft answer to: digital assets and/or algorithmic trading experience
- **Acceptance Criteria:**
  - Claims are backed by concrete project artifacts
  - Narrative is concise and role-aligned
  - Answer is ready to submit with minimal edits

---

## Command Pattern
Use one of these commands to start execution:
- `Start I-001`
- `Start I-00X`

When you trigger an issue, I will:
1. Move it to `IN_PROGRESS`
2. Implement the deliverables in code/docs
3. Validate outputs
4. Mark it `DONE` and summarize results
