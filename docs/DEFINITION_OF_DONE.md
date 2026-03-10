# Definition of Done (All Issues)

## Required Checklist
- Scope matches issue goal and acceptance criteria in `docs/ISSUES.md`.
- Changes are limited to relevant paths listed in `docs/REPO_STRUCTURE.md`.
- Commands or scripts run from a fresh clone with documented steps.
- Outputs are reproducible (seed/config/inputs documented).
- Documentation is updated for usage, assumptions, and limitations.
- At least one validation step is run (smoke test and/or automated test).
- Artifacts are interview-usable (clear, concise, evidence-based).

## Quality Gates
- No broken local paths in docs.
- No placeholder TODOs in final issue output unless explicitly tracked in backlog.
- Security-relevant logic includes severity/context notes.
- Ticket/runbook content is escalation-ready and time-sequenced where applicable.

## Completion Update Rule
When an issue is completed:
1. Update its status in `docs/ISSUES.md` to `DONE`.
2. Add a short completion note in commit/summary output.
3. Confirm what was validated and what remains for the next issue.
