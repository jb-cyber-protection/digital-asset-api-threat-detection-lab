from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RUNBOOK_DIR = ROOT / "runbooks"

RUNBOOKS = [
    "RB-001-phishing-token-abuse.md",
    "RB-002-suspicious-login.md",
    "RB-003-api-key-misuse.md",
    "RB-004-malware-like-endpoint-signal.md",
    "RB-005-exfiltration-burst.md",
]

REQUIRED_SECTIONS = [
    "## Triage Steps",
    "## Decision Gates",
    "## Escalation Criteria",
    "## Authorized Containment Actions (L1)",
    "## Escalate-Only Actions",
]


class TestRunbookCompleteness(unittest.TestCase):
    def test_runbook_files_exist(self) -> None:
        for runbook in RUNBOOKS:
            path = RUNBOOK_DIR / runbook
            self.assertTrue(path.exists(), f"Missing runbook: {runbook}")

    def test_runbooks_contain_required_sections(self) -> None:
        for runbook in RUNBOOKS:
            content = (RUNBOOK_DIR / runbook).read_text(encoding="utf-8")
            for section in REQUIRED_SECTIONS:
                self.assertIn(section, content, f"{runbook} missing section: {section}")

    def test_templates_exist(self) -> None:
        escalation = RUNBOOK_DIR / "templates/escalation_handoff_template.md"
        matrix = RUNBOOK_DIR / "templates/containment_action_matrix.md"
        self.assertTrue(escalation.exists())
        self.assertTrue(matrix.exists())


if __name__ == "__main__":
    unittest.main()
