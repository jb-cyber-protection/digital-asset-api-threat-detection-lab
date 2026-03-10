from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CASES_DIR = ROOT / "reports/cases"


class TestCaseArtifacts(unittest.TestCase):
    def test_minimum_case_count(self) -> None:
        case_files = sorted(CASES_DIR.glob("CASE-*.md"))
        self.assertGreaterEqual(len(case_files), 3)

    def test_disposition_mix_includes_true_and_false_positive(self) -> None:
        case_files = sorted(CASES_DIR.glob("CASE-*.md"))
        content = "\n".join(path.read_text(encoding="utf-8") for path in case_files)
        self.assertIn("True Positive", content)
        self.assertIn("False Positive", content)

    def test_case_files_include_timeline_and_escalation_notes(self) -> None:
        case_files = sorted(CASES_DIR.glob("CASE-*.md"))
        for path in case_files:
            text = path.read_text(encoding="utf-8")
            self.assertIn("## Investigation Timeline", text)
            self.assertIn("## Escalation Notes", text)


if __name__ == "__main__":
    unittest.main()
