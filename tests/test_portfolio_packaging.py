from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PORTFOLIO_DIR = ROOT / "reports/portfolio"


class TestPortfolioPackaging(unittest.TestCase):
    def test_portfolio_files_exist(self) -> None:
        expected = [
            PORTFOLIO_DIR / "EVIDENCE_MAP.md",
            PORTFOLIO_DIR / "RESUME_BULLETS.md",
            PORTFOLIO_DIR / "APPLICATION_ANSWER.md",
        ]
        for path in expected:
            self.assertTrue(path.exists(), f"Missing portfolio file: {path.name}")

    def test_application_answer_has_prompt_and_submission_content(self) -> None:
        text = (PORTFOLIO_DIR / "APPLICATION_ANSWER.md").read_text(encoding="utf-8")
        self.assertIn("Briefly describe", text)
        self.assertIn("Submission-Ready Answer (Concise)", text)
        self.assertIn("Submission-Ready Answer (Expanded)", text)


if __name__ == "__main__":
    unittest.main()
