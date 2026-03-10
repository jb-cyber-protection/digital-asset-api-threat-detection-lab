from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class TestDemoFlow(unittest.TestCase):
    def test_demo_generates_expected_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir) / "demo"
            cmd = [
                "python3",
                str(ROOT / "scripts/demo.py"),
                "--events",
                "300",
                "--output-dir",
                str(output_dir),
            ]
            subprocess.run(cmd, check=True, cwd=ROOT)

            events_path = output_dir / "events.jsonl"
            alerts_path = output_dir / "alerts.jsonl"
            tickets_path = output_dir / "triage.jsonl"
            summary_path = output_dir / "summary.md"

            self.assertTrue(events_path.exists())
            self.assertTrue(alerts_path.exists())
            self.assertTrue(tickets_path.exists())
            self.assertTrue(summary_path.exists())

            alert_lines = [line for line in alerts_path.read_text(encoding="utf-8").splitlines() if line.strip()]
            self.assertTrue(alert_lines)

            scenarios = {json.loads(line)["scenario_id"] for line in alert_lines}
            expected = {"SCN-001", "SCN-002", "SCN-003", "SCN-004", "SCN-005", "SCN-006"}
            self.assertTrue(expected.issubset(scenarios))

            summary = summary_path.read_text(encoding="utf-8")
            self.assertIn("## 5-8 Minute Walkthrough", summary)
            self.assertIn("## Alerts By Scenario", summary)


if __name__ == "__main__":
    unittest.main()
