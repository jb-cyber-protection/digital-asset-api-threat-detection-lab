from __future__ import annotations

import json
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class TestScaffoldSmoke(unittest.TestCase):
    def test_expected_directories_exist(self) -> None:
        expected = [
            ROOT / "src/digital_asset_lab/simulator",
            ROOT / "src/digital_asset_lab/detections",
            ROOT / "src/digital_asset_lab/triage",
            ROOT / "config",
            ROOT / "data/generated",
            ROOT / "runbooks",
            ROOT / "reports/incidents",
            ROOT / "scripts",
            ROOT / "tests",
        ]
        missing = [str(path) for path in expected if not path.exists()]
        self.assertFalse(missing, f"Missing scaffold paths: {missing}")

    def test_generate_activity_script_creates_jsonl(self) -> None:
        output = ROOT / "data/generated/test_events.jsonl"
        cmd = [
            "python3",
            str(ROOT / "scripts/generate_activity.py"),
            "--events",
            "10",
            "--output",
            str(output),
        ]
        subprocess.run(cmd, check=True, cwd=ROOT)

        lines = output.read_text(encoding="utf-8").strip().splitlines()
        self.assertEqual(len(lines), 10)
        sample = json.loads(lines[0])
        self.assertIn("event_id", sample)
        self.assertIn("event_type", sample)
        self.assertIn("profile", sample)
        self.assertIn("timestamp", sample)


if __name__ == "__main__":
    unittest.main()
