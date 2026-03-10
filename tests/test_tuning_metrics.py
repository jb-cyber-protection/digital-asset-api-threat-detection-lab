from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class TestTuningMetrics(unittest.TestCase):
    def test_tuning_improves_metrics_and_keeps_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "metrics.json"
            cmd = [
                "python3",
                str(ROOT / "scripts/evaluate_tuning.py"),
                "--output",
                str(output_path),
            ]
            subprocess.run(cmd, check=True, cwd=ROOT)

            payload = json.loads(output_path.read_text(encoding="utf-8"))
            comparison = payload["comparison"]

            self.assertGreater(comparison["precision_proxy_delta"], 0)
            self.assertLess(comparison["reopen_rate_proxy_delta"], 0)

            improved_rules = 0
            for key in ["scn_001_benign_reduction", "scn_003_benign_reduction", "scn_006_benign_reduction"]:
                if comparison[key] > 0:
                    improved_rules += 1
            self.assertGreaterEqual(improved_rules, 2)

            expected = {"SCN-001", "SCN-002", "SCN-003", "SCN-004", "SCN-005", "SCN-006"}
            tuned_detected = set(payload["tuned"]["detected_injected_scenarios"])
            self.assertTrue(expected.issubset(tuned_detected))


if __name__ == "__main__":
    unittest.main()
