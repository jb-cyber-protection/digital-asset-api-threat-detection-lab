from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCENARIO_LIBRARY_PATH = ROOT / "data/scenarios/scenario_library.json"


class TestScenarioLibrary(unittest.TestCase):
    def test_library_has_minimum_scenarios(self) -> None:
        payload = json.loads(SCENARIO_LIBRARY_PATH.read_text(encoding="utf-8"))
        scenarios = payload["scenarios"]
        self.assertGreaterEqual(len(scenarios), 5)

    def test_scenario_ids_are_unique(self) -> None:
        payload = json.loads(SCENARIO_LIBRARY_PATH.read_text(encoding="utf-8"))
        scenario_ids = [scenario["scenario_id"] for scenario in payload["scenarios"]]
        self.assertEqual(len(scenario_ids), len(set(scenario_ids)))

    def test_each_scenario_has_required_sections(self) -> None:
        payload = json.loads(SCENARIO_LIBRARY_PATH.read_text(encoding="utf-8"))
        for scenario in payload["scenarios"]:
            self.assertTrue(scenario["trigger_conditions"], f"{scenario['scenario_id']} missing trigger_conditions")
            self.assertTrue(scenario["ioc_expectations"]["primary"], f"{scenario['scenario_id']} missing primary IOCs")
            self.assertTrue(
                scenario["expected_analyst_response"],
                f"{scenario['scenario_id']} missing analyst response",
            )
            self.assertTrue(scenario["mitre_attack"], f"{scenario['scenario_id']} missing ATT&CK mapping")

    def test_mitre_mapping_has_ids_and_rationale(self) -> None:
        payload = json.loads(SCENARIO_LIBRARY_PATH.read_text(encoding="utf-8"))
        for scenario in payload["scenarios"]:
            for mapping in scenario["mitre_attack"]:
                self.assertIn("technique_id", mapping)
                self.assertIn("technique_name", mapping)
                self.assertIn("rationale", mapping)
                self.assertTrue(mapping["technique_id"].startswith("T"))
                self.assertTrue(mapping["rationale"])


if __name__ == "__main__":
    unittest.main()
