from __future__ import annotations

from pathlib import Path
import unittest

from tools.workflow.turn_event_coverage import REPORT_PATH, build_rows, render_report


REPO_ROOT = Path(__file__).resolve().parents[2]


class TurnEventCoverageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.rows, cls.mac_complement, cls.callbacks = build_rows(REPO_ROOT)
        cls.by_event = {row["event"]: row for row in cls.rows}

    def test_boot_path_has_no_unowned_gap(self) -> None:
        boot = [row for row in self.rows if row["boot_stage"]]

        self.assertEqual(len(boot), 6)
        self.assertTrue(all(not row["gap_bead"] for row in boot))
        self.assertTrue(all(row["status"] == "implemented_reachable" for row in boot))

    def test_vocabulary_is_complete_and_unique(self) -> None:
        names = [row["vocabulary_name"] for row in self.rows]

        self.assertEqual(len(self.rows), 98)
        self.assertEqual(len(names), len(set(names)))
        self.assertTrue(all(name.startswith("kTurnEvent") for name in names))
        self.assertEqual(self.by_event[0x05DC]["vocabulary_name"], "kTurnEventMainMenu")
        self.assertEqual(self.by_event[0x07DD]["vocabulary_name"], "kTurnEventStrategicMap")
        self.assertEqual(self.by_event[0x0F0A]["vocabulary_name"], "kTurnEventTacticalMapPictureBase")

    def test_core_screen_factories_and_hooks_are_joined(self) -> None:
        self.assertEqual(self.by_event[0x5DC]["boot_stage"], "main_menu")
        self.assertTrue(self.by_event[0x5DC]["factories"])
        self.assertIn("this->HandleTurnEventDialogFactorySlotF8", self.by_event[0x5DC]["hooks"])
        self.assertIn(
            "this->ShowTerrainMap",
            self.by_event[0x7DD]["hooks"],
        )
        self.assertIn(
            "this->RefreshStrategicMapStatusIconsForActiveNation",
            self.by_event[0x7D9]["teardown"],
        )

    def test_missing_builders_have_follow_up_owners(self) -> None:
        missing = [row for row in self.rows if row["status"] == "posted_missing_builder"]

        self.assertEqual(missing, [])

    def test_non_factory_dispositions_carry_evidence(self) -> None:
        disposed = {row["event"]: row for row in self.rows if row["disposition"]}

        self.assertEqual(set(disposed), {0x0F0A, 0x1C52})
        for event, row in disposed.items():
            self.assertEqual(row["status"], "foreign_resource_domain")
            self.assertFalse(row["gap_bead"], f"0x{event:04x} still carries a gap bead")
            self.assertIn("0x", row["disposition"]["evidence"])

    def test_all_mac_views_remain_accounted_for(self) -> None:
        generated_resources = {
            factory["resource"]
            for row in self.rows
            for factory in row["factories"]
            if factory["resource"] != "-"
        }
        complement_resources = {row["resource"] for row in self.mac_complement}

        self.assertEqual(len(generated_resources | complement_resources), 121)
        self.assertFalse(generated_resources & complement_resources)

    def test_callback_controls_are_joined(self) -> None:
        validation = self.callbacks["validation"]

        self.assertTrue(validation["movie_notify_handler"]["found"])
        self.assertEqual(
            validation["startup_factories"]["found"],
            validation["startup_factories"]["expected"],
        )

    def test_committed_report_is_current(self) -> None:
        committed = (REPO_ROOT / REPORT_PATH).read_text(encoding="utf-8")
        self.assertEqual(committed, render_report(self.rows, self.mac_complement, self.callbacks))


if __name__ == "__main__":
    unittest.main()
