from __future__ import annotations

from pathlib import Path
import unittest

from tools.workflow.mac_control_usage import build_index, source_module_hints, tag_hints


REPO_ROOT = Path(__file__).resolve().parents[2]


class MacControlUsageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.index = build_index(REPO_ROOT)

    def test_index_covers_the_complete_view_corpus(self) -> None:
        self.assertEqual(self.index["summary"]["screens"], 121)
        self.assertEqual(self.index["summary"]["nodes"], 3173)
        self.assertEqual(len(self.index["nodes"]), 3173)
        self.assertEqual(len({node["id"] for node in self.index["nodes"]}), 3173)

    def test_screen_identity_remains_resource_file_scoped(self) -> None:
        self.assertIn("Linger.rsrc:2050", self.index["screens"])
        self.assertNotIn("2050", self.index["screens"])

    def test_minimap_parent_and_class_evidence_is_preserved(self) -> None:
        nodes = {
            node["tag"]: node
            for node in self.index["nodes"]
            if node["screen"] == "Linger.rsrc:2050"
        }
        self.assertEqual(nodes["mini"]["class"], "TMiniMapView")
        self.assertEqual(nodes["mini"]["class_source"], "declared")
        self.assertEqual(nodes["mini"]["parent_tag"], "mapW")
        self.assertEqual(nodes["mini"]["parent_class"], "TMiniMapWindow")

    def test_tag_candidates_mark_ambiguity_instead_of_hiding_it(self) -> None:
        ambiguous = [entry for entry in self.index["tags"].values() if entry["ambiguous"]]
        self.assertTrue(ambiguous)
        self.assertTrue(all(len(entry["candidates"]) > 1 for entry in ambiguous))

    def test_portprep_hint_labels_mac_evidence_source(self) -> None:
        hints = tag_hints(self.index, ["book"])
        self.assertTrue(hints)
        self.assertIn("Mac class", hints[0])

    def test_source_module_evidence_reaches_portprep(self) -> None:
        hints = source_module_hints(
            self.index, 0x005769C0, "TNetSelectPicture::HandleEvent"
        )
        self.assertTrue(any("USetupScreens.cpp" in hint for hint in hints))
        self.assertTrue(any("Startup.rsrc:1506" in hint for hint in hints))

    def test_factory_module_join_remains_candidate(self) -> None:
        factory = self.index["factories"]["0x004538a0"]
        setup = next(
            row for row in factory["original_modules"] if row["module"] == "USetupScreens.cpp"
        )
        self.assertEqual(setup["status"], "candidate")


if __name__ == "__main__":
    unittest.main()
