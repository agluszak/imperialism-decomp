from __future__ import annotations

import json
from pathlib import Path
import unittest

from tools.workflow.mac_string_crosswalk import normalized_text


REPO_ROOT = Path(__file__).resolve().parents[2]


class MacStringCrosswalkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.index = json.loads(
            (REPO_ROOT / "docs/reference/mac_string_crosswalk.json").read_text()
        )
        cls.mac_by_id = {row["id"]: row for row in cls.index["mac_strings"]}

    def test_index_covers_committed_mac_and_windows_string_corpora(self) -> None:
        self.assertEqual(self.index["summary"]["mac_strings"], 3821)
        self.assertEqual(self.index["summary"]["text_resources"], 182)
        self.assertEqual(self.index["summary"]["windows_gob_strings"], 2530)
        self.assertGreater(self.index["summary"]["embedded_globals"], 50)

    def test_decoded_text_resources_participate_in_search_evidence(self) -> None:
        row = self.mac_by_id["Strings.rsrc:TEXT:3012"]

        self.assertEqual(row["resource_type"], "TEXT")
        self.assertEqual(row["resource_name"], "Terrain map set 1 body 2")
        self.assertIn("Whenever a civilian is selected", row["text"])

    def test_strings_resource_uses_runtime_load_string_id_formula(self) -> None:
        row = self.mac_by_id["Strings.rsrc:STR#:10045:6"]
        candidate = row["candidates"][0]

        self.assertEqual(row["text"], "Defenders Hold")
        self.assertEqual(candidate["source"], "windows_gob")
        self.assertEqual(candidate["load_string_id"], 21466)
        self.assertEqual(candidate["legacy_tsv_id"], 21482)
        self.assertIn("resource_id_formula_exact_text", candidate["reasons"])

    def test_local_view_string_matches_named_embedded_global(self) -> None:
        row = self.mac_by_id["MapView.rsrc:STR#:1509:2"]
        candidate = row["candidates"][0]

        self.assertEqual(candidate["source"], "embedded_global")
        self.assertEqual(candidate["symbol"], "g_szUiSkirmishReportTitle_00694998")
        self.assertEqual(candidate["address"], "0x00694998")

    def test_normalization_handles_platform_newlines_and_punctuation(self) -> None:
        self.assertEqual(
            normalized_text("[1:countryName]’s\rReport"),
            normalized_text("[1:countryName]'s\\nReport"),
        )

    def test_function_index_resolves_gob_calls_and_generated_resource_text(self) -> None:
        book = self.index["functions"]["0x0056f560"]["references"]
        self.assertEqual(
            [(row["group"], row["index"], row["text"]) for row in book],
            [(10032, 11, "Next Page"), (10032, 12, "Previous Page")],
        )
        generated = self.index["functions"]["0x0043dbc0"]["references"]
        self.assertTrue(
            any(
                row["kind"] == "generated_mac_resource"
                and row["mac_string"] == "MapView.rsrc:STR#:1509:2"
                for row in generated
            )
        )


if __name__ == "__main__":
    unittest.main()
