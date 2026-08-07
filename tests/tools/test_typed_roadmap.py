import csv
import tempfile
import unittest
from pathlib import Path

from reccmp.tools.roadmap import RoadmapRow
from reccmp.types import EntityType

from tools.reccmp.typed_roadmap import export_typed_csv, pairing_state, typed_entity_name


def row(orig, recomp, state):
    return RoadmapRow(None, None, orig, recomp, None, "data", 0, None, None, state)


class TypedRoadmapTests(unittest.TestCase):
    def test_entity_names_are_unambiguous(self):
        self.assertEqual(typed_entity_name(int(EntityType.IMPORT)), "import")
        self.assertEqual(typed_entity_name(int(EntityType.IMPORT_THUNK)), "import_thunk")

    def test_pairing_state_is_structural(self):
        self.assertEqual(pairing_state(row(0x401000, 0x501000, "paired")), "paired")
        self.assertEqual(
            pairing_state(row(0x401000, None, "original_alias")), "original_alias"
        )
        self.assertEqual(
            pairing_state(row(None, 0x501000, "recomp_duplicate")),
            "recomp_duplicate",
        )

    def test_csv_has_typed_state_schema_and_quotes_names(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "roadmap.csv"
            value = RoadmapRow(None, None, 0x401000, None, None,
                               "import_thunk", 6, "callee, imported", None, "unexplained")
            export_typed_csv(str(path), [value])
            with path.open(encoding="utf-8", newline="") as fd:
                parsed = list(csv.DictReader(fd))
        self.assertEqual(parsed[0]["row_type"], "import_thunk")
        self.assertEqual(parsed[0]["pairing_state"], "unexplained")
        self.assertEqual(parsed[0]["name"], "callee, imported")


if __name__ == "__main__":
    unittest.main()
