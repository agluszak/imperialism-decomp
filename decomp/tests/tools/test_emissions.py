"""Compiler identity overlays must never manufacture source APIs."""

import tempfile
import unittest
from pathlib import Path

from tools.emissions import load_emissions
from tools.generate_symbols import generate_rows
from tools.source_model import build_model
from tools.stubgen import compute_stub_rows

HEADER = "address|name|symbol|prototype|type|source_file|provenance\n"


class EmissionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        (self.root / "config").mkdir()
        (self.root / "config/original_entities.csv").write_text(
            "address|name|symbol|size|type|prototype|provenance\n"
            "00401000|provisional||8|function||retail\n"
        )

    def catalog(self, rows):
        (self.root / "config/compiler_emissions.csv").write_text(HEADER + rows)

    def test_identity_is_binary_overlay_and_not_source_claim(self):
        self.catalog(
            "00401000|Known::deleting destructor|??_GKnown@@UAEPAXI@Z||synthetic||reviewed\n"
        )
        model = build_model(self.root)
        self.assertFalse(model.functions)
        _, [row], _ = generate_rows(self.root, model=model)
        self.assertEqual(row["symbol"], "??_GKnown@@UAEPAXI@Z")
        self.assertEqual(row["name"], "Known::deleting destructor")
        self.assertEqual(
            compute_stub_rows(self.root, model=model, overlay_rows=[row]), []
        )

    def test_unnamed_emission_still_cannot_acquire_a_stub(self):
        self.catalog("00401000||||synthetic||legacy-marker\n")
        _, rows, _ = generate_rows(self.root)
        self.assertEqual(rows[0]["name"], "provisional")
        self.assertEqual(compute_stub_rows(self.root, overlay_rows=rows), [])

    def test_template_identity_is_retained_without_cpp(self):
        self.catalog("00401000|Vector<int>::Grow|||template||legacy-marker\n")
        _, [row], _ = generate_rows(self.root)
        self.assertEqual(row["name"], "Vector<int>::Grow")
        self.assertFalse((self.root / "src").exists())

    def test_duplicate_emissions_are_errors(self):
        self.catalog("00401000||||synthetic||legacy-marker\n" * 2)
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            load_emissions(self.root)
