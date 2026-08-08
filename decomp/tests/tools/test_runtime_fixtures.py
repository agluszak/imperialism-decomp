#!/usr/bin/env python3
"""Contracts for retail runtime-fixture provenance."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from tools.runtime.fixtures import validate_fixture_metadata


class RuntimeFixtureMetadataTests(unittest.TestCase):
    def _fixture(self, root: Path) -> Path:
        fixture = root / "sample.imp"
        fixture.write_bytes(b"retail save")
        metadata = {
            "file": fixture.name,
            "format": "imperialism-save",
            "sha256": hashlib.sha256(fixture.read_bytes()).hexdigest(),
            "size": fixture.stat().st_size,
            "format_version": 62,
            "source_kind": "retail_fixture_oracle",
            "creation_instructions": "Create with the retail executable.",
        }
        fixture.with_suffix(".imp.json").write_text(
            json.dumps(metadata), encoding="utf-8"
        )
        return fixture

    def test_valid_sidecar_binds_integrity_and_retail_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self._fixture(Path(temporary))
            metadata = validate_fixture_metadata(fixture)
        self.assertEqual(metadata["format_version"], 62)

    def test_changed_fixture_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self._fixture(Path(temporary))
            fixture.write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "sha256"):
                validate_fixture_metadata(fixture)

    def test_missing_provenance_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self._fixture(Path(temporary))
            sidecar = fixture.with_suffix(".imp.json")
            metadata = json.loads(sidecar.read_text(encoding="utf-8"))
            del metadata["creation_instructions"]
            sidecar.write_text(json.dumps(metadata), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "creation_instructions"):
                validate_fixture_metadata(fixture)


if __name__ == "__main__":
    unittest.main()
