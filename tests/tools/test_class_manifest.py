#!/usr/bin/env python3
"""Tests for tools.common.class_manifest (schema, emitter, loader, merge)."""

from __future__ import annotations

import unittest

from tools.common import class_manifest as cm


def _sample() -> dict:
    return {
        "class": "TCity",
        "generated": {
            "vtable_addr": "0x0064f580",
            "object_size": "0x2d4",
            "base": "TObject",
            "ancestry": ["TCity", "TObject", "CObject"],
            "root": "TObject",
            "slots": [
                {
                    "index": 0x1D,
                    "byte": 0x74,
                    "target": 0x004B44D0,
                    "kind": "new",
                    "is_thunk": False,
                    "is_null": False,
                    "ghidra_name": "TCity::GetCitySummaryRecordSlot74",
                    "size": 78,
                    "prototype": "short __thiscall Get(int a, int b)",
                },
                {
                    "index": 0,
                    "byte": 0,
                    "target": 0,
                    "kind": "null",
                    "is_thunk": False,
                    "is_null": True,
                },
            ],
        },
        "curated": {
            "layout": {"base_offset": "0x04", "status": "recovered"},
            "slots": [
                {
                    "index": "0x1d",
                    "method": "GetCitySummaryRecordSlot74",
                    "confidence": "high",
                    # Free text with punctuation that YAML must not re-read.
                    "evidence": "CALL [vptr+0x74], body 0x004b44d0; ok: yes",
                }
            ],
            "fields": [
                {"offset": "0xb6", "type": "short[0x17]", "name": "fieldB6", "source": "manual", "evidence": "0x0050C1BF"},
            ],
        },
    }


class ClassManifestRoundTripTests(unittest.TestCase):
    def test_dump_load_dump_is_stable(self) -> None:
        text = cm.dump_manifest(_sample())
        reloaded = cm.loads_manifest(text)
        self.assertEqual(cm.dump_manifest(reloaded), text)

    def test_hex_is_canonicalized(self) -> None:
        text = cm.dump_manifest(_sample())
        self.assertIn("target: 0x004b44d0", text)
        self.assertIn("index: 0x1d", text)
        self.assertIn("object_size: 0x2d4", text)
        self.assertIn("base_offset: 0x04", text)

    def test_freetext_evidence_survives_round_trip(self) -> None:
        loaded = cm.loads_manifest(cm.dump_manifest(_sample()))
        ev = loaded["curated"]["slots"][0]["evidence"]
        self.assertEqual(ev, "CALL [vptr+0x74], body 0x004b44d0; ok: yes")
        # A bare hex-looking field stays a string, not an int.
        self.assertEqual(loaded["curated"]["fields"][0]["evidence"], "0x0050C1BF")

    def test_int_inputs_format_as_hex(self) -> None:
        loaded = cm.loads_manifest(cm.dump_manifest(_sample()))
        slot = loaded["generated"]["slots"][0]
        self.assertEqual(slot["target"], "0x004b44d0")
        self.assertEqual(slot["index"], "0x1d")
        # Body size is a plain decimal count, not an address.
        self.assertEqual(slot["size"], 78)


class ClassManifestMergeTests(unittest.TestCase):
    def test_refresh_replaces_generated_and_preserves_curated(self) -> None:
        existing = cm.loads_manifest(cm.dump_manifest(_sample()))
        fresh_generated = {
            "vtable_addr": "0x0064f580",
            "object_size": "0x300",  # changed in Ghidra
            "base": "TObject",
            "ancestry": ["TCity", "TObject"],
            "root": "TObject",
            "slots": [{"index": 0x1D, "byte": 0x74, "target": 0x004B44D0, "kind": "new", "is_thunk": False, "is_null": False}],
        }
        merged = cm.merge_refresh(existing, fresh_generated, "TCity")
        # generated region is the fresh one (curated never leaks in)
        self.assertEqual(merged["generated"]["object_size"], "0x300")
        # curated region is preserved verbatim (curated wins)
        self.assertEqual(merged["curated"]["slots"][0]["method"], "GetCitySummaryRecordSlot74")
        self.assertEqual(merged["curated"]["layout"]["status"], "recovered")

    def test_refresh_with_no_existing_yields_empty_curated(self) -> None:
        merged = cm.merge_refresh(None, {"vtable_addr": "0x1", "slots": []}, "TFoo")
        self.assertEqual(merged["curated"], {})
        self.assertEqual(merged["class"], "TFoo")

    def test_curated_slot_methods_keyed_by_index(self) -> None:
        manifest = cm.loads_manifest(cm.dump_manifest(_sample()))
        methods = cm.curated_slot_methods(manifest)
        self.assertIn(0x1D, methods)
        self.assertEqual(methods[0x1D]["method"], "GetCitySummaryRecordSlot74")


class CuratedProjectionTests(unittest.TestCase):
    """The accessors that replaced the former class-shaped CSVs."""

    def _store(self) -> dict[str, dict]:
        # Round-trip through the emitter so we exercise the on-disk representation.
        m = cm.loads_manifest(
            cm.dump_manifest(
                {
                    "class": "TSimMgr",
                    "generated": {"vtable_addr": "0x00662a58", "slots": []},
                    "curated": {
                        "layout": {"base_offset": "0x04", "base_class": "TObject", "status": "recovered", "header": "TSimMgr.h"},
                        "slots": [
                            {"index": "0x1d", "method": "FormatNumWide", "mac_method": "FormatNum", "evidence": "x"},
                            {"index": "0x1f", "method": "GetStringPrelude"},
                        ],
                        "fields": [
                            {"offset": "0x90", "type": "TCity", "name": "pCity", "source": "manual", "evidence": "e"},
                        ],
                        "aliases": [{"alias_class": "TLocalizationRuntime", "vtable_addr": "0x00662a58"}],
                        "vtable_annotation": {"address": "662a58", "note": "auto"},
                    },
                }
            )
        )
        return {"TSimMgr": m}

    def test_slot_method_overrides(self) -> None:
        ov = cm.slot_method_overrides(self._store())
        self.assertEqual(ov[("TSimMgr", 0x1D)], {"method_name": "FormatNumWide", "mac_method": "FormatNum"})
        # mac_method defaults to the method name when absent
        self.assertEqual(ov[("TSimMgr", 0x1F)], {"method_name": "GetStringPrelude", "mac_method": "GetStringPrelude"})

    def test_vtable_aliases(self) -> None:
        self.assertEqual(cm.vtable_aliases(self._store()), {"TLocalizationRuntime": "TSimMgr"})

    def test_recovered_field_rows(self) -> None:
        rows = cm.recovered_field_rows(self._store())
        self.assertEqual(
            rows,
            [{"class": "TSimMgr", "offset": "0x90", "field_type": "TCity", "field_name": "pCity", "note": "e"}],
        )

    def test_vtable_annotation_rows_preserve_bare_address(self) -> None:
        rows = cm.vtable_annotation_rows(self._store())
        self.assertEqual(rows, [{"class": "TSimMgr", "address": "662a58", "note": "auto"}])

    def test_curated_layout(self) -> None:
        layout = cm.curated_layout(self._store()["TSimMgr"])
        self.assertEqual(layout["base_offset"], "0x04")
        self.assertEqual(layout["status"], "recovered")


class CuratedOnlyManifestTests(unittest.TestCase):
    def test_generated_omitted_when_empty(self) -> None:
        text = cm.dump_manifest(
            {"class": "Family_X", "curated": {"vtable_annotation": {"address": "63eb24", "note": "n"}}}
        )
        self.assertNotIn("generated:", text)
        self.assertEqual(cm.dump_manifest(cm.loads_manifest(text)), text)  # stable


if __name__ == "__main__":
    unittest.main()
