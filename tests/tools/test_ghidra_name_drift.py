"""Tests for the offline Ghidra-name-drift detection.

The TSoundChannelNode case is the decisive regression fixture: source retired the junk
provisional name and recovered the class behind vtable 0x650a08 as TLongintList, so any
address symbols.csv calls TLongintList must never surface in the autogen under the old
TSoundChannelNode namespace.
"""

from __future__ import annotations

import unittest

import tempfile
from pathlib import Path

from tools.workflow.check_ghidra_name_drift import (
    class_of,
    find_drift,
    find_override_drift,
    keys_for,
    sanitize_stem,
)


class TestClassOf(unittest.TestCase):
    def test_qualified_and_bare(self):
        self.assertEqual(class_of("TLongintList::InsertLast"), "TLongintList")
        self.assertEqual(class_of("TSoundChannelNode::SoundChannelNodeDummy00"),
                         "TSoundChannelNode")
        self.assertEqual(class_of("GlobalFreeFunction"), "")


class TestFindDrift(unittest.TestCase):
    def test_tsoundchannelnode_class_drift_flagged(self):
        # symbols.csv is authoritative: 0x4c6740 is TLongintList::InsertLast.
        symbols = {"004c6740": "TLongintList::InsertLast",
                   "00487f70": "TLongintList::NoOpWriteTo"}
        # ...but the autogen still emits it under the retired TSoundChannelNode namespace.
        autogen = [("004c6740", "TSoundChannelNode::SoundChannelNodeDummy00", "TSoundChannelNode"),
                   ("00487f70", "TSoundChannelNode::SoundChannelNodeDummy02", "TSoundChannelNode")]
        class_drift, stale = find_drift(symbols, autogen)
        self.assertEqual(len(class_drift), 2)
        self.assertIn(("004c6740", "TLongintList::InsertLast",
                       "TSoundChannelNode::SoundChannelNodeDummy00"), class_drift)
        # The whole TSoundChannelNode bucket is stale (no address owned by it).
        self.assertIn(("TSoundChannelNode", "TSoundChannelNode"), stale)

    def test_converged_names_have_no_drift(self):
        symbols = {"004c6740": "TLongintList::InsertLast"}
        autogen = [("004c6740", "TLongintList::InsertLast", "TLongintList")]
        class_drift, stale = find_drift(symbols, autogen)
        self.assertEqual(class_drift, [])
        self.assertEqual(stale, [])

    def test_method_name_lag_within_class_is_not_flagged(self):
        # Same class, method renamed in source but DB lags — routine churn, not drift.
        symbols = {"004c6740": "TLongintList::InsertLast"}
        autogen = [("004c6740", "TLongintList::AppendLong", "TLongintList")]
        class_drift, stale = find_drift(symbols, autogen)
        self.assertEqual(class_drift, [])
        self.assertEqual(stale, [])

    def test_addresses_not_in_symbols_are_ignored(self):
        symbols: dict[str, str] = {}
        autogen = [("00401000", "SomeGhidraOnly::Thing", "SomeGhidraOnly")]
        class_drift, stale = find_drift(symbols, autogen)
        self.assertEqual(class_drift, [])
        self.assertEqual(stale, [])

    def test_template_bucket_is_not_stale(self):
        # symbols.csv owns the address under the template class name; the autogen bucket
        # filename sanitizes the template syntax. These are the same class, not drift.
        symbols = {"004c65d0": "CList<long,long>::Serialize"}
        autogen = [("004c65d0", "CList<long,long>::Serialize", "CList_long_long")]
        class_drift, stale = find_drift(symbols, autogen)
        self.assertEqual(class_drift, [])
        self.assertEqual(stale, [])

    def test_sanitize_stem_matches_ghidra_bucket_names(self):
        self.assertEqual(sanitize_stem("CList<long,long>"), "CList_long_long")
        self.assertEqual(sanitize_stem("CArray<void*,void*>"), "CArray_void_void")
        self.assertEqual(
            sanitize_stem("CMap<void*,void*,CacheRecord*,CacheRecord*>"),
            "CMap_void_void_CacheRecord_CacheRecord",
        )

    def test_keys_are_stable(self):
        class_drift = [("004c6740", "TLongintList::InsertLast",
                        "TSoundChannelNode::SoundChannelNodeDummy00")]
        stale = [("TSoundChannelNode", "TSoundChannelNode")]
        keys = keys_for(class_drift, stale)
        self.assertIn("fn|004c6740|TSoundChannelNode", keys)
        self.assertIn("bucket|TSoundChannelNode", keys)


class TestOverrideDrift(unittest.TestCase):
    """A stale function_name_overrides row is applied after the curated merge and
    reverts a curated rename — the 0x413250 IsNationSlotEligibleForEventProcessing case."""

    def _run(self, overrides_text: str, symbols: dict[str, str]):
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            (repo / "config").mkdir()
            (repo / "config" / "function_name_overrides.csv").write_text(
                overrides_text, encoding="utf-8"
            )
            return find_override_drift(repo, symbols)

    def test_stale_override_flagged(self):
        symbols = {"00413250": "TDiplomacyMgr::IsNationSlotEligibleForEventProcessing"}
        overrides = ("address|name|prototype\n"
                     "0x00413250|TDiplomacyMgr::WrapperFor_IsNationSlotEligibleForEventProcessingAt413250|x\n")
        drift = self._run(overrides, symbols)
        self.assertEqual(len(drift), 1)
        self.assertEqual(drift[0][0], "00413250")

    def test_matching_override_ok(self):
        symbols = {"00413250": "TDiplomacyMgr::IsNationSlotEligibleForEventProcessing"}
        overrides = ("address|name|prototype\n"
                     "0x00413250|TDiplomacyMgr::IsNationSlotEligibleForEventProcessing|x\n")
        self.assertEqual(self._run(overrides, symbols), [])

    def test_override_for_uncurated_address_ok(self):
        # An override for an address not in symbols.csv is fine (nothing to contradict).
        overrides = "address|name|prototype\n0x00999999|Foo::Bar|x\n"
        self.assertEqual(self._run(overrides, {}), [])


if __name__ == "__main__":
    unittest.main()
