"""Tests for the offline Ghidra-name-drift detection.

The TSoundChannelNode case is the decisive regression fixture: source retired the junk
provisional name and recovered the class behind vtable 0x650a08 as TLongintList, so any
address symbols.csv calls TLongintList must never surface in the autogen under the old
TSoundChannelNode namespace.
"""

from __future__ import annotations

import unittest

from tools.workflow.check_ghidra_name_drift import class_of, find_drift, keys_for


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

    def test_keys_are_stable(self):
        class_drift = [("004c6740", "TLongintList::InsertLast",
                        "TSoundChannelNode::SoundChannelNodeDummy00")]
        stale = [("TSoundChannelNode", "TSoundChannelNode")]
        keys = keys_for(class_drift, stale)
        self.assertIn("fn|004c6740|TSoundChannelNode", keys)
        self.assertIn("bucket|TSoundChannelNode", keys)


if __name__ == "__main__":
    unittest.main()
