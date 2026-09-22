from __future__ import annotations

from pathlib import Path
import unittest

from tools.runtime.oracles.ui import (
    compare_ui_snapshot,
    evaluate_ui_oracle,
    semantic_node_paths,
)
from tools.workflow.ui_platform_diff import build_report


REPO_ROOT = Path(__file__).resolve().parents[2]

# Small mapped case: Startup.rsrc:952 behind factory 0x004538a0, 8 nodes.
FUNCTION_KEY = "0x004538a0"
EVENT_KEY = "0x03b8"


def live_snapshot(report: dict) -> dict:
    """A live-tree snapshot identical to the report's expected semantics."""
    case = report["functions"][FUNCTION_KEY]["cases"][EVENT_KEY]
    nodes = []
    for path, (_node_id, row) in semantic_node_paths(case["nodes"]).items():
        semantic = row["semantic"]
        node = {
            "path": path,
            "tag": row["tag"],
            "class": semantic["class_name"],
            "bounds": list(semantic["geometry"]),
            "state": semantic["state"],
            "enabled": bool(semantic["enabled"]),
            "control_value": semantic["control_value"],
        }
        family = semantic["family"]
        if family.get("picture_id") is not None:
            node["picture_id"] = family["picture_id"]
        text = family.get("text")
        if text is not None and text.get("value") is not None:
            node["text"] = text["value"]
        nodes.append(node)
    return {"event": int(EVENT_KEY, 16), "nodes": nodes}


class CompareUiSnapshotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.report, cls.errors = build_report(REPO_ROOT)

    def setUp(self) -> None:
        self.assertEqual(self.errors, [])

    def test_identical_snapshot_passes(self) -> None:
        comparison = compare_ui_snapshot(self.report, live_snapshot(self.report))

        self.assertEqual(comparison["status"], "passed")
        self.assertEqual(comparison["differences"], [])
        self.assertEqual(comparison["nodes_checked"], 8)
        self.assertEqual(comparison["factory"], FUNCTION_KEY)

    def test_missing_child_is_reported(self) -> None:
        snapshot = live_snapshot(self.report)
        dropped = snapshot["nodes"].pop()

        comparison = compare_ui_snapshot(self.report, snapshot)

        self.assertEqual(comparison["status"], "failed")
        self.assertEqual(len(comparison["differences"]), 1)
        difference = comparison["differences"][0]
        self.assertEqual(difference["kind"], "missing_node")
        self.assertEqual(difference["path"], dropped["path"])
        self.assertEqual(difference["tag"], dropped["tag"])
        self.assertTrue(difference["node_id"])

    def test_extra_node_is_reported(self) -> None:
        snapshot = live_snapshot(self.report)
        snapshot["nodes"].append(
            {
                "path": "62617365#1/7a7a7a7a#1",
                "tag": "zzzz",
                "class": "TView",
                "bounds": [0, 0, 1, 1],
                "state": 0,
                "enabled": True,
                "control_value": 0,
            }
        )

        comparison = compare_ui_snapshot(self.report, snapshot)

        self.assertEqual(comparison["status"], "failed")
        self.assertEqual(
            [d["kind"] for d in comparison["differences"]], ["extra_node"]
        )
        self.assertEqual(
            comparison["differences"][0]["path"], "62617365#1/7a7a7a7a#1"
        )
        self.assertEqual(comparison["differences"][0]["class"], "TView")

    def test_class_mismatch_is_reported(self) -> None:
        snapshot = live_snapshot(self.report)
        target = snapshot["nodes"][1]
        target["class"] = "TNotTheClass"

        comparison = compare_ui_snapshot(self.report, snapshot)

        mismatches = [
            d for d in comparison["differences"] if d["kind"] == "field_mismatch"
        ]
        self.assertEqual(len(mismatches), 1)
        self.assertEqual(mismatches[0]["field"], "class_name")
        self.assertEqual(mismatches[0]["actual"], "TNotTheClass")
        self.assertEqual(mismatches[0]["path"], target["path"])

    def test_rectangle_mismatch_is_reported(self) -> None:
        snapshot = live_snapshot(self.report)
        target = snapshot["nodes"][1]
        target["bounds"][2] += 1

        comparison = compare_ui_snapshot(self.report, snapshot)

        mismatches = [
            d for d in comparison["differences"] if d["kind"] == "field_mismatch"
        ]
        self.assertEqual(len(mismatches), 1)
        self.assertEqual(mismatches[0]["field"], "geometry")
        self.assertEqual(mismatches[0]["actual"], target["bounds"])

    def test_control_value_mismatch_is_reported(self) -> None:
        snapshot = live_snapshot(self.report)
        target = snapshot["nodes"][1]
        target["control_value"] += 1

        comparison = compare_ui_snapshot(self.report, snapshot)

        mismatches = [
            d for d in comparison["differences"] if d["kind"] == "field_mismatch"
        ]
        self.assertEqual(len(mismatches), 1)
        self.assertEqual(mismatches[0]["field"], "control_value")
        self.assertEqual(mismatches[0]["actual"], target["control_value"])

    def test_wrong_parent_reports_missing_and_extra(self) -> None:
        snapshot = live_snapshot(self.report)
        root = snapshot["nodes"][0]["path"]
        # A grandchild: reparenting under root changes its path.
        moved = next(n for n in snapshot["nodes"] if n["path"].count("/") >= 2)
        original_path = moved["path"]
        segment = original_path.rsplit("/", 1)[1]
        moved["path"] = f"{root}/{segment}"

        comparison = compare_ui_snapshot(self.report, snapshot)

        kinds = sorted(d["kind"] for d in comparison["differences"])
        self.assertEqual(kinds, ["extra_node", "missing_node"])
        by_kind = {d["kind"]: d for d in comparison["differences"]}
        self.assertEqual(by_kind["missing_node"]["path"], original_path)
        self.assertEqual(by_kind["extra_node"]["path"], moved["path"])

    def test_unknown_event_is_an_error(self) -> None:
        snapshot = {"event": 0x0BAD, "nodes": []}

        with self.assertRaises(ValueError):
            compare_ui_snapshot(self.report, snapshot)

    def test_evaluate_ui_oracle_without_snapshots_is_absent(self) -> None:
        self.assertIsNone(evaluate_ui_oracle({"captures": {}}))
        self.assertIsNone(evaluate_ui_oracle({}))

    def test_evaluate_ui_oracle_compares_each_snapshot(self) -> None:
        result = {
            "captures": {"ui_tree": {"snapshots": [live_snapshot(self.report)]}}
        }

        oracle = evaluate_ui_oracle(result)

        self.assertEqual(oracle["status"], "passed")
        self.assertEqual(len(oracle["snapshots"]), 1)


if __name__ == "__main__":
    unittest.main()
