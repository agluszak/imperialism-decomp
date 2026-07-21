from __future__ import annotations

from pathlib import Path
import unittest

from tools.workflow.mac_resource_xrefs import build_graph, query_result


REPO_ROOT = Path(__file__).resolve().parents[2]


class MacResourceXrefTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.graph = build_graph(REPO_ROOT)

    def test_graph_covers_committed_resource_corpus(self) -> None:
        kinds = self.graph["summary"]["node_kinds"]
        self.assertEqual(kinds["view"], 121)
        self.assertEqual(kinds["view_node"], 3263)
        self.assertEqual(kinds["pict"], 2297)
        self.assertEqual(kinds["str_entry"], 3821)
        self.assertEqual(kinds["txst"], 316)

    def test_generated_factory_ownership_reaches_mac_view(self) -> None:
        edges = self.graph["edges"]
        self.assertIn(
            {
                "from": "windows_factory:0x0045d520",
                "relation": "handles_event",
                "to": "windows_event:0x0898",
                "status": "resolved",
            },
            edges,
        )
        self.assertIn(
            {
                "from": "windows_event:0x0898",
                "relation": "builds_view",
                "to": "Tech.rsrc:View:2200",
                "status": "resolved",
            },
            edges,
        )

    def test_view_query_returns_transitive_asset_dependencies(self) -> None:
        result = query_result(self.graph, "Tech.rsrc:View:2200")
        dependencies = result["dependencies"]
        self.assertIn("Tech.rsrc:PICT:2200", dependencies)
        self.assertIn("Tech.rsrc:STR#:3200:1", dependencies)
        self.assertIn("Tech.rsrc:TxSt:1502", dependencies)

    def test_file_scope_is_not_replaced_by_numeric_id_guessing(self) -> None:
        dangling = [
            edge
            for edge in self.graph["edges"]
            if edge["to"] == "Citydlog.rsrc:PICT:9240"
        ]
        self.assertTrue(dangling)
        self.assertNotIn("Citydlog.rsrc:PICT:9240", self.graph["nodes"])
        self.assertTrue(all(edge["status"] == "dangling_explained" for edge in dangling))
        self.assertTrue(all(edge["bead"] == "imperialism-decomp-1uj.77.5" for edge in dangling))

    def test_every_dangling_edge_has_an_explanation_and_owner(self) -> None:
        dangling = [edge for edge in self.graph["edges"] if edge["status"] != "resolved"]
        self.assertTrue(dangling)
        self.assertTrue(all(edge.get("explanation") and edge.get("bead") for edge in dangling))
        self.assertEqual(self.graph["summary"]["dangling_unexplained"], 0)

    def test_source_resolve_call_is_joined_to_known_control_tag(self) -> None:
        self.assertIn(
            {
                "from": "windows_function:0x004acb60",
                "relation": "resolves_control_tag",
                "to": "control_tag:0x696e666f",
                "status": "resolved",
            },
            self.graph["edges"],
        )

    def test_undecoded_text_and_styl_source_is_explicit(self) -> None:
        source = self.graph["sources"]["text_and_styl"]
        self.assertEqual(source["status"], "pending_decoder")
        self.assertEqual(source["bead"], "imperialism-decomp-1uj.77.4")


if __name__ == "__main__":
    unittest.main()
