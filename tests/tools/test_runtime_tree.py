"""Tests for the UI-tree renderer that authors read selectors out of."""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from tools.runtime.tree import newest_run_result, render_tree


def _node(path, parent, tag, cls, **extra):
    node = {"path": path, "parent": parent, "tag": tag, "class": cls}
    node.update(extra)
    return node


class RenderTreeTest(unittest.TestCase):
    def _tree(self):
        return {
            "role": "main_view",
            "event": 0x07DD,
            "class": "TMapUberPicture",
            "nodes": [
                _node("main#1", None, "main", "TMapUberPicture", actionable=1, enabled=1),
                _node(
                    "main#1/tool#1",
                    "main#1",
                    "tool",
                    "TToolBarCluster",
                    actionable=1,
                    enabled=1,
                    event_number=5,
                ),
                _node(
                    "main#1/tool#1/trad#1",
                    "main#1/tool#1",
                    "trad",
                    "TUpDownPictureButton",
                    actionable=1,
                    enabled=1,
                    event_number=10,
                    picture_id=9443,
                ),
                _node(
                    "main#1/tool#1/quer#1",
                    "main#1/tool#1",
                    "quer",
                    "TPictureButton",
                    actionable=0,
                    enabled=0,
                    event_number=10,
                ),
            ],
        }

    def test_header_names_role_and_event(self):
        lines = render_tree(self._tree(), show_paths=False)
        self.assertIn("TMapUberPicture", lines[0])
        self.assertIn("main_view", lines[0])
        self.assertIn("event=0x07dd", lines[0])

    def test_nesting_follows_parent_links(self):
        lines = render_tree(self._tree(), show_paths=False)
        indents = {
            line.split()[0]: len(line) - len(line.lstrip())
            for line in lines[1:]
            if line.strip()
        }
        self.assertLess(indents["main"], indents["tool"])
        self.assertLess(indents["tool"], indents["trad"])
        self.assertEqual(indents["trad"], indents["quer"])

    def test_reports_event_actionable_and_disabled(self):
        rendered = "\n".join(render_tree(self._tree(), show_paths=False))
        self.assertIn("event=0x000a actionable=1", rendered)
        self.assertIn("picture=9443", rendered)
        # A control that exists but will not accept activation is the single most common
        # cause of a "missing control" failure, so it has to be visible.
        self.assertIn("actionable=0 disabled", rendered)

    def test_selector_omits_the_root_tag(self):
        """RequireControl resolves the first tag as a child of the root it is handed.

        Including the root's own tag would hand the author a path one level too deep, which
        resolves to nothing and reads like a missing control.
        """
        rendered = "\n".join(render_tree(self._tree(), show_paths=True))
        self.assertIn("selector: tool/trad", rendered)
        self.assertNotIn("selector: main/tool", rendered)
        self.assertIn("selector: (the root itself)", rendered)

    def test_blank_tags_stay_visible(self):
        tree = {
            "role": "main_view",
            "class": "TRoot",
            "nodes": [
                _node("root#1", None, "root", "TRoot"),
                _node("root#1/    #1", "root#1", "    ", "TMiniMapView", actionable=1),
            ],
        }
        rendered = "\n".join(render_tree(tree, show_paths=True))
        self.assertIn("???? TMiniMapView", rendered)
        self.assertIn("selector: ????", rendered)

    def test_missing_nodes_render_nothing(self):
        self.assertEqual(render_tree({"role": "main_view"}, show_paths=False), [])


class NewestRunResultTest(unittest.TestCase):
    def test_prefers_newest_per_run_bundle_over_canonical(self):
        with TemporaryDirectory() as raw:
            root = Path(raw)
            canonical = root / "trade.json"
            canonical.write_text("{}", encoding="utf-8")
            for index, stamp in enumerate(("20260101T000000Z-1", "20260102T000000Z-2")):
                run = root / f"trade-{stamp}"
                run.mkdir()
                result = run / "result.json"
                result.write_text(json.dumps({"n": index}), encoding="utf-8")
                # Force a deterministic ordering rather than relying on filesystem timing.
                import os

                os.utime(result, (1_000 + index, 1_000 + index))
            found = newest_run_result(root, "trade")
            self.assertIsNotNone(found)
            assert found is not None
            self.assertEqual(json.loads(found.read_text(encoding="utf-8")), {"n": 1})

    def test_falls_back_to_canonical_result(self):
        with TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "trade.json").write_text("{}", encoding="utf-8")
            found = newest_run_result(root, "trade")
            self.assertEqual(found, root / "trade.json")

    def test_missing_result_is_none(self):
        with TemporaryDirectory() as raw:
            self.assertIsNone(newest_run_result(Path(raw), "trade"))


if __name__ == "__main__":
    unittest.main()
