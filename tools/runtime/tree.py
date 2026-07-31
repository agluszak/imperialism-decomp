#!/usr/bin/env python3
"""Print the UI tree a runtime test last saw, so selectors are read rather than guessed.

Writing a scenario action means naming a control by its tag path, expected class and event
number. Until now the only way to find those was to read the UI builders, or to compile a
guess and watch `RuntimeUiDriver::RequireControl` reject it. Both are slow, and the builders
are generated, so they describe the tags without describing the *hierarchy* a selector needs.

The harness already serialises the whole tree; failed and held runs now record the live one
under `current_ui_tree`. This renders it as an indented listing:

    TTradeScreenPicture                      (main_view, event=0x07d9)
      mcap  TNumberText            event=0x0001 actionable=0
      gd05  TTradeCluster
        card TTradeOrderPicture    event=0x0004 actionable=1  picture=2111

Every line's selector path is unambiguous -- the harness disambiguates repeated sibling tags
by occurrence -- so `--paths` prints the exact tag chain to pass to RuntimeControlSelector.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from tools.common.repo import repo_root_from_file


def newest_run_result(result_dir: Path, name: str) -> Path | None:
    """The newest per-run result.json for `name`, else the canonical published one."""
    candidates = sorted(
        result_dir.glob(f"{name}-*/result.json"),
        key=lambda path: path.stat().st_mtime,
    )
    if candidates:
        return candidates[-1]
    canonical = result_dir / f"{name}.json"
    return canonical if canonical.is_file() else None


def _tag_of(node: dict) -> str:
    tag = node.get("tag")
    # A tag of spaces or NULs is a real thing in this UI (unnamed container views); showing
    # it as blank would make the listing unreadable and the selector wrong.
    text = str(tag).strip("\0 \t") if isinstance(tag, str) else ""
    return text if text else "????"


def _selector_path(node: dict, by_path: dict[str, dict]) -> str:
    """The tag chain a RuntimeControlSelector would spell for this node.

    RuntimeUiDriver::RequireControl resolves the first tag as a *direct child* of the root
    it is handed, so the root's own tag is not part of the selector. Including it would give
    an author a path one level too deep -- which resolves to nothing and reads like a
    missing control.
    """
    chain: list[str] = []
    cursor: dict | None = node
    seen: set[str] = set()
    while cursor is not None:
        parent_key = cursor.get("parent")
        if not isinstance(parent_key, str):
            break  # the root itself; its tag is implied by the root argument
        chain.append(_tag_of(cursor))
        if parent_key in seen:
            break
        seen.add(parent_key)
        cursor = by_path.get(parent_key)
    chain.reverse()
    return "/".join(chain) if chain else "(the root itself)"


def render_tree(tree: dict, show_paths: bool) -> list[str]:
    nodes = tree.get("nodes")
    if not isinstance(nodes, list):
        return []
    by_path = {
        str(node["path"]): node
        for node in nodes
        if isinstance(node, dict) and isinstance(node.get("path"), str)
    }
    depth_of: dict[str, int] = {}
    lines: list[str] = []

    role = tree.get("role", "?")
    header = f"{tree.get('class') or '?'}"
    event = tree.get("event")
    detail = f"({role}"
    if isinstance(tree.get("depth"), int):
        detail += f" depth={tree['depth']}"
    if isinstance(event, int) and event >= 0:
        detail += f", event=0x{event:04x}"
    detail += ")"
    lines.append(f"{header:<40} {detail}")

    for node in nodes:
        if not isinstance(node, dict):
            continue
        path = str(node.get("path", ""))
        parent = node.get("parent")
        depth = depth_of.get(parent, -1) + 1 if isinstance(parent, str) else 0
        depth_of[path] = depth

        parts = []
        event_number = node.get("event_number")
        if isinstance(event_number, int):
            parts.append(f"event=0x{event_number & 0xFFFF:04x}")
        actionable = node.get("actionable")
        if isinstance(actionable, int):
            parts.append(f"actionable={actionable}")
        if node.get("enabled") == 0:
            parts.append("disabled")
        picture = node.get("picture_id")
        if isinstance(picture, int) and picture:
            parts.append(f"picture={picture}")
        text = node.get("text")
        if isinstance(text, str) and text:
            parts.append(f'text="{text}"')

        indent = "  " * (depth + 1)
        label = f"{indent}{_tag_of(node):<5}{node.get('class') or '?'}"
        lines.append(f"{label:<58}{' '.join(parts)}")
        if show_paths:
            lines.append(f"{indent}      selector: {_selector_path(node, by_path)}")
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("name", help="Runtime test name, e.g. trade_screen_operates.")
    parser.add_argument(
        "--paths",
        action="store_true",
        help="Also print each node's unambiguous selector tag chain.",
    )
    parser.add_argument(
        "--snapshots",
        action="store_true",
        help="Render the recorded ui_snapshots instead of the live tree.",
    )
    args = parser.parse_args(argv)

    repo = repo_root_from_file(__file__)
    result_dir = repo / "build-runtime-tests" / "runtime-results"
    result_path = newest_run_result(result_dir, args.name)
    if result_path is None:
        print(f"No runtime result for {args.name!r} under {result_dir}.")
        print(f"Run it first: just runtime-run {args.name}")
        return 2

    result = json.loads(result_path.read_text(encoding="utf-8"))
    print(f"# {result_path}")
    print(f"# status={result.get('status')} phase={result.get('phase')}")

    trees = result.get("ui_snapshots") if args.snapshots else result.get("current_ui_tree")
    if not isinstance(trees, list) or not trees:
        which = "ui_snapshots" if args.snapshots else "current_ui_tree"
        print(f"\nNo {which} recorded in this result.")
        if not args.snapshots:
            # The live tree is deliberately only captured when it is useful.
            print(
                "The live tree is captured on a non-passing run and under --hold; a passing"
                " run records none. Re-run with `--hold <screen>` or after a failure, or pass"
                " --snapshots to render the recorded snapshots."
            )
        return 1

    for tree in trees:
        if not isinstance(tree, dict):
            continue
        print()
        for line in render_tree(tree, args.paths):
            print(line.rstrip())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
