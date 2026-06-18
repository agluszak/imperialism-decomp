#!/usr/bin/env python3
"""Dump the Ghidra thunk-name -> real-name map to config/thunk_map.csv.

The map lets offline consumers (``tools.workflow.shape_body`` during
``recover-class`` promotion) rewrite jmp-thunk / alias call names to the real
symbol without a live Ghidra connection. Read-only against the DB; idempotent
output (deterministic, sorted) so re-dumping an unchanged DB is a no-op diff.

Usage:
  uv run python -m tools.ghidra.dump_thunk_map [--out config/thunk_map.csv]
"""

from __future__ import annotations

import argparse

from tools.common import ghidra_env
from tools.common.repo import repo_root_from_file, resolve_repo_path
from tools.common.thunk_names import dump_thunk_map as serialize_thunk_map
from tools.ghidra.decompile_one import build_thunk_map


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Dump Ghidra thunk map to config/thunk_map.csv.")
    p.add_argument(
        "--out",
        default="config/thunk_map.csv",
        help="Repo-relative output path (default: config/thunk_map.csv).",
    )
    return p.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = repo_root_from_file(__file__)
    out_path = resolve_repo_path(repo_root, args.out)

    project = ghidra_env.open_project()
    consumer, program = ghidra_env.open_program(project)
    try:
        thunk_map = build_thunk_map(program)
    finally:
        program.release(consumer)
        project.close()

    text = serialize_thunk_map(thunk_map)
    changed = not out_path.exists() or out_path.read_text(encoding="utf-8") != text
    if changed:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(text, encoding="utf-8")
    print(f"dump-thunk-map: {len(thunk_map)} thunks -> {out_path} ({'changed' if changed else 'up to date'})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
