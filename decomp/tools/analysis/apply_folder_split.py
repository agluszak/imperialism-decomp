#!/usr/bin/env python3
"""Apply the subsystem folder split (bd imperialism-decomp-8mo.6).

Moves src/game/*.cpp into src/game/<subsystem>/ per
docs/reference/subsystem_assignment.csv, and (with --headers) mirrors each moved
class's header include/game/X.h into include/game/<subsystem>/X.h, rewriting
`#include "game/X.h"` references tree-wide. Files without an assignment (or with
a blank/flagged one) stay at the root, which is the shared/hub tier: hub headers
(mfc.h, TObject.h, TView.h, globals/, ...) deliberately remain there.

Codegen safety: include rewrites only change path strings (token stream
identical); moving .cpp files changes the CMake glob order → link order, which
is the register/alignment wobble class the reccmp fork proves. Anon-namespace
entities are file-keyed — run the symbols resync after applying.

Dry-run by default; --apply performs git mv + rewrites.
"""

from __future__ import annotations

import argparse
import csv
import re
import subprocess
from pathlib import Path

from tools.common.repo import repo_root_from_file

ASSIGNMENT = "docs/reference/subsystem_assignment.csv"


def load_assignment(repo_root: Path) -> dict[str, str]:
    mapping: dict[str, str] = {}
    with (repo_root / ASSIGNMENT).open() as fh:
        for row in csv.DictReader(fh, delimiter="|"):
            sub = (row.get("proposed_subsystem") or "").strip()
            if sub:
                mapping[row["file"].strip()] = sub
    return mapping


def plan_moves(repo_root: Path, headers: bool) -> list[tuple[Path, Path]]:
    assignment = load_assignment(repo_root)
    moves: list[tuple[Path, Path]] = []
    for cpp_name, sub in sorted(assignment.items()):
        src = repo_root / "src/game" / cpp_name
        if src.is_file():
            moves.append((src, repo_root / "src/game" / sub / cpp_name))
        if headers:
            header = repo_root / "include/game" / (Path(cpp_name).stem + ".h")
            if header.is_file():
                moves.append((header, repo_root / "include/game" / sub / header.name))
    return moves


def rewrite_includes(repo_root: Path, moved_headers: dict[str, str], apply: bool) -> int:
    """Rewrite `game/X.h` -> `game/<sub>/X.h` for every moved header, tree-wide."""
    if not moved_headers:
        return 0
    pattern = re.compile(
        r'#include "game/(' + "|".join(map(re.escape, moved_headers)) + r')"'
    )
    changed = 0
    scan_roots = ["src", "include", "tools", "tests"]
    for root in scan_roots:
        for path in (repo_root / root).rglob("*"):
            if path.suffix not in (".cpp", ".h", ".py"):
                continue
            text = path.read_text(errors="ignore")
            new = pattern.sub(lambda m: f'#include "game/{moved_headers[m.group(1)]}/{m.group(1)}"', text)
            if new != text:
                changed += 1
                if apply:
                    path.write_text(new)
    return changed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--headers", action="store_true", help="also move class headers")
    args = parser.parse_args()
    repo_root = repo_root_from_file(__file__)
    moves = plan_moves(repo_root, args.headers)
    moved_headers = {
        src.name: dst.parent.name
        for src, dst in moves
        if src.parent.name == "game" and src.suffix == ".h"
    }
    for src, dst in moves:
        print(f"{'mv' if args.apply else 'would mv'} {src.relative_to(repo_root)} -> {dst.relative_to(repo_root)}")
        if args.apply:
            dst.parent.mkdir(parents=True, exist_ok=True)
            subprocess.run(["git", "mv", str(src), str(dst)], check=True, cwd=repo_root)
    changed = rewrite_includes(repo_root, moved_headers, args.apply)
    print(f"{len(moves)} moves; include rewrites touch {changed} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
