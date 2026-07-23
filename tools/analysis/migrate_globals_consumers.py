#!/usr/bin/env python3
"""Migrate umbrella global_data_tables.h consumers to per-subsystem globals headers.

Stage 3 of the globals split (bd imperialism-decomp-8mo.2). Each TU that includes
the umbrella is rewritten to include game/globals/prelude.h (the stable
type/forward-decl core, which also carries the transitive foundation includes the
umbrella used to provide) plus exactly the subsystem globals headers whose declared
identifiers the TU references. After migration, adding a global to one subsystem
header no longer recompiles consumers outside that subsystem.

Identifier matching is conservative: any word-boundary occurrence of a name
declared by a subsystem header pulls that header in. False positives cost an
include; false negatives fail the build loudly.

Dry-run by default; --apply rewrites the consumer files.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

from tools.common.repo import repo_root_from_file

UMBRELLA = "game/global_data_tables.h"
GLOBALS_DIR = "include/game/globals"
PRELUDE = "game/globals/prelude.h"

EXTERN_RE = re.compile(
    r'^extern\s+(?:"C"\s+)?[\w\s\*&:<>,]*?\b(\w+)\s*(?:\[[^\]]*\])*\s*;', re.M
)
RECORD_RE = re.compile(r"^(?:struct|class|enum|union)\s+(\w+)", re.M)
TYPEDEF_RE = re.compile(r"^typedef\s+.*?\b(\w+)\s*;", re.M)
FUNC_DECL_RE = re.compile(r"^[\w\s\*&:<>,]+?\b(\w+)\s*\([^;{]*\)\s*;", re.M)
DEFINE_RE = re.compile(r"^#\s*define\s+(\w+)", re.M)
INCLUDE_UMBRELLA_RE = re.compile(r'^#include "game/global_data_tables\.h"\n', re.M)


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    return re.sub(r"//[^\n]*", " ", text)


def header_identifiers(path: Path) -> set[str]:
    text = strip_comments(path.read_text())
    names: set[str] = set()
    for regex in (EXTERN_RE, RECORD_RE, TYPEDEF_RE, FUNC_DECL_RE, DEFINE_RE):
        names.update(m.group(1) for m in regex.finditer(text))
    return {n for n in names if len(n) > 2}


def build_index(repo_root: Path) -> dict[str, set[str]]:
    """subsystem header repo path -> identifiers it declares."""
    index: dict[str, set[str]] = {}
    for header in sorted((repo_root / GLOBALS_DIR).glob("*.h")):
        if header.name == "prelude.h":
            continue  # always included; no need to match
        index[f"game/globals/{header.name}"] = header_identifiers(header)
    return index


def needed_headers(text: str, index: dict[str, set[str]]) -> list[str]:
    body = strip_comments(text)
    words = set(re.findall(r"\b\w+\b", body))
    return sorted(h for h, names in index.items() if names & words)


def migrate_file(path: Path, index: dict[str, set[str]], apply: bool) -> list[str] | None:
    text = path.read_text()
    if not INCLUDE_UMBRELLA_RE.search(text):
        return None
    needed = needed_headers(text, index)
    replacement = "".join(f'#include "{h}"\n' for h in [PRELUDE, *needed])
    new_text = INCLUDE_UMBRELLA_RE.sub(replacement, text, count=1)
    # A second umbrella include would be a duplicate; drop any.
    new_text = INCLUDE_UMBRELLA_RE.sub("", new_text)
    if apply:
        path.write_text(new_text)
    return needed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="rewrite consumer files")
    parser.add_argument(
        "--keep",
        nargs="*",
        default=["src/game/core/global_data_tables.cpp"],
        help="files that keep the umbrella include (the definitions TU)",
    )
    args = parser.parse_args()
    repo_root = repo_root_from_file(__file__)
    index = build_index(repo_root)

    migrated = 0
    counts: dict[str, int] = {}
    for path in sorted((repo_root / "src/game").rglob("*.cpp")):
        rel = path.relative_to(repo_root).as_posix()
        if rel in args.keep:
            continue
        needed = migrate_file(path, index, args.apply)
        if needed is None:
            continue
        migrated += 1
        for h in needed:
            counts[h] = counts.get(h, 0) + 1
    mode = "rewrote" if args.apply else "would rewrite"
    print(f"{mode} {migrated} umbrella consumers (prelude + per-subsystem includes)")
    for h in sorted(counts, key=lambda name: counts[name], reverse=True):
        print(f"  {counts[h]:4d}  {h}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
