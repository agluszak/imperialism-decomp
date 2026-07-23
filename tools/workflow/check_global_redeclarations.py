#!/usr/bin/env python3
"""Gate: no local `extern` redeclarations of globals already declared in
include/game/global_data_tables.h.

The type-modeling guardrail requires consumers to `#include "game/global_data_tables.h"`
and use the single authoritative declaration. A hand-rolled local `extern` silently
drifts (type, constness, array-ness) from the header and hides the dependency from
refactors. This gate fails on any manual .cpp/.h (outside the global tables pair and
generated trees) that re-declares a name the header already declares.

usage: check_global_redeclarations [--roots src include]
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
HEADER = REPO_ROOT / "include" / "game" / "global_data_tables.h"
GLOBALS_DIR = REPO_ROOT / "include" / "game" / "globals"
SELF_FILES = (
    "include/game/global_data_tables.h",
    "src/game/core/global_data_tables.cpp",
)
SELF_DIRS = ("include/game/globals/",)
GENERATED_MARKERS = ("/ghidra_autogen/", "/autogen/")
EXTERN_RE = re.compile(
    r'^\s*extern\s+(?:"C"\s+)?(?:const\s+)?[\w:*&<> ]+?[\s*&](\w+)\s*(?:\[[^\]]*\])?\s*;',
    re.M,
)


def header_names() -> set[str]:
    """Externs across the umbrella + the per-subsystem globals headers (8mo.2)."""
    names = set(EXTERN_RE.findall(HEADER.read_text(encoding="utf-8", errors="ignore")))
    if GLOBALS_DIR.is_dir():
        for header in GLOBALS_DIR.glob("*.h"):
            names |= set(EXTERN_RE.findall(header.read_text(encoding="utf-8", errors="ignore")))
    return names


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--roots", nargs="+", default=["src", "include"])
    args = parser.parse_args()

    names = header_names()
    failures: list[str] = []
    for root in args.roots:
        for path in (REPO_ROOT / root).rglob("*"):
            if path.suffix not in (".cpp", ".h", ".hpp", ".cc"):
                continue
            rel = path.relative_to(REPO_ROOT).as_posix()
            if (rel in SELF_FILES or rel.startswith(SELF_DIRS)
                    or any(m in f"/{rel}" for m in GENERATED_MARKERS)):
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            for m in EXTERN_RE.finditer(text):
                if m.group(1) in names:
                    line = text.count("\n", 0, m.start()) + 1
                    failures.append(f"{rel}:{line}: local extern redeclares "
                                    f"{m.group(1)!r} (already in global_data_tables.h "
                                    "— include the header instead)")
    if failures:
        print("Global-redeclaration gate failed:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(f"Global-redeclaration gate passed ({len(names)} header globals guarded).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
