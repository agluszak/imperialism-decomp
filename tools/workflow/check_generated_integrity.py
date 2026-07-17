#!/usr/bin/env python3
"""Generated-artifact integrity: no hand-edits under generated directories.

Files under src/autogen/, src/ghidra_autogen/, include/ghidra_autogen/ and
config/function_ownership.csv are tool output. A diff may only touch them when it
also changes at least one `// FUNCTION:`-family marker in manual src/include —
that is the signal that `just regen-stubs` (or the sync pipeline) legitimately
re-derived them. Generated churn with no marker change means someone hand-edited
tool output (Hard Rule 7).

Shared enforcement: `just agent-check` applies this rule locally via
`generated_violations()`; CI runs this module against the PR's merge base.

  uv run python -m tools.workflow.check_generated_integrity [--base REF]
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

GENERATED_VIA_TOOLS = (
    "src/autogen/",
    "src/ghidra_autogen/",
    "include/ghidra_autogen/",
    "config/function_ownership.csv",
)
MARKER_RE = re.compile(
    r"^[+-].*//\s*(FUNCTION|SYNTHETIC|TEMPLATE|LIBRARY|GLOBAL|VTABLE|NOOP):",
)
# Marker-bearing manual sources plus the curated tables the sync pipeline reads;
# a change to any of these legitimises regenerated output.
REGEN_INPUT_PREFIXES = ("src/", "include/", "config/symbols.csv",
                       "config/name_overrides", "config/thunk_map.csv")


def _git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=REPO_ROOT, capture_output=True,
                          text=True).stdout


def generated_violations(base: str, *, include_worktree: bool = True) -> list[str]:
    """Generated paths changed vs `base` without any marker/regen-input change."""
    committed = _git("diff", "--name-only", base).splitlines()
    names = set(p for p in committed if p)
    if include_worktree:
        names |= {l[3:].strip() for l in _git("status", "--porcelain").splitlines()
                  if l.strip()}
    generated = sorted(p for p in names if p.startswith(GENERATED_VIA_TOOLS))
    if not generated:
        return []

    diff_text = _git("diff", base, "--", "src", "include")
    if include_worktree:
        diff_text += "\n" + _git("diff", "--", "src", "include")
    markers_changed = any(MARKER_RE.match(l) for l in diff_text.splitlines())
    inputs_changed = any(p.startswith(REGEN_INPUT_PREFIXES)
                         and not p.startswith(GENERATED_VIA_TOOLS)
                         for p in names)
    if markers_changed or inputs_changed:
        return []
    return generated


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default="",
                        help="base ref (default: merge-base HEAD origin/main)")
    parser.add_argument("--no-worktree", action="store_true",
                        help="only look at committed changes (CI mode)")
    args = parser.parse_args()

    base = args.base or _git("merge-base", "HEAD", "origin/main").strip()
    if not base:
        print("check_generated_integrity: cannot resolve a base ref", file=sys.stderr)
        return 2
    bad = generated_violations(base, include_worktree=not args.no_worktree)
    if bad:
        print("Generated-artifact integrity FAILED — these tool-owned paths changed "
              "with no marker or curated-input change to justify regeneration:")
        for p in bad:
            print(f"  - {p}")
        print("Never hand-edit generated files; revert them and drive the change "
              "through markers + `just regen-stubs` (or the sync pipeline).")
        return 1
    print(f"Generated-artifact integrity OK vs {base[:10]}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
