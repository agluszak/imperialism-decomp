#!/usr/bin/env python3
"""Structure-audit gate for manually-owned game source (bd imperialism-decomp-8mo.18).

Umbrella enforcement so the source-structure cleanups don't regress. Rules enforced
today (the tree is green behind each):

  (2) compatibility-alias headers — a header whose only content is a single
      `#include` plus optional `typedef Real Alias;` lines is a pure re-export
      alias (the 8mo.12 cleanup dissolved five of these). New code must name the
      real class and include its real header. Multi-include umbrella headers are
      deliberate and not flagged.
  (3) duplicate include — the same header `#include`d more than once at top level
      (outside any `#if`/`#ifdef`) in one file. Header guards make the repeat a
      no-op, so it is pure noise; keep the first, drop the rest.
  (4) line endings — no CR (`\\r`): manual source is LF-only. A CRLF/mixed file
      churns diffs and trips whitespace tooling.

Deferred rules from the bead, to be enabled as their sibling cleanups land (each
has its own gate today or is blocked on another bead):
  (1) annotation-only TUs (needs 8mo.11);
  (5) class-method claims whose owner differs from the filename, minus an
      allowlist (needs the 8mo.13 family/TU-split allowlist + tools.source_model);
  (6) `// slot ... inherited unchanged` listing comments — already enforced by
      `just generated-marker-gate`, so not duplicated here;
  (7) duplicate struct/packet-layout declarations (landed via
      include/game/multiplayer_packets.h; a general detector is still open).

File-size limits, per the bead, would be WARNINGS only and never hard failures.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

from tools.common.file_scan import iter_files
from tools.common.repo import normalize_repo_relative_path, repo_root_from_file

DEFAULT_PATHS = ("include/game", "src/game")
INCLUDE_RE = re.compile(r'^\s*#\s*include\s+([<"][^>"]+[>"])')
IF_RE = re.compile(r"^\s*#\s*(if|ifdef|ifndef)\b")
ENDIF_RE = re.compile(r"^\s*#\s*endif\b")


def duplicate_top_level_includes(text: str) -> list[str]:
    """Headers `#include`d more than once at top level (nesting depth 0)."""
    depth = 0
    seen: dict[str, int] = {}
    for line in text.splitlines():
        if IF_RE.match(line):
            depth += 1
            continue
        if ENDIF_RE.match(line):
            depth = max(0, depth - 1)
            continue
        m = INCLUDE_RE.match(line)
        if m and depth == 0:
            seen[m.group(1)] = seen.get(m.group(1), 0) + 1
    return sorted(k for k, n in seen.items() if n > 1)


PRAGMA_ONCE_RE = re.compile(r"^\s*#\s*pragma\s+once\b")
TYPEDEF_ALIAS_RE = re.compile(r"^\s*typedef\s+(\w+)\s+\w+\s*;\s*$")
LINE_COMMENT_RE = re.compile(r"^\s*//")


def is_alias_header(text: str) -> bool:
    """A pure re-export header: one `#include` plus optional `typedef X Y;` lines
    whose target X is the included header's own class (e.g. `typedef TViewMgr
    TUiRuntimeContext;` over `#include "game/TViewMgr.h"`).

    Multi-include umbrella headers and domain-vocabulary headers (typedefs of
    scalar types like `typedef short NationSlot;`) are deliberate and not flagged.
    """
    include_stems: list[str] = []
    typedef_targets: list[str] = []
    for line in text.splitlines():
        if not line.strip() or LINE_COMMENT_RE.match(line) or PRAGMA_ONCE_RE.match(line):
            continue
        m = INCLUDE_RE.match(line)
        if m:
            include_stems.append(Path(m.group(1).strip('<">')).stem)
            continue
        m = TYPEDEF_ALIAS_RE.match(line)
        if m:
            typedef_targets.append(m.group(1))
            continue
        return False  # any other declaration/content -> a real header
    if len(include_stems) != 1:
        return False
    # Pure wrapper (no typedefs) or a class re-export alias of the included header.
    return all(target == include_stems[0] for target in typedef_targets)


def collect_offenders(paths, repo_root: Path) -> tuple[list[str], list[str], list[str]]:
    dup_offenders: list[str] = []
    crlf_offenders: list[str] = []
    alias_offenders: list[str] = []
    for path in iter_files(paths):
        if path.suffix not in (".cpp", ".h"):
            continue
        rel = normalize_repo_relative_path(path, repo_root)
        raw = path.read_bytes()
        if b"\r" in raw:
            crlf_offenders.append(rel)
        text = raw.decode("utf-8", errors="ignore")
        dups = duplicate_top_level_includes(text)
        if dups:
            dup_offenders.append(f"{rel}: {', '.join(dups)}")
        if path.suffix == ".h" and is_alias_header(text):
            alias_offenders.append(rel)
    return sorted(dup_offenders), sorted(crlf_offenders), sorted(alias_offenders)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--paths", nargs="+", default=list(DEFAULT_PATHS))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = repo_root_from_file(__file__)
    dup_offenders, crlf_offenders, alias_offenders = collect_offenders(args.paths, repo_root)

    if not dup_offenders and not crlf_offenders and not alias_offenders:
        print("Structure-audit gate passed (no duplicate includes, no CRLF, no alias headers).")
        return 0

    print("Structure-audit gate failed:")
    if crlf_offenders:
        print(f"  CR (\\r) in LF-only manual source ({len(crlf_offenders)}):")
        for rel in crlf_offenders:
            print(f"    - {rel}")
    if dup_offenders:
        print(f"  duplicate top-level #include ({len(dup_offenders)}):")
        for line in dup_offenders:
            print(f"    - {line}")
        print("Header guards make repeat includes no-ops; keep the first, drop the rest.")
    if alias_offenders:
        print(f"  compatibility-alias headers (single-include re-export) ({len(alias_offenders)}):")
        for rel in alias_offenders:
            print(f"    - {rel}")
        print("Name the real class and include its real header; do not add alias headers.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
