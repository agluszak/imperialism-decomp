#!/usr/bin/env python3
"""Structure-audit gate for manually-owned game source (bd imperialism-decomp-8mo.18).

Umbrella enforcement so the source-structure cleanups don't regress. Rules enforced
today (the tree is green behind each):

  (1) annotation-only TUs — a `src/game/*.cpp` whose only content is comments
      (including `// FUNCTION|LIBRARY|SYNTHETIC:` markers), preprocessor
      directives, and blank lines. The 8mo.11 cleanup retired 19 such marker
      carriers; their identity claims live in
      `config/reviewed_library_identities.csv` and are projected into the
      generated marker TU by stubgen. New claims go in the CSV, never in a
      code-free manual .cpp.
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

  (7) duplicate struct definitions — the same `struct Name {` defined in more
      than one manual TU is the wire-layout divergence class the type-modeling
      guardrail exists to prevent (two declarations silently drift; the 8mo.16
      packet unification and the RelationshipRankEntry/TScopedWaitCursor twins
      are the precedent). Define the record once in a header.

  (5) cross-file ownership — a `// FUNCTION:` claim in `src/game/X.cpp` whose
      declared class is neither `X` nor `X`'s pre-underscore base must be covered
      by `config/tu_layout_allowlist.csv`: `family_module` rows allow any class,
      `companion_record` rows allow the classes named in their `classes` column,
      `split_exception` rows cover the ClassName_<part>.cpp form (Hard Rule 7 +
      the 8mo.14 TU-layout policy, docs/reference/tu_layout_policy.md).

Not duplicated here:
  (6) `// slot ... inherited unchanged` listing comments — already enforced by
      `just generated-marker-gate`.

File-size limits are WARNINGS only and never hard failures: TUs over
SIZE_WARN_LINES lines are listed informationally (split candidates tracked in
8mo.15), with no effect on the exit code.
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
    TUiRuntimeContext;` over `#include "game/ui_core/TViewMgr.h"`).

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


BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)


def is_annotation_only_tu(text: str) -> bool:
    """A .cpp whose only content is comments (including `// FUNCTION:` /
    `// LIBRARY:` / `// SYNTHETIC:` markers), preprocessor directives, and blank
    lines — no executable definitions. Such a TU compiles on every build while
    contributing nothing; its identity/ownership claims belong in
    `config/reviewed_library_identities.csv` (projected into the generated
    marker TU by stubgen), never in a manual marker-carrier .cpp.

    Code hidden inside `#if 0` still counts as content (conservatively not
    flagged) — the generated `#if 0` marker TU lives in the build dir and is
    never scanned here.
    """
    stripped = BLOCK_COMMENT_RE.sub("", text)
    continuation = False
    for line in stripped.splitlines():
        code = line.split("//", 1)[0].strip()
        if continuation:
            continuation = code.endswith("\\")
            continue
        if not code:
            continue
        if code.startswith("#"):
            continuation = code.endswith("\\")
            continue
        return False
    return True


SIZE_WARN_LINES = 2000

ALLOWLIST_PATH = "config/tu_layout_allowlist.csv"

STRUCT_DEF_RE = re.compile(r"^(?:typedef\s+)?struct\s+(\w+)\s*(?::[^{;]*)?\{", re.M)


def load_tu_layout_allowlist(repo_root: Path) -> dict[str, tuple[str, set[str]]]:
    """file -> (kind, allowed companion classes)."""
    allow: dict[str, tuple[str, set[str]]] = {}
    path = repo_root / ALLOWLIST_PATH
    if not path.is_file():
        return allow
    from tools.common.pipe_csv import read_pipe_rows

    for row in read_pipe_rows(path):
        classes = set((row.get("classes") or "").split(";")) - {""}
        allow[row["file"]] = (row["kind"], classes)
    return allow


CLAIM_CLASS_RE = re.compile(r"\b(\w+)::")


def ownership_offenders(repo_root: Path) -> list[str]:
    """Rule (5): cross-file class-method claims not covered by the allowlist."""
    from tools.source_model import scan_marker_claims

    allow = load_tu_layout_allowlist(repo_root)
    offenders = []
    for claim in scan_marker_claims(repo_root, "IMPERIALISM"):
        if claim.kind != "FUNCTION" or not claim.file.startswith("src/game/"):
            continue
        m = CLAIM_CLASS_RE.search(claim.prototype or "")
        if not m:
            continue
        cls = m.group(1)
        stem = Path(claim.file).stem
        if cls in (stem, stem.split("_")[0]):
            continue
        kind, classes = allow.get(claim.file, ("", set()))
        if kind == "family_module":
            continue
        if kind == "companion_record" and cls in classes:
            continue
        offenders.append(f"{claim.file}:{claim.line}: {cls}::{claim.name}")
    return sorted(offenders)


def tu_struct_definitions(text: str) -> list[str]:
    """Names of structs DEFINED (with a body) in a TU, comments stripped."""
    stripped = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    stripped = re.sub(r"//[^\n]*", "", stripped)
    return [m.group(1) for m in STRUCT_DEF_RE.finditer(stripped)]


def collect_offenders(
    paths, repo_root: Path
) -> tuple[list[str], list[str], list[str], list[str], list[str]]:
    dup_offenders: list[str] = []
    crlf_offenders: list[str] = []
    alias_offenders: list[str] = []
    annotation_offenders: list[str] = []
    struct_files: dict[str, list[str]] = {}
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
        if path.suffix == ".cpp":
            if is_annotation_only_tu(text):
                annotation_offenders.append(rel)
            for name in tu_struct_definitions(text):
                struct_files.setdefault(name, []).append(rel)
    twin_offenders = [
        f"{name}: {', '.join(sorted(files))}"
        for name, files in sorted(struct_files.items())
        if len(set(files)) > 1
    ]
    return (
        sorted(dup_offenders),
        sorted(crlf_offenders),
        sorted(alias_offenders),
        sorted(annotation_offenders),
        twin_offenders,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--paths", nargs="+", default=list(DEFAULT_PATHS))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = repo_root_from_file(__file__)
    (
        dup_offenders,
        crlf_offenders,
        alias_offenders,
        annotation_offenders,
        twin_offenders,
    ) = collect_offenders(args.paths, repo_root)
    owner_offenders = ownership_offenders(repo_root)

    # Size WARNINGS (never affect the exit code; split candidates live in 8mo.15).
    oversized = []
    for path in iter_files(args.paths):
        if path.suffix == ".cpp":
            lines = path.read_bytes().count(b"\n")
            if lines > SIZE_WARN_LINES:
                oversized.append((lines, normalize_repo_relative_path(path, repo_root)))
    if oversized:
        print(f"warning: {len(oversized)} TUs exceed {SIZE_WARN_LINES} lines (informational):")
        for lines, rel in sorted(oversized, reverse=True):
            print(f"    {lines:6d}  {rel}")

    if not any(
        (
            dup_offenders,
            crlf_offenders,
            alias_offenders,
            annotation_offenders,
            twin_offenders,
            owner_offenders,
        )
    ):
        print(
            "Structure-audit gate passed (no duplicate includes, no CRLF, no alias headers, "
            "no annotation-only TUs, no cross-TU struct twins, no unallowed cross-file claims)."
        )
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
    if annotation_offenders:
        print(f"  annotation-only TUs (comments/markers/preprocessor only) ({len(annotation_offenders)}):")
        for rel in annotation_offenders:
            print(f"    - {rel}")
        print(
            "Move the identity/ownership claims to config/reviewed_library_identities.csv "
            "(stubgen projects them into the generated marker TU) and delete the code-free .cpp."
        )
    if twin_offenders:
        print(f"  struct defined in more than one manual TU ({len(twin_offenders)}):")
        for line in twin_offenders:
            print(f"    - {line}")
        print("Define the record once in a shared header; twin declarations silently drift.")
    if owner_offenders:
        print(f"  cross-file class-method claims not in the TU-layout allowlist ({len(owner_offenders)}):")
        for line in owner_offenders:
            print(f"    - {line}")
        print(
            "Move the method to its owner's ClassName.cpp, or record the file in "
            "config/tu_layout_allowlist.csv (see docs/reference/tu_layout_policy.md)."
        )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
