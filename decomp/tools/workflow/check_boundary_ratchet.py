#!/usr/bin/env python3
"""Hard-ban gate for the manual/autogen boundary (two counts that must stay at zero).

Metric 1 — stub_call_refs: distinct (manual file, autogen-stub name) reference
pairs where manual source calls, takes the address of, or typedef-casts an
autogen stub symbol. Every such reference is boundary debt.

Metric 2 — fn_ptr_casts: function-pointer casts of named function symbols in
manual sources — the legacy `typedef Ret (*Name_t)(...)` per-callsite cast form
plus inline `reinterpret_cast<Ret(__conv*)(...)>` spellings. The
calling-convention guardrail retires these.

This is a baseline-free HARD BAN: the debt was fully eradicated, so ANY nonzero
count fails. There is no baseline file and no update escape hatch -- a new
reference/cast is always a source defect to fix (give the callee a canonical
typed declaration), never to bless.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from tools.common.repo import repo_root_from_file
from tools.workflow.boundary_audit import LIBRARY_RANGE_START, collect_stubs, scan_references
from tools.workflow.check_typedef_cast_drift import TYPEDEF_RE
from tools.common.file_scan import is_excluded_scan_path

INLINE_FN_PTR_CAST_RE = re.compile(
    r"reinterpret_cast\s*<[^;>]*\(\s*(?:__cdecl|__stdcall|__fastcall|__thiscall)?\s*\*"
)


def count_stub_call_refs(repo_root: Path) -> tuple[int, list[str]]:
    stubs = collect_stubs(repo_root)
    scan_references(repo_root, stubs)
    pairs: set[tuple[str, str]] = set()
    for stub in stubs.values():
        if stub.address >= LIBRARY_RANGE_START:
            continue  # CRT/MFC segment: wants the real library declaration, not a port
        for ref in stub.calls + stub.address_takes + stub.typedef_casts:
            pairs.add((ref.split(":")[0], stub.name))
    detail = sorted(f"{f} -> {n}" for f, n in pairs)
    return len(pairs), detail


def count_fn_ptr_casts(repo_root: Path) -> tuple[int, list[str]]:
    total = 0
    detail: list[str] = []
    for base in (repo_root / "src" / "game", repo_root / "include" / "game"):
        for path in sorted(base.rglob("*")):
            if path.suffix not in (".cpp", ".h") or is_excluded_scan_path(path, roots=[repo_root]):
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            n = len(TYPEDEF_RE.findall(text)) + len(INLINE_FN_PTR_CAST_RE.findall(text))
            if n:
                total += n
                detail.append(f"{path.relative_to(repo_root)}: {n}")
    return total, sorted(detail)


def main() -> int:
    repo_root = repo_root_from_file(__file__)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verbose", action="store_true", help="Print every counted item")
    args = parser.parse_args()

    stub_refs, stub_detail = count_stub_call_refs(repo_root)
    casts, cast_detail = count_fn_ptr_casts(repo_root)
    current = {"stub_call_refs": (stub_refs, stub_detail), "fn_ptr_casts": (casts, cast_detail)}

    failed = False
    for key, (now, detail) in current.items():
        if now > 0:
            failed = True
            print(f"Boundary gate FAILED [{key}]: {now} occurrence(s) (hard ban -- must be 0).")
            for line in detail:
                print(f"    - {line}")
            print(
                "  New manual->autogen boundary debt. Give the callee a canonical typed\n"
                "  declaration (real method / real free function) instead of calling or\n"
                "  casting the stub symbol; see the MSVC500 calling-convention guardrail."
            )
        else:
            print(f"Boundary gate passed [{key}]: 0 (hard ban -- zero offenders).")
            if args.verbose:
                for line in detail:
                    print(f"    - {line}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
