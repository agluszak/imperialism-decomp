#!/usr/bin/env python3
"""Ratchet gate for the manual/autogen boundary (two monotonically falling counts).

Metric 1 — stub_call_refs: distinct (manual file, autogen-stub name) reference
pairs where manual source calls, takes the address of, or typedef-casts an
autogen stub symbol. Every port should retire at least the references it
touches; new references are new debt.

Metric 2 — fn_ptr_casts: function-pointer casts of named function symbols in
manual sources — the legacy `typedef Ret (*Name_t)(...)` per-callsite cast form
plus inline `reinterpret_cast<Ret(__conv*)(...)>` spellings. The
calling-convention guardrail retires these; new ones are forbidden.

  count > baseline  -> FAIL (new boundary debt appeared)
  count < baseline  -> PASS + reminder to ratchet the baseline down
  count == baseline -> PASS

`--write-baseline` records the current counts (config/boundary_baseline.json);
the just target guards it behind ALLOW_POLICY_BASELINE_UPDATE like every other
architecture-policy baseline.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from tools.common.repo import repo_root_from_file, resolve_repo_path
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
            if path.suffix not in (".cpp", ".h") or is_excluded_scan_path(path):
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
    parser.add_argument(
        "--baseline", default=str(repo_root / "config" / "boundary_baseline.json")
    )
    parser.add_argument("--write-baseline", action="store_true")
    parser.add_argument("--verbose", action="store_true", help="Print every counted item")
    args = parser.parse_args()
    baseline_path = resolve_repo_path(repo_root, args.baseline)

    stub_refs, stub_detail = count_stub_call_refs(repo_root)
    casts, cast_detail = count_fn_ptr_casts(repo_root)
    current = {"stub_call_refs": stub_refs, "fn_ptr_casts": casts}

    if args.verbose:
        print("stub_call_refs:")
        for line in stub_detail:
            print(f"  {line}")
        print("fn_ptr_casts:")
        for line in cast_detail:
            print(f"  {line}")

    if args.write_baseline:
        baseline_path.write_text(json.dumps(current, indent=2) + "\n")
        print(f"Wrote baseline: {baseline_path} ({current})")
        return 0

    if not baseline_path.exists():
        print(f"Baseline missing: {baseline_path}")
        print("Run `just boundary-gate-update` once (needs ALLOW_POLICY_BASELINE_UPDATE=1).")
        return 1

    baseline = json.loads(baseline_path.read_text())
    failed = False
    for key, now in current.items():
        base = int(baseline.get(key, 0))
        if now > base:
            failed = True
            print(
                f"Boundary gate FAILED [{key}]: {base} -> {now} (+{now - base}).\n"
                "  New manual->autogen boundary debt. Give the callee a canonical typed\n"
                "  declaration (real method / real free function) instead of calling or\n"
                "  casting the stub symbol; see the MSVC500 calling-convention guardrail.\n"
                "  Inspect with: uv run python -m tools.workflow.check_boundary_ratchet --verbose"
            )
        elif now < base:
            print(
                f"Boundary gate passed [{key}]: {now} (baseline {base}; -{base - now} — "
                "run `just boundary-gate-update` to ratchet down)."
            )
        else:
            print(f"Boundary gate passed [{key}]: {now} (== baseline).")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
