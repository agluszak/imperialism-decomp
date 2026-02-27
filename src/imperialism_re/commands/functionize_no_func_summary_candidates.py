#!/usr/bin/env python3
"""
Batch-functionize inferred starts from inventory_no_func_branch_sources summary CSV.

Default behavior is conservative:
  - only rows with empty inferred_start_owner
  - only rows with branch_count >= 1
  - deduplicate and sort addresses

Usage:
  uv run impk functionize_no_func_summary_candidates \
    --summary-csv tmp_decomp/batch776_no_func_branch_sources_post26_summary.csv \
    --max-create 40 --apply
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.ghidra_session import open_program

def parse_hex_addr(text: str) -> int:
    t = (text or "").strip()
    if not t:
        raise ValueError("empty address")
    if t.lower().startswith("0x"):
        return int(t, 16)
    return int(t, 16)

def parse_rows(path: Path, min_branch_count: int, owner_mode: str) -> list[int]:
    addrs: set[int] = set()
    with path.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            start = (row.get("inferred_start") or "").strip()
            if not start:
                continue
            try:
                bc = int((row.get("branch_count") or "0").strip())
            except ValueError:
                continue
            if bc < min_branch_count:
                continue

            owner = (row.get("inferred_start_owner") or "").strip()
            if owner_mode == "empty" and owner:
                continue
            if owner_mode == "nonempty" and not owner:
                continue

            try:
                addrs.add(parse_hex_addr(start))
            except ValueError:
                continue
    return sorted(addrs)

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--summary-csv", required=True, help="Summary CSV from no-func inventory")
    ap.add_argument(
        "--owner-mode",
        default="empty",
        choices=["any", "empty", "nonempty"],
        help="Filter by inferred_start_owner",
    )
    ap.add_argument(
        "--min-branch-count",
        type=int,
        default=1,
        help="Minimum branch_count to include row",
    )
    ap.add_argument(
        "--max-create",
        type=int,
        default=40,
        help="Max functions to create when --apply (0=unlimited)",
    )
    ap.add_argument("--apply", action="store_true", help="Create functions")
    ap.add_argument(
        "--project-root",
        default=default_project_root(),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    summary_csv = Path(args.summary_csv).resolve()
    root = resolve_project_root(args.project_root)

    addrs = parse_rows(summary_csv, args.min_branch_count, args.owner_mode)
    print(
        f"[plan] summary={summary_csv} owner_mode={args.owner_mode} "
        f"min_branch_count={args.min_branch_count} addrs={len(addrs)} apply={args.apply}"
    )
    if not addrs:
        print("[done] no candidates")
        return 0

    with open_program(root) as program:
        from ghidra.program.flatapi import FlatProgramAPI

        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()
        api = FlatProgramAPI(program)

        missing: list[int] = []
        for a in addrs:
            addr = af.getAddress(f"0x{a:08x}")
            fn = fm.getFunctionContaining(addr)
            if fn is None:
                missing.append(a)
                print(f"  0x{a:08x} -> <missing>")
            else:
                print(f"  0x{a:08x} -> {fn.getEntryPoint()} {fn.getName()}")

        if not args.apply:
            print(f"[dry-run] missing={len(missing)}")
            return 0

        to_create = missing
        if args.max_create > 0:
            to_create = missing[: args.max_create]

        tx = program.startTransaction("Functionize no-func summary candidates")
        created = skipped = failed = 0
        try:
            for a in to_create:
                addr = af.getAddress(f"0x{a:08x}")
                if fm.getFunctionContaining(addr) is not None:
                    skipped += 1
                    continue
                try:
                    api.disassemble(addr)
                    fn = api.createFunction(addr, None)
                    if fn is None and fm.getFunctionContaining(addr) is None:
                        failed += 1
                        print(f"[fail] 0x{a:08x} createFunction returned None")
                    else:
                        created += 1
                except Exception as ex:
                    failed += 1
                    print(f"[fail] 0x{a:08x} err={ex}")
        finally:
            program.endTransaction(tx, True)

        program.save("functionize no-func summary candidates", None)
        print(
            f"[done] candidates={len(addrs)} missing={len(missing)} "
            f"attempted={len(to_create)} created={created} skipped={skipped} failed={failed}"
        )
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

