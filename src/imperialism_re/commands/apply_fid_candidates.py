#!/usr/bin/env python3
"""
Apply FID (Function ID) rename candidates from CSV.

CSV columns:
  address     – hex address of the function
  new_name    – proposed function name (may have address suffix for disambiguation)
  raw_match_name – base function name from FID database
  source      – origin of match (e.g. FID_single_match_phase1_nodebug)

Dry-run by default; pass --apply to write changes.

Usage:
  uv run impk apply_fid_candidates --in-csv tmp_decomp/batch327_fid_single_match_candidates.csv
  uv run impk apply_fid_candidates --in-csv tmp_decomp/batch327_fid_single_match_candidates.csv --apply
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.ghidra_session import open_program
from imperialism_re.core.typing_utils import parse_hex


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Apply FID rename candidates from CSV.",
    )
    ap.add_argument("--in-csv", required=True, help="CSV with FID candidates")
    ap.add_argument("--apply", action="store_true", help="Write changes (dry-run without)")
    ap.add_argument(
        "--override-conflicts",
        action="store_true",
        help="Override existing user-defined names (FID library names are authoritative)",
    )
    ap.add_argument(
        "--project-root",
        default=default_project_root(),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    csv_path = Path(args.in_csv)
    if not csv_path.exists():
        print(f"missing csv: {csv_path}")
        return 1

    rows = list(csv.DictReader(csv_path.open("r", encoding="utf-8", newline="")))
    if not rows:
        print("no rows")
        return 0

    root = resolve_project_root(args.project_root)
    with open_program(root) as program:
        from ghidra.program.model.symbol import SourceType

        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()

        # --- Validate and plan ---
        planned = []
        bad_rows = 0
        for i, row in enumerate(rows, start=1):
            addr_txt = (row.get("address") or "").strip()
            new_name = (row.get("new_name") or "").strip()
            raw_match = (row.get("raw_match_name") or "").strip()
            source = (row.get("source") or "").strip()
            if not addr_txt or not new_name:
                bad_rows += 1
                print(f"[row-fail] row={i} missing address/new_name")
                continue
            try:
                addr_int = parse_hex(addr_txt)
            except Exception as ex:
                bad_rows += 1
                print(f"[row-fail] row={i} addr={addr_txt} err={ex}")
                continue
            planned.append((addr_int, new_name, raw_match, source))

        print(f"[rows] total={len(rows)} planned={len(planned)} bad_rows={bad_rows}")

        # --- Preview ---
        override = args.override_conflicts
        renamed_preview = 0
        already_match = 0
        missing = 0
        conflict = 0
        override_preview = 0

        for addr_int, new_name, raw_match, source in planned:
            addr = af.getAddress(f"0x{addr_int:08x}")
            func = fm.getFunctionAt(addr)
            if func is None:
                missing += 1
                if missing <= 10:
                    print(f"  [miss] 0x{addr_int:08x} {new_name}")
                continue
            old_name = func.getName()
            if old_name == new_name:
                already_match += 1
            elif not old_name.startswith("FUN_") and not old_name.startswith("thunk_FUN_"):
                if override:
                    override_preview += 1
                    if override_preview <= 30:
                        print(f"  [override] 0x{addr_int:08x} {old_name} -> {new_name} (raw={raw_match})")
                else:
                    conflict += 1
                    if conflict <= 20:
                        print(f"  [conflict] 0x{addr_int:08x} old={old_name} -> {new_name} (raw={raw_match})")
            else:
                renamed_preview += 1
                if renamed_preview <= 20:
                    print(f"  [rename] 0x{addr_int:08x} {old_name} -> {new_name} (raw={raw_match})")

        print(f"\n[preview] to_rename={renamed_preview} override={override_preview} "
              f"already_match={already_match} conflict={conflict} missing={missing}")

        if not args.apply:
            print("[dry-run] pass --apply to write changes")
            return 0

        # --- Apply ---
        tx = program.startTransaction("Apply FID rename candidates")
        ok = 0
        skip_match = 0
        skip_conflict = 0
        fail = 0
        try:
            for addr_int, new_name, raw_match, source in planned:
                addr = af.getAddress(f"0x{addr_int:08x}")
                func = fm.getFunctionAt(addr)
                if func is None:
                    fail += 1
                    continue
                old_name = func.getName()
                if old_name == new_name:
                    skip_match += 1
                    continue
                # Skip user-named functions unless --override-conflicts
                if not old_name.startswith("FUN_") and not old_name.startswith("thunk_FUN_"):
                    if not override:
                        skip_conflict += 1
                        continue
                try:
                    func.setName(new_name, SourceType.USER_DEFINED)
                    # Tag the function with a comment noting FID origin
                    existing_comment = func.getComment() or ""
                    fid_tag = f"[FID:{source}]"
                    if fid_tag not in existing_comment:
                        sep = " " if existing_comment else ""
                        func.setComment(existing_comment + sep + fid_tag)
                    ok += 1
                except Exception as ex:
                    fail += 1
                    print(f"[rename-fail] 0x{addr_int:08x} {old_name} -> {new_name} err={ex}")
        finally:
            program.endTransaction(tx, True)

        program.save("apply FID rename candidates", None)
        print(f"[done] ok={ok} skip_match={skip_match} skip_conflict={skip_conflict} fail={fail}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
