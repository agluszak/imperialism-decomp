#!/usr/bin/env python3
"""
Apply thunk signatures by copying from target functions listed in a CSV.

Expected CSV columns:
  address,target_addr
  (typically produced by generate_missing_jmp_thunk_candidates.py)

Behavior:
  - source function must exist at `address`
  - source name must start with `thunk_` (or `--allow-non-thunk`)
  - target function must exist at `target_addr`
  - copy calling convention, return type, and formal parameters from target

Usage:
  .venv/bin/python new_scripts/apply_thunk_target_signatures_from_csv.py \
    <csv_path> [project_root]
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

import pyghidra

GHIDRA_DIR = Path(
    "/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC"
)
PROJECT_NAME = "imperialism-decomp"
PROGRAM_PATH = "/Imperialism.exe"


def parse_hex(text: str) -> int:
    t = text.strip()
    if t.lower().startswith("0x"):
        return int(t, 16)
    return int(t, 16)


def open_project_with_lock_cleanup(root: Path):
    try:
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)
    except Exception:
        for lock_file in (root / f"{PROJECT_NAME}.lock", root / f"{PROJECT_NAME}.lock~"):
            if lock_file.exists():
                lock_file.unlink()
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("csv_path", help="CSV with source address + target_addr")
    ap.add_argument(
        "project_root",
        nargs="?",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    ap.add_argument(
        "--allow-non-thunk",
        action="store_true",
        help="Allow source functions not starting with thunk_",
    )
    args = ap.parse_args()

    csv_path = Path(args.csv_path)
    root = Path(args.project_root).resolve()
    if not csv_path.exists():
        print(f"missing csv: {csv_path}")
        return 1

    rows = list(csv.DictReader(csv_path.open("r", encoding="utf-8")))
    if not rows:
        print("no rows")
        return 0

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        from ghidra.program.model.listing import Function, ParameterImpl
        from ghidra.program.model.symbol import SourceType

        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()

        tx = program.startTransaction("Apply thunk signatures from CSV targets")
        ok = 0
        skip = 0
        fail = 0
        try:
            for r in rows:
                addr_s = (r.get("address") or "").strip()
                target_s = (r.get("target_addr") or "").strip()
                if not addr_s or not target_s:
                    fail += 1
                    continue
                try:
                    src_a = af.getAddress(f"0x{parse_hex(addr_s):08x}")
                    dst_a = af.getAddress(f"0x{parse_hex(target_s):08x}")
                except Exception:
                    fail += 1
                    continue

                src = fm.getFunctionAt(src_a)
                dst = fm.getFunctionAt(dst_a)
                if src is None or dst is None:
                    fail += 1
                    continue
                if (not args.allow_non_thunk) and (not src.getName().startswith("thunk_")):
                    skip += 1
                    continue

                try:
                    old_sig = str(src.getSignature())
                    cc = dst.getCallingConventionName()
                    if cc:
                        src.setCallingConvention(cc)

                    params = []
                    dst_params = dst.getParameters()
                    for i in range(len(dst_params)):
                        p = dst_params[i]
                        nm = p.getName() or f"param_{i+1}"
                        params.append(
                            ParameterImpl(nm, p.getDataType(), program, SourceType.USER_DEFINED)
                        )

                    src.replaceParameters(
                        Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
                        True,
                        SourceType.USER_DEFINED,
                        params,
                    )
                    src.setReturnType(dst.getReturnType(), SourceType.USER_DEFINED)
                    if str(src.getSignature()) == old_sig:
                        skip += 1
                    else:
                        ok += 1
                except Exception as ex:
                    fail += 1
                    print(f"[fail] {src.getEntryPoint()} {src.getName()} err={ex}")
        finally:
            program.endTransaction(tx, True)

        program.save("apply thunk signatures from csv targets", None)
        print(f"[done] rows={len(rows)} ok={ok} skip={skip} fail={fail}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
