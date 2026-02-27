#!/usr/bin/env python3
"""
Apply EControlTagFourCC parameter typing to high-confidence command-tag handlers.

Input:
  - dispatch matrix CSV from generate_command_tag_dispatch_matrix.py

Selection rules (conservative):
  1) row kind == handler
  2) row command_tags intersects target set (default: txen,yako,enod)
  3) function has parameters whose names strongly imply control-tag semantics:
     - commandTag / controlTag / dialogActionTag
     - commandId only when function name contains CommandTag
  4) current parameter type is scalar integral (not pointer/struct)
  5) optional widening for `commandId` params via function-name regex gate

Usage:
  .venv/bin/python new_scripts/apply_control_tag_enum_param_types.py \
    --matrix-csv tmp_decomp/batch453_command_tag_dispatch_matrix.csv

  .venv/bin/python new_scripts/apply_control_tag_enum_param_types.py \
    --matrix-csv tmp_decomp/batch453_command_tag_dispatch_matrix.csv --apply

  # broaden commandId handling for dialog/command handlers only
  .venv/bin/python new_scripts/apply_control_tag_enum_param_types.py \
    --matrix-csv tmp_decomp/batch453_command_tag_dispatch_matrix.csv \
    --commandid-name-regex "CommandTag|DialogCommand|CommandTags" --apply
"""

from __future__ import annotations

import argparse
import csv
import re
from pathlib import Path

import pyghidra

GHIDRA_DIR = Path(
    "/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC"
)
PROJECT_NAME = "imperialism-decomp"
PROGRAM_PATH = "/Imperialism.exe"

TAG_PARAM_RE = re.compile(r"(commandtag|controltag|dialogactiontag)", re.IGNORECASE)
CMDID_RE = re.compile(r"^commandid$", re.IGNORECASE)
INTEGRAL_TYPE_RE = re.compile(
    r"^(byte|char|short|ushort|int|uint|long|ulong|undefined1|undefined2|undefined4)$",
    re.IGNORECASE,
)


def open_project_with_lock_cleanup(root: Path):
    try:
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)
    except Exception:
        for lock_file in (root / f"{PROJECT_NAME}.lock", root / f"{PROJECT_NAME}.lock~"):
            if lock_file.exists():
                lock_file.unlink()
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)


def parse_hex(text: str) -> int:
    t = text.strip()
    if t.lower().startswith("0x"):
        return int(t, 16)
    return int(t, 16)


def is_integral_nonptr_type_name(type_name: str) -> bool:
    t = type_name.strip().replace(" ", "")
    if "*" in t:
        return False
    return INTEGRAL_TYPE_RE.match(t) is not None


def load_targets(matrix_csv: Path, tags_wanted: set[str]) -> list[tuple[int, str, set[str]]]:
    rows = []
    with matrix_csv.open("r", encoding="utf-8", newline="") as fh:
        rd = csv.DictReader(fh)
        for row in rd:
            if (row.get("kind") or "").strip().lower() != "handler":
                continue
            faddr = (row.get("function_addr") or "").strip()
            fname = (row.get("function_name") or "").strip()
            ctags = {
                t.strip()
                for t in (row.get("command_tags") or "").split(",")
                if t.strip()
            }
            if not faddr or not fname or not ctags:
                continue
            if not (ctags & tags_wanted):
                continue
            rows.append((parse_hex(faddr), fname, ctags))
    # Dedup by address.
    dedup = {}
    for addr, fname, ctags in rows:
        dedup[addr] = (fname, ctags)
    return [(addr, dedup[addr][0], dedup[addr][1]) for addr in sorted(dedup.keys())]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--matrix-csv", required=True)
    ap.add_argument("--enum-path", default="/Imperialism/EControlTagFourCC")
    ap.add_argument("--tags", default="txen,yako,enod")
    ap.add_argument(
        "--commandid-name-regex",
        default=r"CommandTag",
        help=(
            "Regex gate for treating `commandId` param as control-tag enum; "
            "set empty string to disable commandId widening."
        ),
    )
    ap.add_argument("--apply", action="store_true")
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    matrix_csv = Path(args.matrix_csv)
    if not matrix_csv.exists():
        print(f"[error] missing matrix csv: {matrix_csv}")
        return 1
    tags_wanted = {t.strip() for t in args.tags.split(",") if t.strip()}
    root = Path(args.project_root).resolve()

    cmdid_fn_re = (
        re.compile(args.commandid_name_regex, re.IGNORECASE)
        if args.commandid_name_regex
        else None
    )

    targets = load_targets(matrix_csv, tags_wanted)
    print(f"[targets] handlers={len(targets)} tags={','.join(sorted(tags_wanted))}")

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        from ghidra.program.model.listing import Function, ParameterImpl
        from ghidra.program.model.symbol import SourceType

        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()
        dtm = program.getDataTypeManager()
        enum_dt = dtm.getDataType(args.enum_path)
        if enum_dt is None:
            print(f"[error] missing enum type: {args.enum_path}")
            return 1

        plans = []
        for addr_i, fname_expected, ctags in targets:
            addr = af.getAddress(f"0x{addr_i:08x}")
            fn = fm.getFunctionAt(addr)
            if fn is None:
                continue
            fname = fn.getName()
            params = list(fn.getParameters())
            changed_indexes = []
            for i, p in enumerate(params):
                pname = str(p.getName() or "")
                ptype = str(p.getDataType().getName() or "")
                if not is_integral_nonptr_type_name(ptype):
                    continue

                lower = pname.lower()
                match = TAG_PARAM_RE.search(lower) is not None
                if not match and CMDID_RE.match(lower):
                    if cmdid_fn_re is not None and cmdid_fn_re.search(fname):
                        match = True
                if not match:
                    continue

                changed_indexes.append(i)

            if changed_indexes:
                plans.append((fn, changed_indexes, sorted(ctags)))

        print(f"[plan] functions={len(plans)}")
        for fn, idxs, ctags in plans[:200]:
            ps = list(fn.getParameters())
            idx_desc = ", ".join(
                f"{i}:{ps[i].getName()}:{ps[i].getDataType().getName()}" for i in idxs
            )
            print(
                f"  {fn.getEntryPoint()} {fn.getName()} tags={','.join(ctags)} "
                f"-> [{idx_desc}] => {enum_dt.getName()}"
            )
        if len(plans) > 200:
            print(f"... ({len(plans) - 200} more)")

        if not args.apply:
            print("[dry-run] pass --apply to write changes")
            return 0

        tx = program.startTransaction("Apply EControlTagFourCC parameter types")
        ok = skip = fail = 0
        try:
            for fn, idxs, _ctags in plans:
                try:
                    old_sig = str(fn.getSignature())
                    old_params = list(fn.getParameters())
                    new_params = []
                    for i, p in enumerate(old_params):
                        dt = p.getDataType()
                        if i in idxs:
                            dt = enum_dt
                        new_params.append(
                            ParameterImpl(
                                p.getName(),
                                dt,
                                program,
                                SourceType.USER_DEFINED,
                            )
                        )
                    fn.replaceParameters(
                        Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
                        True,
                        SourceType.USER_DEFINED,
                        new_params,
                    )
                    new_sig = str(fn.getSignature())
                    if new_sig == old_sig:
                        skip += 1
                    else:
                        ok += 1
                except Exception as ex:
                    fail += 1
                    print(f"[fail] {fn.getEntryPoint()} {fn.getName()} err={ex}")
        finally:
            program.endTransaction(tx, True)

        program.save("apply control-tag enum parameter types", None)
        print(f"[done] ok={ok} skip={skip} fail={fail}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
