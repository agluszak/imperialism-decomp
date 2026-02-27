#!/usr/bin/env python3
"""
Apply EControlTagFourCC parameter typing to high-confidence command-tag handlers.

Input:
  - dispatch matrix CSV from generate_command_tag_dispatch_matrix.py
"""

from __future__ import annotations

import argparse
import csv
import re
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.datatypes import project_datatype_path, resolve_datatype_by_path_or_legacy_aliases
from imperialism_re.core.ghidra_session import open_program
from imperialism_re.core.typing_utils import parse_hex

TAG_PARAM_RE = re.compile(r"(commandtag|controltag|dialogactiontag)", re.IGNORECASE)
CMDID_RE = re.compile(r"^commandid$", re.IGNORECASE)
INTEGRAL_TYPE_RE = re.compile(
    r"^(byte|char|short|ushort|int|uint|long|ulong|undefined1|undefined2|undefined4)$",
    re.IGNORECASE,
)


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
            ctags = {t.strip() for t in (row.get("command_tags") or "").split(",") if t.strip()}
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
    ap.add_argument("--tags", required=True, help="Comma-separated tag_le values to target")
    ap.add_argument(
        "--commandid-name-regex",
        default="",
        help=(
            "Regex gate for treating `commandId` param as control-tag enum; "
            "set empty string to disable commandId widening."
        ),
    )
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--project-root", default=default_project_root())
    args = ap.parse_args()

    root = resolve_project_root(args.project_root)
    matrix_csv = Path(args.matrix_csv)
    if not matrix_csv.is_absolute():
        matrix_csv = root / matrix_csv
    if not matrix_csv.exists():
        print(f"[error] missing matrix csv: {matrix_csv}")
        return 1
    tags_wanted = {t.strip() for t in args.tags.split(",") if t.strip()}

    cmdid_fn_re = re.compile(args.commandid_name_regex, re.IGNORECASE) if args.commandid_name_regex else None

    targets = load_targets(matrix_csv, tags_wanted)
    print(f"[targets] handlers={len(targets)} tags={','.join(sorted(tags_wanted))}")

    with open_program(root) as program:
        from ghidra.program.model.listing import Function, ParameterImpl
        from ghidra.program.model.symbol import SourceType

        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()
        dtm = program.getDataTypeManager()
        enum_dt = resolve_datatype_by_path_or_legacy_aliases(
            dtm, project_datatype_path("EControlTagFourCC")
        )
        if enum_dt is None:
            print("[error] missing enum type: /imperialism/EControlTagFourCC")
            return 1

        plans = []
        for addr_i, _fname_expected, ctags in targets:
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
