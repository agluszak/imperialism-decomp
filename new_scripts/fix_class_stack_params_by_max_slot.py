#!/usr/bin/env python3
"""
Convert positive in_stack_* usage into explicit stack parameters for class methods.

Conservative gates:
  - class namespace matches regex
  - function already has exactly one param (assumed pThis)
  - decompiled C has no in_ECX
  - positive in_stack slots exist and max slot <= threshold (default 0x10)

Applied signature shape:
  __thiscall <ret> Func(<this_type> pThis, int arg1, ..., int argN)
where N = max_slot / 4.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

import pyghidra

GHIDRA_DIR = Path(
    "/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC"
)
PROJECT_NAME = "imperialism-decomp"
PROGRAM_PATH = "/Imperialism.exe"

STACK_RE = re.compile(r"\bin_stack_([0-9a-fA-F]{8})\b")


def parse_hex(text: str) -> int:
    t = text.strip().lower()
    if t.startswith("0x"):
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
    ap.add_argument("--apply", action="store_true", help="Write changes")
    ap.add_argument("--dry-run", action="store_true", help="Preview only")
    ap.add_argument(
        "--class-regex",
        default=r"^(TMap|TViewMgr|TApplication|TAmbitApplication|TMacViewMgr|TWorldView|TAssetMgr|TArmyMgr|TCivMgr)",
    )
    ap.add_argument("--addr-min", default="0x00400000")
    ap.add_argument("--addr-max", default="0x0062ffff")
    ap.add_argument("--max-slot", default="0x10", help="Max positive stack slot allowed")
    ap.add_argument("--max-print", type=int, default=200)
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    do_apply = args.apply and not args.dry_run
    class_re = re.compile(args.class_regex)
    lo = parse_hex(args.addr_min)
    hi = parse_hex(args.addr_max)
    max_slot = parse_hex(args.max_slot)
    root = Path(args.project_root).resolve()

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        from ghidra.app.decompiler import DecompInterface
        from ghidra.program.model.data import IntegerDataType
        from ghidra.program.model.listing import Function, ParameterImpl
        from ghidra.program.model.symbol import SourceType

        fm = program.getFunctionManager()
        global_ns = program.getGlobalNamespace()

        ifc = DecompInterface()
        ifc.openProgram(program)

        candidates = []

        fit = fm.getFunctions(True)
        while fit.hasNext():
            f = fit.next()
            addr = f.getEntryPoint().getOffset() & 0xFFFFFFFF
            if addr < lo or addr > hi:
                continue

            ns = f.getParentNamespace()
            if ns is None or ns == global_ns:
                continue
            cls = ns.getName()
            if not class_re.search(cls):
                continue

            params = list(f.getParameters())
            if len(params) != 1:
                continue

            res = ifc.decompileFunction(f, 20, None)
            if not res or not res.decompileCompleted():
                continue
            c_code = res.getDecompiledFunction().getC()
            if "in_ECX" in c_code:
                continue

            slots = sorted(
                {
                    int(m, 16)
                    for m in STACK_RE.findall(c_code)
                    if int(m, 16) < 0x80000000
                }
            )
            if not slots:
                continue

            mslot = max(slots)
            if mslot > max_slot:
                continue
            if mslot % 4 != 0:
                continue
            add_count = mslot // 4
            if add_count <= 0 or add_count > 8:
                continue

            candidates.append((f, cls, slots, add_count, params[0].getDataType()))

        print(
            f"[candidates] {len(candidates)} class_regex={args.class_regex} "
            f"range=0x{lo:08x}-0x{hi:08x} max_slot=0x{max_slot:08x}"
        )
        for f, cls, slots, add_count, _this_dt in candidates[: args.max_print]:
            addr = f.getEntryPoint().getOffset() & 0xFFFFFFFF
            slots_txt = ",".join(f"0x{x:08x}" for x in slots)
            print(
                f"  0x{addr:08x} {cls}::{f.getName()} "
                f"slots=[{slots_txt}] add_count={add_count} sig={f.getSignature()}"
            )
        if len(candidates) > args.max_print:
            print(f"  ... ({len(candidates) - args.max_print} more)")

        if not do_apply:
            print("[dry-run] pass --apply to write changes")
            return 0

        tx = program.startTransaction("Fix class stack params by max slot")
        ok = skip = fail = 0
        try:
            for f, _cls, _slots, add_count, this_dt in candidates:
                try:
                    old_sig = str(f.getSignature())
                    f.setCallingConvention("__thiscall")

                    new_params = [
                        ParameterImpl("pThis", this_dt, program, SourceType.USER_DEFINED)
                    ]
                    for i in range(add_count):
                        new_params.append(
                            ParameterImpl(
                                f"arg{i+1}",
                                IntegerDataType.dataType,
                                program,
                                SourceType.USER_DEFINED,
                            )
                        )

                    f.replaceParameters(
                        Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
                        True,
                        SourceType.USER_DEFINED,
                        new_params,
                    )
                    new_sig = str(f.getSignature())
                    if new_sig == old_sig:
                        skip += 1
                    else:
                        ok += 1
                except Exception as ex:
                    fail += 1
                    addr = f.getEntryPoint().getOffset() & 0xFFFFFFFF
                    print(f"[fail] 0x{addr:08x} err={ex}")
        finally:
            program.endTransaction(tx, True)

        program.save("fix class stack params by max slot", None)
        print(f"[done] ok={ok} skip={skip} fail={fail}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

