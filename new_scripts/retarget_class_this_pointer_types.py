#!/usr/bin/env python3
"""
Retarget class-method first parameter ("this") to /imperialism/classes/<Class>.

Use this when duplicate datatypes exist (e.g. root "/" stubs + real class structs),
and method signatures point at the wrong one.

Conservative behavior:
  - only touches methods in requested class namespaces
  - only rewrites first parameter
  - keeps calling convention/other params unchanged

Usage:
  .venv/bin/python new_scripts/retarget_class_this_pointer_types.py \
    --classes TMyClass TOtherClass \
    --apply
"""

from __future__ import annotations

import argparse
from pathlib import Path

import pyghidra

GHIDRA_DIR = Path(
    "/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC"
)
PROJECT_NAME = "imperialism-decomp"
PROGRAM_PATH = "/Imperialism.exe"

GENERIC_P0_TYPES = {
    "void *",
    "undefined *",
    "undefined4",
    "undefined8",
}


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
    ap.add_argument("--classes", nargs="+", required=True, help="Class namespaces to target")
    ap.add_argument("--apply", action="store_true", help="Write changes")
    ap.add_argument("--dry-run", action="store_true", help="Preview only")
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    do_apply = args.apply and not args.dry_run
    target_classes = set(args.classes)

    root = Path(args.project_root).resolve()
    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        from ghidra.program.model.data import CategoryPath, PointerDataType, TypeDef
        from ghidra.program.model.listing import Function, ParameterImpl
        from ghidra.program.model.symbol import SourceType

        fm = program.getFunctionManager()
        dtm = program.getDataTypeManager()
        global_ns = program.getGlobalNamespace()

        preferred_ptr_type = {}
        for cls in sorted(target_classes):
            dt = dtm.getDataType(CategoryPath("/imperialism/classes"), cls)
            if dt is None:
                print(f"[skip-class] missing /imperialism/classes/{cls}")
                continue
            preferred_ptr_type[cls] = PointerDataType(dt)

        def unwrap_typedef(dt):
            cur = dt
            hops = 0
            while isinstance(cur, TypeDef) and hops < 8:
                cur = cur.getDataType()
                hops += 1
            return cur

        candidates = []
        fit = fm.getFunctions(True)
        while fit.hasNext():
            f = fit.next()
            ns = f.getParentNamespace()
            if ns is None or ns == global_ns:
                continue
            cls = ns.getName()
            if cls not in preferred_ptr_type:
                continue

            params = list(f.getParameters())
            if not params:
                continue
            p0 = params[0]
            p0_dt = p0.getDataType()
            p0_name = p0_dt.getName()

            should_retarget = False
            reason = ""
            if p0_name in GENERIC_P0_TYPES:
                should_retarget = True
                reason = "generic"
            else:
                try:
                    base = unwrap_typedef(p0_dt)
                    if base.getName().endswith("*"):
                        base = base.getDataType()
                except Exception:
                    base = None
                if base is not None:
                    try:
                        base_name = base.getName()
                        base_cat = str(base.getCategoryPath().getPath())
                        if base_name == cls and base_cat != "/imperialism/classes":
                            should_retarget = True
                            reason = f"{base_cat}->{'/imperialism/classes'}"
                    except Exception:
                        pass

            if should_retarget:
                candidates.append((f, cls, reason, params))

        print(f"[candidates] {len(candidates)}")
        for f, cls, reason, _params in candidates[:300]:
            addr = f.getEntryPoint().getOffset() & 0xFFFFFFFF
            print(f"  0x{addr:08x} {cls}::{f.getName()} reason={reason} sig={f.getSignature()}")
        if len(candidates) > 300:
            print(f"  ... ({len(candidates)-300} more)")

        if not do_apply:
            print("[dry-run] pass --apply to write changes")
            return 0

        tx = program.startTransaction("Retarget class this pointer types")
        ok = skip = fail = 0
        try:
            for f, cls, _reason, params in candidates:
                try:
                    old_sig = str(f.getSignature())
                    new_params = []
                    for i, p in enumerate(params):
                        if i == 0:
                            dt = preferred_ptr_type[cls]
                            nm = "this"
                        else:
                            dt = p.getDataType()
                            nm = p.getName() or f"param_{i+1}"
                        new_params.append(ParameterImpl(nm, dt, program, SourceType.USER_DEFINED))

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
                    print(f"[fail] 0x{addr:08x} {cls}::{f.getName()} err={ex}")
        finally:
            program.endTransaction(tx, True)

        program.save("retarget class this pointer types", None)
        print(f"[done] ok={ok} skip={skip} fail={fail}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
