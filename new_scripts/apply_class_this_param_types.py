#!/usr/bin/env python3
"""
Retype first method parameter to ClassName* for class namespace methods.

Conservative rules:
  - function must be in namespace T*
  - class datatype with matching name must exist
  - function must have at least 1 parameter
  - first parameter type must be generic-ish (void*/undefined*/int/uint)

Usage:
  .venv/bin/python new_scripts/apply_class_this_param_types.py \
    --classes TEditText TStaticText TView TGameWindow TMultiplayerMgr \
    --dry-run

  .venv/bin/python new_scripts/apply_class_this_param_types.py \
    --classes TEditText TStaticText TView TGameWindow TMultiplayerMgr \
    --apply

  .venv/bin/python new_scripts/apply_class_this_param_types.py \
    --all-classes \
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

GENERIC_FIRST_PARAM_TYPES = {
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


def find_datatype_by_name(dtm, name: str):
    # Prefer /imperialism/classes/name, then any matching datatype by name.
    from ghidra.program.model.data import CategoryPath

    dt = dtm.getDataType(CategoryPath("/imperialism/classes"), name)
    if dt is not None:
        return dt

    it = dtm.getAllDataTypes()
    while it.hasNext():
        cand = it.next()
        if cand.getName() == name:
            return cand
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--classes", nargs="+", default=[], help="Class namespaces to target")
    ap.add_argument(
        "--all-classes",
        action="store_true",
        help="Target all class namespaces with a matching datatype",
    )
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
        from ghidra.program.model.data import PointerDataType
        from ghidra.program.model.listing import Function, ParameterImpl
        from ghidra.program.model.symbol import SourceType

        fm = program.getFunctionManager()
        dtm = program.getDataTypeManager()
        global_ns = program.getGlobalNamespace()

        if args.all_classes:
            st = program.getSymbolTable()
            it_cls = st.getClassNamespaces()
            while it_cls.hasNext():
                cls = it_cls.next().getName()
                if cls:
                    target_classes.add(cls)

        if not target_classes:
            print("[error] no classes selected (use --classes ... or --all-classes)")
            return 1

        class_ptr_types = {}
        for cls in sorted(target_classes):
            dt = find_datatype_by_name(dtm, cls)
            if dt is None:
                print(f"[skip-class] missing datatype: {cls}")
                continue
            class_ptr_types[cls] = PointerDataType(dt)

        candidates = []
        fit = fm.getFunctions(True)
        while fit.hasNext():
            f = fit.next()
            ns = f.getParentNamespace()
            if ns is None or ns == global_ns:
                continue
            cls = ns.getName()
            if cls not in class_ptr_types:
                continue

            params = list(f.getParameters())
            if not params:
                continue
            p0 = params[0]
            p0_type = p0.getDataType().getName()
            if p0_type not in GENERIC_FIRST_PARAM_TYPES:
                continue

            candidates.append((f, cls, p0_type, params))

        print(f"[candidates] {len(candidates)}")
        for f, cls, p0_type, params in candidates[:300]:
            addr = f.getEntryPoint().getOffset() & 0xFFFFFFFF
            print(f"  0x{addr:08x} {cls}::{f.getName()} p0={p0_type} sig={f.getSignature()}")
        if len(candidates) > 300:
            print(f"  ... ({len(candidates)-300} more)")

        if not do_apply:
            print("[dry-run] pass --apply to write changes")
            return 0

        tx = program.startTransaction("Apply class this param types")
        ok = skip = fail = 0
        try:
            for f, cls, _p0_type, params in candidates:
                try:
                    old_sig = str(f.getSignature())
                    new_params = []
                    for i, p in enumerate(params):
                        nm = p.getName() or ("pThis" if i == 0 else f"param_{i+1}")
                        dt = class_ptr_types[cls] if i == 0 else p.getDataType()
                        if i == 0:
                            nm = "pThis"
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

        program.save("apply class this param types", None)
        print(f"[done] ok={ok} skip={skip} fail={fail}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
