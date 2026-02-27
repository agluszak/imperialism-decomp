#!/usr/bin/env python3
"""
Normalize `__thiscall` functions that redundantly keep explicit first `pThis`.

Pattern fixed:
  __thiscall Func(<Class>* this, <Class>* pThis, ...)
to:
  __thiscall Func(<Class>* this, ...)
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
    ap.add_argument("--max-print", type=int, default=240)
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    do_apply = args.apply and not args.dry_run
    root = Path(args.project_root).resolve()

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        from ghidra.program.model.listing import Function, ParameterImpl
        from ghidra.program.model.symbol import SourceType

        fm = program.getFunctionManager()

        candidates = []
        fit = fm.getFunctions(True)
        while fit.hasNext():
            f = fit.next()
            cc = f.getCallingConventionName() or ""
            if cc != "__thiscall":
                continue
            params = list(f.getParameters())
            if len(params) < 2:
                continue
            p0 = params[0]
            p1 = params[1]
            if (p0.getName() or "") != "this":
                continue
            if (p1.getName() or "") != "pThis":
                continue
            # Extra guard: only touch obvious redundant pattern in signature text.
            sig = str(f.getSignature())
            if " this, " not in sig or " pThis" not in sig:
                continue
            candidates.append((f, params, sig))

        print(f"[candidates] {len(candidates)}")
        for f, _params, sig in candidates[: args.max_print]:
            addr = f.getEntryPoint().getOffset() & 0xFFFFFFFF
            print(f"  0x{addr:08x} {f.getName()} sig={sig}")
        if len(candidates) > args.max_print:
            print(f"  ... ({len(candidates) - args.max_print} more)")

        if not do_apply:
            print("[dry-run] pass --apply to write changes")
            return 0

        tx = program.startTransaction("Normalize redundant pThis on __thiscall")
        ok = skip = fail = 0
        try:
            for f, params, _sig in candidates:
                try:
                    old_sig = str(f.getSignature())
                    new_params = []
                    kept = [params[0], *params[2:]]
                    for idx, p in enumerate(kept):
                        if idx == 0:
                            nm = "this"
                        else:
                            nm = f"arg{idx}"
                        dt = p.getDataType()
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
                    print(f"[fail] 0x{addr:08x} {f.getName()} err={ex}")
        finally:
            program.endTransaction(tx, True)

        program.save("normalize redundant pThis thiscall", None)
        print(f"[done] ok={ok} skip={skip} fail={fail}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
