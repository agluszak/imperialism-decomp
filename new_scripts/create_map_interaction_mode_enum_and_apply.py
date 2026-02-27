#!/usr/bin/env python3
"""
Create EMapInteractionMode from observed SetMapInteractionMode callsites and apply typing/comments.

Actions:
1) Create/update enum: /Imperialism/EMapInteractionMode
2) Set SetMapInteractionMode / thunk parameter #1 to EMapInteractionMode
3) Annotate immediate PUSH values at callsites into thunk_SetMapInteractionMode
"""

from __future__ import annotations

from pathlib import Path

import pyghidra

GHIDRA_DIR = Path(
    "/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC"
)
PROJECT_NAME = "imperialism-decomp"
PROGRAM_PATH = "/Imperialism.exe"

ENUM_PATH = "/Imperialism/EMapInteractionMode"


def open_project_with_lock_cleanup(root: Path):
    try:
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)
    except Exception:
        for lock_file in (root / f"{PROJECT_NAME}.lock", root / f"{PROJECT_NAME}.lock~"):
            if lock_file.exists():
                lock_file.unlink()
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        from ghidra.program.model.data import CategoryPath, DataTypeConflictHandler, EnumDataType
        from ghidra.program.model.listing import CodeUnit, Function, ParameterImpl
        from ghidra.program.model.symbol import SourceType

        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()
        listing = program.getListing()
        refman = program.getReferenceManager()
        dtm = program.getDataTypeManager()

        # Collect SetMapInteractionMode targets.
        targets = []
        fit = fm.getFunctions(True)
        while fit.hasNext():
            f = fit.next()
            if "SetMapInteractionMode" in f.getName():
                targets.append(f)

        # Collect observed immediate values from thunk callsites.
        observed_values = set()
        callsite_push = []  # (push_addr, value, caller_name)
        thunk = fm.getFunctionAt(af.getAddress("0x004032a1"))
        if thunk is not None:
            refs = refman.getReferencesTo(thunk.getEntryPoint())
            for r in refs:
                call_ins = listing.getInstructionAt(r.getFromAddress())
                caller = fm.getFunctionContaining(r.getFromAddress())
                if call_ins is None or caller is None:
                    continue
                cur = call_ins.getPrevious()
                k = 0
                found = None
                found_addr = None
                while cur is not None and k < 10:
                    if str(cur.getMnemonicString()).upper() == "PUSH":
                        sc = cur.getScalar(0)
                        if sc is not None:
                            v = int(sc.getUnsignedValue()) & 0xFFFFFFFF
                            if v < 0x10000:
                                found = v
                                found_addr = cur.getAddress()
                                break
                    cur = cur.getPrevious()
                    k += 1
                if found is not None:
                    observed_values.add(found)
                    callsite_push.append((found_addr, found, caller.getName()))

        # Conservative expected range from observed values.
        vals = sorted(v for v in observed_values if 0 <= v <= 0xFF)
        if not vals:
            vals = [0, 1, 2, 3, 4, 5]

        tx = program.startTransaction("Create/apply EMapInteractionMode")
        try:
            enum_dt = EnumDataType(CategoryPath("/Imperialism"), "EMapInteractionMode", 2)
            for v in vals:
                enum_dt.add(f"MAP_INTERACTION_MODE_{v}", v)
            enum_dt = dtm.addDataType(enum_dt, DataTypeConflictHandler.REPLACE_HANDLER)
            print(f"[enum] {enum_dt.getPathName()} values={len(vals)} set={vals}")

            # Apply parameter type in SetMapInteractionMode functions.
            typed_ok = typed_skip = typed_fail = 0
            for f in targets:
                try:
                    params = list(f.getParameters())
                    if len(params) < 2:
                        typed_skip += 1
                        continue
                    # For __thiscall SetMapInteractionMode(this, nMode), index 1 is mode.
                    i = 1
                    old_sig = str(f.getSignature())
                    new_params = []
                    for idx, p in enumerate(params):
                        dt = enum_dt if idx == i else p.getDataType()
                        new_params.append(
                            ParameterImpl(
                                p.getName(),
                                dt,
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
                    if str(f.getSignature()) == old_sig:
                        typed_skip += 1
                    else:
                        typed_ok += 1
                except Exception as ex:
                    typed_fail += 1
                    print(f"[fail-typing] {f.getEntryPoint()} {f.getName()} err={ex}")
            print(f"[typing] ok={typed_ok} skip={typed_skip} fail={typed_fail}")

            # Annotate callsite immediate pushes.
            ann = 0
            for addr, val, caller_name in callsite_push:
                comment = f"EMapInteractionMode::MAP_INTERACTION_MODE_{val} ({val})"
                prev = listing.getComment(CodeUnit.EOL_COMMENT, addr)
                if prev == comment:
                    continue
                listing.setComment(addr, CodeUnit.EOL_COMMENT, comment)
                ann += 1
                print(f"[annotated] {addr} {caller_name}: {comment}")
            print(f"[annotate] set={ann}")
        finally:
            program.endTransaction(tx, True)

        program.save("create/apply map interaction mode enum", None)
        print("[done]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

