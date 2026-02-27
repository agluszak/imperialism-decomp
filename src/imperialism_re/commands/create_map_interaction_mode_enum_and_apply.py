#!/usr/bin/env python3
"""
Create/update map-interaction enum and apply typing/comments to selected callsites.
"""

from __future__ import annotations

import argparse

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.datatypes import project_category_path
from imperialism_re.core.ghidra_session import open_program


def parse_int_auto(text: str) -> int:
    return int(text, 0)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--enum-name", required=True)
    ap.add_argument(
        "--enum-size",
        type=int,
        default=2,
        help="Enum storage size in bytes",
    )
    ap.add_argument(
        "--set-mode-name-substring",
        required=True,
        help="Substring to locate Set* function(s) whose second param should be enum-typed",
    )
    ap.add_argument(
        "--call-thunk-addr",
        required=True,
        help="Thunk/function address whose callsites should be scanned for PUSH immediate mode values",
    )
    ap.add_argument(
        "--fallback-values",
        default="0,1,2,3,4,5",
        help="Comma-separated values used when no callsite immediates are found",
    )
    ap.add_argument("--project-root", default=default_project_root())
    args = ap.parse_args()

    root = resolve_project_root(args.project_root)
    thunk_addr_int = parse_int_auto(args.call_thunk_addr)
    fallback_values = [int(v.strip(), 0) for v in args.fallback_values.split(",") if v.strip()]

    with open_program(root) as program:
        from ghidra.program.model.data import CategoryPath, DataTypeConflictHandler, EnumDataType
        from ghidra.program.model.listing import CodeUnit, Function, ParameterImpl
        from ghidra.program.model.symbol import SourceType

        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()
        listing = program.getListing()
        refman = program.getReferenceManager()
        dtm = program.getDataTypeManager()

        # Collect mode-setting targets.
        targets = []
        fit = fm.getFunctions(True)
        while fit.hasNext():
            f = fit.next()
            if args.set_mode_name_substring in f.getName():
                targets.append(f)

        # Collect observed immediate values from thunk callsites.
        observed_values = set()
        callsite_push = []  # (push_addr, value, caller_name)
        thunk = fm.getFunctionAt(af.getAddress(f"0x{thunk_addr_int:08x}"))
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

        vals = sorted(v for v in observed_values if 0 <= v <= 0xFFFF)
        if not vals:
            vals = sorted(set(fallback_values))

        tx = program.startTransaction("Create/apply map interaction mode enum")
        try:
            enum_dt = EnumDataType(
                CategoryPath(project_category_path()), args.enum_name, args.enum_size
            )
            for v in vals:
                enum_dt.add(f"MAP_INTERACTION_MODE_{v}", v)
            enum_dt = dtm.addDataType(enum_dt, DataTypeConflictHandler.REPLACE_HANDLER)
            print(f"[enum] {enum_dt.getPathName()} values={len(vals)} set={vals}")

            typed_ok = typed_skip = typed_fail = 0
            for f in targets:
                try:
                    params = list(f.getParameters())
                    if len(params) < 2:
                        typed_skip += 1
                        continue
                    # __thiscall SetX(this, mode)
                    mode_idx = 1
                    old_sig = str(f.getSignature())
                    new_params = []
                    for idx, p in enumerate(params):
                        dt = enum_dt if idx == mode_idx else p.getDataType()
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

            ann = 0
            for addr, val, caller_name in callsite_push:
                comment = f"{args.enum_name}::MAP_INTERACTION_MODE_{val} ({val})"
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
