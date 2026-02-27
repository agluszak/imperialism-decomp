#!/usr/bin/env python3
"""
Annotate turn-instruction table-dispatch internals with enum-aware comments.
"""

from __future__ import annotations

import argparse

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.ghidra_session import open_program


def _ins_immediates(ins) -> list[int]:
    from ghidra.program.model.scalar import Scalar

    out: list[int] = []
    try:
        nops = int(ins.getNumOperands())
    except Exception:
        return out
    for i in range(nops):
        try:
            for obj in ins.getOpObjects(i):
                if isinstance(obj, Scalar):
                    out.append(int(obj.getUnsignedValue() & 0xFFFFFFFF))
        except Exception:
            continue
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--functions",
        default="0x00581e60,0x00406730",
        help="Comma-separated dispatcher/thunk addresses",
    )
    ap.add_argument("--project-root", default=default_project_root())
    args = ap.parse_args()

    targets = []
    for part in (args.functions or "").split(","):
        p = part.strip()
        if not p:
            continue
        targets.append(int(p, 0))
    if not targets:
        print("[error] no function targets")
        return 1

    root = resolve_project_root(args.project_root)
    with open_program(root) as program:
        from ghidra.program.model.listing import CodeUnit

        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()
        listing = program.getListing()

        tx = program.startTransaction("Annotate turn-instruction dispatch internals")
        try:
            touched = 0
            for va in targets:
                fn = fm.getFunctionAt(af.getAddress(f"0x{va:08x}"))
                if fn is None:
                    print(f"[skip] missing function 0x{va:08x}")
                    continue
                fn.setComment(
                    "[TurnDispatch] Streams ETurnInstructionTokenFourCC tokens, "
                    "resolves ETurnInstructionDispatchIndex via token table scan, "
                    "and dispatches handlers through g_apfnTurnInstructionHandlerByIndex."
                )
                ins_it = listing.getInstructions(fn.getBody(), True)
                while ins_it.hasNext():
                    ins = ins_it.next()
                    vals = _ins_immediates(ins)
                    if not vals:
                        continue
                    cmt = None
                    if 0x5445524D in vals:
                        cmt = "TURN_TOKEN_TERM ('TERM') stream terminator sentinel."
                    elif 0x006629E4 in vals:
                        cmt = "g_aeTurnInstructionTokenFourCCByIndex_End (table bound sentinel)."
                    elif 0x00662978 in vals:
                        cmt = "g_aeTurnInstructionTokenFourCCByIndex table base."
                    if cmt:
                        listing.setComment(ins.getAddress(), CodeUnit.EOL_COMMENT, cmt)
                        touched += 1
                        print(f"[annotated] {ins.getAddress()} {cmt}")
        finally:
            program.endTransaction(tx, True)

        program.save("annotate turn-instruction dispatch internals", None)
        print(f"[done] touched={touched}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
