#!/usr/bin/env python3
"""
Annotate immediate 0x64/0x65 constants in split-arrow handlers.
"""

from __future__ import annotations

import argparse

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.ghidra_session import open_program


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--function-names",
        required=True,
        help="Comma-separated function names to scan",
    )
    ap.add_argument("--left-value", type=lambda x: int(x, 0), default=0x64)
    ap.add_argument("--right-value", type=lambda x: int(x, 0), default=0x65)
    ap.add_argument("--left-comment", default="EArrowSplitCommandId::ARROW_SPLIT_CMD_LEFT")
    ap.add_argument("--right-comment", default="EArrowSplitCommandId::ARROW_SPLIT_CMD_RIGHT")
    ap.add_argument("--project-root", default=default_project_root())
    args = ap.parse_args()
    root = resolve_project_root(args.project_root)
    target_funcs = {x.strip() for x in args.function_names.split(",") if x.strip()}
    if not target_funcs:
        print("[error] no function names provided")
        return 1

    with open_program(root) as program:
        from ghidra.program.model.listing import CodeUnit

        fm = program.getFunctionManager()
        listing = program.getListing()

        tx = program.startTransaction("Annotate arrow command constants")
        changed = 0
        scanned = 0
        try:
            for fn in fm.getFunctions(True):
                name = fn.getName()
                if name not in target_funcs:
                    continue
                scanned += 1
                ins_it = listing.getInstructions(fn.getBody(), True)
                while ins_it.hasNext():
                    ins = ins_it.next()
                    comment = None
                    for oi in range(ins.getNumOperands()):
                        sc = ins.getScalar(oi)
                        if sc is None:
                            continue
                        try:
                            val = int(sc.getUnsignedValue())
                        except Exception:
                            continue
                        if val == args.left_value:
                            comment = f"{args.left_comment} (0x{args.left_value:x})"
                            break
                        if val == args.right_value:
                            comment = f"{args.right_comment} (0x{args.right_value:x})"
                            break
                    if comment is None:
                        continue
                    prev = listing.getComment(CodeUnit.EOL_COMMENT, ins.getAddress())
                    if prev == comment:
                        continue
                    listing.setComment(ins.getAddress(), CodeUnit.EOL_COMMENT, comment)
                    changed += 1
                    print(f"[annotated] {ins.getAddress()} {name}: {comment}")
        finally:
            program.endTransaction(tx, True)

        program.save("annotate arrow command constants", None)
        print(f"[done] scanned_functions={scanned} annotations_set={changed}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
