#!/usr/bin/env python3
"""
Annotate control-tag FourCC immediates in command-tag handler functions.

Primary focus tags:
  - txen
  - yako
  - enod

Secondary tags:
  - kcab/verp/ofni/pleh
"""

from __future__ import annotations

from pathlib import Path

import pyghidra

GHIDRA_DIR = Path(
    "/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC"
)
PROJECT_NAME = "imperialism-decomp"
PROGRAM_PATH = "/Imperialism.exe"

TAG_TO_ENUM = {
    "txen": "CONTROL_TAG_TXEN",
    "yako": "CONTROL_TAG_YAKO",
    "enod": "CONTROL_TAG_ENOD",
    "kcab": "CONTROL_TAG_KCAB",
    "verp": "CONTROL_TAG_VERP",
    "ofni": "CONTROL_TAG_OFNI",
    "pleh": "CONTROL_TAG_PLEH",
}


def open_project_with_lock_cleanup(root: Path):
    try:
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)
    except Exception:
        for lock_file in (root / f"{PROJECT_NAME}.lock", root / f"{PROJECT_NAME}.lock~"):
            if lock_file.exists():
                lock_file.unlink()
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)


def tag_le_to_u32(tag: str) -> int:
    b = tag.encode("ascii", errors="strict")
    if len(b) != 4:
        raise ValueError(f"tag must be 4 chars: {tag!r}")
    return int.from_bytes(b, byteorder="little", signed=False)


def is_command_tag_handler_name(name: str) -> bool:
    n = name.lower()
    return (
        "commandtag" in n
        or "commandtags" in n
        or ("handle" in n and "tag" in n and "command" in n)
    )


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    val_to_tag = {tag_le_to_u32(tag): tag for tag in TAG_TO_ENUM}

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        from ghidra.program.model.listing import CodeUnit

        fm = program.getFunctionManager()
        listing = program.getListing()

        tx = program.startTransaction("Annotate control tag constants")
        scanned_funcs = 0
        annotations = 0
        try:
            fit = fm.getFunctions(True)
            while fit.hasNext():
                fn = fit.next()
                fn_name = fn.getName()
                if not is_command_tag_handler_name(fn_name):
                    continue
                scanned_funcs += 1

                ins_it = listing.getInstructions(fn.getBody(), True)
                while ins_it.hasNext():
                    ins = ins_it.next()
                    found = None
                    for oi in range(ins.getNumOperands()):
                        sc = ins.getScalar(oi)
                        if sc is None:
                            continue
                        try:
                            val = int(sc.getUnsignedValue())
                        except Exception:
                            continue
                        if val in val_to_tag:
                            found = val_to_tag[val]
                            break
                    if found is None:
                        continue

                    enum_member = TAG_TO_ENUM[found]
                    comment = f"EControlTagFourCC::{enum_member} ('{found}')"
                    prev = listing.getComment(CodeUnit.EOL_COMMENT, ins.getAddress())
                    if prev == comment:
                        continue
                    listing.setComment(ins.getAddress(), CodeUnit.EOL_COMMENT, comment)
                    annotations += 1
                    print(f"[annotated] {ins.getAddress()} {fn_name}: {comment}")
        finally:
            program.endTransaction(tx, True)

        program.save("annotate control tag constants", None)
        print(f"[done] scanned_functions={scanned_funcs} annotations_set={annotations}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
