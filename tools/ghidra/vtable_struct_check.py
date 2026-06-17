#!/usr/bin/env python3
"""Assert Ghidra vtable struct field names at byte offsets (datatype-level checks).

Complements decomp_check.py: verifies the DB struct naming independent of
decompiler composite indexing quirks. When the vtable struct datatype is
truncated, falls back to the resolved function name at the PE slot address.

Usage:
  uv run python -m tools.ghidra.vtable_struct_check
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass

VTABLE_HEADER = re.compile(
    r"^\s*//\s*VTABLE:\s*IMPERIALISM\s+(0x[0-9a-fA-F]+)",
    re.IGNORECASE,
)
CLASS_DECL = re.compile(r"^\s*class\s+(\w+)")


@dataclass(frozen=True)
class StructFieldCheck:
    struct_name: str
    byte_offset: int
    field_name: str
    vtable_addr: int | None = None
    note: str = ""


# Regression anchors — datatype names in /MFC/vtables/ plus PE vtable fallbacks.
CHECKS: tuple[StructFieldCheck, ...] = (
    StructFieldCheck(
        "TSimMgrVtbl",
        0x84,
        "LoadUiStringByCodeGroupAndOffset",
        vtable_addr=0x00662A58,
        note="slot 0x21 / UI string loader; listing CALL [vptr+0x84] @ 0x0050C1BF",
    ),
    StructFieldCheck(
        "TSimMgrVtbl",
        0x74,
        "FormatSignedIntWithSingleThousandsSeparator",
        vtable_addr=0x00662A58,
        note="slot 0x1d",
    ),
)


def field_name_at_offset(dtm, struct_name: str, byte_offset: int) -> str | None:
    from ghidra.program.model.data import CategoryPath

    dt = dtm.getDataType(CategoryPath("/MFC/vtables"), struct_name)
    if dt is None:
        dt = dtm.getDataType(CategoryPath.ROOT, struct_name)
    if dt is None or dt.getLength() <= byte_offset:
        return None
    comp = dt.getComponentAt(byte_offset)
    if comp is None:
        for i in range(dt.getNumComponents()):
            comp_i = dt.getComponent(i)
            if comp_i.getOffset() == byte_offset:
                return comp_i.getFieldName()
        return None
    return comp.getFieldName()


def resolve_entry(program, entry: int) -> tuple[int, str | None]:
    af = program.getAddressFactory().getDefaultAddressSpace()
    fm = program.getFunctionManager()
    listing = program.getListing()
    target = entry
    for _ in range(8):
        addr = af.getAddress(target)
        fn = fm.getFunctionContaining(addr)
        if fn is not None and fn.isThunk():
            tf = fn.getThunkedFunction(True)
            if tf is not None:
                nxt = int(tf.getEntryPoint().getOffset())
                if nxt == target:
                    break
                target = nxt
                continue
        if fn is not None and int(fn.getEntryPoint().getOffset()) == target:
            name = fn.getName()
            if "::" in name:
                name = name.split("::", 1)[1]
            return target, name
        ins = listing.getInstructionAt(addr)
        if ins is None:
            break
        if ins.getMnemonicString().lower() == "jmp" and len(ins.getFlows()) == 1:
            target = int(ins.getFlows()[0].getOffset())
        else:
            break
    fn = fm.getFunctionContaining(af.getAddress(target))
    if fn is None:
        return target, None
    name = fn.getName()
    if "::" in name:
        name = name.split("::", 1)[1]
    return target, name


def slot_function_name(program, vtable_addr: int, byte_offset: int) -> str | None:
    af = program.getAddressFactory().getDefaultAddressSpace()
    mem = program.getMemory()
    try:
        entry = mem.getInt(af.getAddress(vtable_addr + byte_offset)) & 0xFFFFFFFF
    except Exception:  # noqa: BLE001
        return None
    if entry == 0:
        return None
    _, name = resolve_entry(program, entry)
    return name


def run_checks(checks: tuple[StructFieldCheck, ...]) -> list[str]:
    from tools.common import ghidra_env

    failures: list[str] = []
    project = ghidra_env.open_project()
    consumer = None
    program = None
    try:
        consumer, program = ghidra_env.open_program(project)
        dtm = program.getDataTypeManager()
        for check in checks:
            actual = field_name_at_offset(dtm, check.struct_name, check.byte_offset)
            if actual != check.field_name and check.vtable_addr is not None:
                actual = slot_function_name(program, check.vtable_addr, check.byte_offset)
            if actual != check.field_name:
                failures.append(
                    f"{check.struct_name}+0x{check.byte_offset:x}: "
                    f"expected {check.field_name!r}, got {actual!r}"
                    + (f" ({check.note})" if check.note else "")
                )
    finally:
        if program is not None and consumer is not None:
            program.release(consumer)
        project.close()
    return failures


def discover_vtable_classes() -> list[tuple[str, int]]:
    from pathlib import Path

    from tools.common.repo import repo_root_from_file

    include_game = repo_root_from_file(__file__) / "include" / "game"
    found: list[tuple[str, int]] = []
    for path in sorted(include_game.glob("*.h")):
        pending_vt: int | None = None
        for line in path.read_text(encoding="utf-8").splitlines():
            vt_match = VTABLE_HEADER.match(line)
            if vt_match:
                pending_vt = int(vt_match.group(1), 16)
                continue
            class_match = CLASS_DECL.match(line)
            if class_match and pending_vt is not None:
                found.append((class_match.group(1), pending_vt))
                pending_vt = None
    return found


def main() -> int:
    parser = argparse.ArgumentParser(description="Ghidra vtable struct field-name checks.")
    parser.add_argument(
        "--list-vtables",
        action="store_true",
        help="Print class/vtable addresses from header // VTABLE: annotations and exit.",
    )
    args = parser.parse_args()

    if args.list_vtables:
        for cls, addr in discover_vtable_classes():
            print(f"{cls}|0x{addr:08x}")
        return 0

    print("Ghidra vtable struct check")
    print("=" * 60)
    try:
        failures = run_checks(CHECKS)
    except Exception as exc:  # noqa: BLE001
        print(f"FAIL  {exc}", file=sys.stderr)
        return 1

    failed_set = set(failures)
    for check in CHECKS:
        matched = [
            failure
            for failure in failed_set
            if check.struct_name in failure and f"+0x{check.byte_offset:x}" in failure
        ]
        if matched:
            for failure in matched:
                print(f"  FAIL  {failure}")
        else:
            print(f"  ok    {check.struct_name}+0x{check.byte_offset:x} = {check.field_name}")

    print("=" * 60)
    if failures:
        print("RESULT: FAIL")
        return 1
    print("RESULT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
