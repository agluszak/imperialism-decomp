#!/usr/bin/env python3
"""Audit duplicate Ghidra structure datatypes in root and MFC categories."""

from __future__ import annotations

import argparse
from collections import defaultdict
import sys

import jpype

from tools.common import ghidra_env
from tools.ghidra.apply_mfc_datatypes import MFC_MODELS


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--limit",
        type=int,
        default=80,
        help="Maximum duplicate-name groups to print (0 = all).",
    )
    parser.add_argument(
        "--fail-on-mfc-library-duplicates",
        action="store_true",
        help="Exit non-zero if an MFC library type exists both at root and under /MFC.",
    )
    parser.add_argument(
        "--fail-on-duplicates",
        action="store_true",
        help="Exit non-zero if any concrete structure name is duplicated under root or /MFC.",
    )
    return parser.parse_args()


def is_interesting_path(path: str) -> bool:
    if not path.startswith("/"):
        return False
    category = path.rsplit("/", 1)[0]
    return category == "" or category.startswith("/MFC")


def field_summary(datatype) -> str:
    fields: list[str] = []
    try:
        for i in range(min(datatype.getNumComponents(), 4)):
            comp = datatype.getComponent(i)
            name = comp.getFieldName() or f"field_0x{comp.getOffset():x}"
            fields.append(f"{comp.getOffset():#x}:{name}")
    except Exception:  # noqa: BLE001
        return ""
    return ", ".join(fields)


def collect_duplicates(program):
    Structure = jpype.JClass("ghidra.program.model.data.Structure")
    dtm = program.getDataTypeManager()
    by_name: dict[str, list[object]] = defaultdict(list)
    it = dtm.getAllDataTypes()
    while it.hasNext():
        datatype = it.next()
        if not Structure.class_.isAssignableFrom(datatype.getClass()):
            continue
        path = datatype.getPathName()
        if is_interesting_path(path):
            by_name[datatype.getName()].append(datatype)
    return {
        name: sorted(datatype_list, key=lambda dt: dt.getPathName())
        for name, datatype_list in by_name.items()
        if len(datatype_list) > 1
    }


def main() -> int:
    args = parse_args()
    project = ghidra_env.open_project()
    consumer = None
    program = None
    try:
        consumer, program = ghidra_env.open_program(project)
        duplicates = collect_duplicates(program)
    finally:
        if program is not None:
            program.release(consumer)
        project.close()

    mfc_library_duplicates = {
        name: dts
        for name, dts in duplicates.items()
        if name in MFC_MODELS
        and any(dt.getPathName() == f"/{name}" for dt in dts)
        and any(dt.getPathName().startswith("/MFC/") for dt in dts)
    }

    print(
        "Duplicate concrete structures under root or /MFC: "
        f"{len(duplicates)} groups; MFC library duplicate groups: {len(mfc_library_duplicates)}"
    )
    limit = len(duplicates) if args.limit == 0 else args.limit
    for i, name in enumerate(sorted(duplicates)):
        if i >= limit:
            remaining = len(duplicates) - limit
            if remaining > 0:
                print(f"... {remaining} more duplicate groups omitted (use --limit 0)")
            break
        marker = " [MFC library]" if name in mfc_library_duplicates else ""
        print(f"\n{name}{marker}")
        for datatype in duplicates[name]:
            summary = field_summary(datatype)
            suffix = f" fields={summary}" if summary else ""
            print(f"  {datatype.getPathName()} size={datatype.getLength()}{suffix}")

    if args.fail_on_duplicates and duplicates:
        print(
            "\nERROR: concrete structure datatypes are duplicated under root or /MFC.",
            file=sys.stderr,
        )
        return 1
    if args.fail_on_mfc_library_duplicates and mfc_library_duplicates:
        print(
            "\nERROR: canonical MFC library datatypes are duplicated under /MFC.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
