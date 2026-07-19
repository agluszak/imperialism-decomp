#!/usr/bin/env python3
"""Remove Ghidra datatypes that make TypeResolver's by-simple-name lookup
(``tools/ghidra/apply_source_signatures.py``) ambiguous.

``TypeResolver`` builds a name -> DataType cache from ``dtm.getAllDataTypes()``
and picks whichever datatype it sees first for a given simple name (see
``ambiguous_simple_name`` in ``resolve_quality``). Two datatypes sharing a
simple name make that pick a coin flip instead of a semantic match.

One concrete cause: Ghidra's built-in C++ Demangler analyzer creates
lightweight placeholder structs under ``/Demangler/<Name>`` when it meets a
mangled symbol for a class it doesn't have a full definition for yet. When the
real, fully-modeled MFC class is later imported at the root path
(``apply_mfc_datatypes``/``apply_mfc_rtti``), the ``/Demangler`` placeholder
becomes a dead duplicate that only exists to confuse by-name lookups.

This tool finds every ``/Demangler/<Name>`` (or ``/Demangler/<Name> *``
pointer) datatype whose simple name collides with a datatype already present
at Ghidra datatype-manager root, verifies nothing outside the ``/Demangler``
duplicate group still references it (``getDataTypesContaining``), and removes
it. Dry-run by default -- pass ``--apply`` to write.

Usage:
  uv run python -m tools.ghidra.dedupe_ambiguous_datatypes [--apply]
"""

from __future__ import annotations

import argparse

import pyghidra

from tools.common import ghidra_env


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="Write changes (default: dry-run).")
    return parser.parse_args()


def find_demangler_duplicates(dtm) -> list:
    """Every /Demangler/<Name>[ *]* datatype whose simple name also exists at root."""
    candidates = []
    for dt in dtm.getAllDataTypes():
        path = dt.getPathName()
        if not path.startswith("/Demangler/"):
            continue
        root = dtm.getDataType(f"/{dt.getName()}")
        if root is not None and root is not dt:
            candidates.append(dt)
    return candidates


def is_safe_to_remove(dtm, datatype, keep: set) -> tuple[bool, str]:
    """Safe iff every referrer is itself one of the /Demangler duplicates being
    removed in this same pass (e.g. CWnd's own '/Demangler/CWnd *' pointer)."""
    referrers = list(dtm.getDataTypesContaining(datatype))
    outside = [r for r in referrers if r not in keep]
    if outside:
        names = ", ".join(r.getPathName() for r in outside[:5])
        return False, f"referenced outside the duplicate group: {names}"
    return True, ""


def run(dtm, apply_changes: bool) -> dict:
    duplicates = find_demangler_duplicates(dtm)
    keep = set(duplicates)
    removed: list[str] = []
    skipped: list[str] = []
    # Remove dependents (pointers) before the structs they point to.
    duplicates.sort(key=lambda dt: 0 if dt.getPathName().rstrip().endswith("*") else 1)
    for dt in duplicates:
        path = dt.getPathName()
        safe, reason = is_safe_to_remove(dtm, dt, keep)
        if not safe:
            skipped.append(f"{path}: {reason}")
            continue
        if apply_changes:
            if dtm.remove(dt):
                removed.append(path)
            else:
                skipped.append(f"{path}: dtm.remove() returned False")
        else:
            removed.append(path)
    return {"removed": removed, "skipped": skipped}


def main() -> int:
    args = parse_args()
    project = ghidra_env.open_project()
    consumer = None
    program = None
    txid = None
    try:
        consumer, program = ghidra_env.open_program(project, writable=bool(args.apply))
        dtm = program.getDataTypeManager()
        if args.apply:
            txid = program.startTransaction("dedupe ambiguous /Demangler datatypes")
        result = run(dtm, args.apply)
        if args.apply:
            program.endTransaction(txid, True)
            txid = None
            program.save("dedupe ambiguous /Demangler datatypes", pyghidra.task_monitor())

        mode = "APPLIED" if args.apply else "DRY RUN"
        for path in result["removed"]:
            print(f"  removed {path}")
        for line in result["skipped"]:
            print(f"  !! skipped {line}")
        print(f"\n[{mode}] removed={len(result['removed'])} skipped={len(result['skipped'])}")
        if not args.apply:
            print("Re-run with --apply to write these changes to the Ghidra DB.")
        return 0
    finally:
        if txid is not None:
            program.endTransaction(txid, False)
        if program is not None:
            program.release(consumer)
        project.close()


if __name__ == "__main__":
    raise SystemExit(main())
