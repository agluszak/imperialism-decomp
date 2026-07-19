#!/usr/bin/env python3
"""Propagate reviewed MSVC500 library override NAMES into the live Ghidra DB.

`apply_library_overrides` (run inside `db-resync`) writes the reviewed names in
``config/msvc500_library_overrides.csv`` into ``config/original_entities.csv``, but nothing
pushes them into the Ghidra database itself. `push-names` (which does push
symbols.csv names into the DB) runs *before* the overrides are applied and also
skips two whole classes of address:

  * addresses with no Function entity -- MFC helpers the DB keeps as bare
    ``LAB_00xxxxxx`` labels (per policy, library code stays LIBRARY and is not
    functionized), and
  * ``ownership==library`` addresses outside the ``--library-*`` range.

The result is that override renames land in the derived symbols.csv but never in
the DB / exported ``.gzf`` -- e.g. 0x60a60a shows ``CWnd::RunModalLoop`` in
symbols.csv but ``TView::RunModalLoop`` in the DB. This tool closes that gap by
applying the reviewed override authority directly to the DB: a Function entity is
renamed in place; a label-only address gets a primary user label (it is *not*
functionized). Names Ghidra cannot store as symbols (spaces/backticks, e.g. the
``CThreadLocal<class ...>`` spelling) are reported and skipped, exactly as
push-names skips them.

Read-only by default; ``--apply`` writes the DB and saves it. Run it inside
the refresh flow so `sync_exports`/`export-project` pick
up the names.
"""

from __future__ import annotations

import argparse

import pyghidra

from tools.common import ghidra_env
from tools.common.pipe_csv import read_pipe_table
from tools.common.repo import repo_root_from_file

REPO_ROOT = repo_root_from_file(__file__, levels_up=2)
OVERRIDES = REPO_ROOT / "config" / "msvc500_library_overrides.csv"


def load_override_names() -> list[tuple[int, str]]:
    _fieldnames, rows = read_pipe_table(OVERRIDES)
    out: list[tuple[int, str]] = []
    for row in rows:
        addr_text = (row.get("address") or "").strip().lower().removeprefix("0x")
        name = (row.get("name") or "").strip()
        if not addr_text or not name:
            continue
        try:
            addr = int(addr_text, 16)
        except ValueError:
            continue
        out.append((addr, name))
    return out


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Apply reviewed library override names directly to the Ghidra DB."
    )
    parser.add_argument("--apply", action="store_true", help="Write and save the DB (default: dry-run).")
    parser.add_argument("--quiet", action="store_true", help="Only print the summary line.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    rows = load_override_names()
    project = ghidra_env.open_project()
    consumer = None
    program = None
    txid = None
    try:
        consumer, program = ghidra_env.open_program(project, writable=bool(args.apply))
        from ghidra.program.model.symbol import SourceType
        from ghidra.util.exception import DuplicateNameException, InvalidInputException

        af = program.getAddressFactory().getDefaultAddressSpace()
        st = program.getSymbolTable()
        fm = program.getFunctionManager()
        if args.apply:
            txid = program.startTransaction("push library override names")

        applied = renamed_fn = created_label = skipped = already = 0
        for addr, want in rows:
            a = af.getAddress(addr)
            if want in [s.getName() for s in st.getSymbols(a)]:
                already += 1
                continue
            if any(ch in want for ch in "` "):
                skipped += 1
                if not args.quiet:
                    print(f"  skip (illegal chars) 0x{addr:08x} {want}")
                continue
            fn = fm.getFunctionAt(a)
            if not args.apply:
                if not args.quiet:
                    print(f"  would set 0x{addr:08x} -> {want} ({'fn' if fn else 'label'})")
                applied += 1
                continue
            try:
                if fn is not None:
                    fn.setName(want, SourceType.USER_DEFINED)
                    renamed_fn += 1
                else:
                    st.createLabel(a, want, SourceType.USER_DEFINED).setPrimary()
                    created_label += 1
                applied += 1
            except (DuplicateNameException, InvalidInputException) as exc:
                skipped += 1
                print(f"  !! 0x{addr:08x} -> {want} failed: {exc}")

        if args.apply:
            program.endTransaction(txid, True)
            txid = None
            program.save("push library override names", pyghidra.task_monitor())

        mode = "APPLIED" if args.apply else "DRY RUN"
        print(
            f"[{mode}] overrides={len(rows)} already={already} "
            f"applied={applied} (fn={renamed_fn} label={created_label}) skipped={skipped}"
        )
        return 0
    finally:
        if txid is not None:
            program.endTransaction(txid, False)
        if program is not None:
            program.release(consumer)
        project.close()


if __name__ == "__main__":
    raise SystemExit(main())
