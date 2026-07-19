#!/usr/bin/env python3
"""Push ALL curated names from config/original_entities.csv into the live Ghidra DB.

Source is authoritative: the retired `push-names` overrides channel deliberately
never pushed the bulk of symbols.csv, which left ~700 curated names -- game class
methods (`ImperialismApp::GetMessageMap`), RTTI/global descriptors
(`TScroller::classTScroller`), etc. -- present in source/symbols.csv but stale in
the DB / exported .gzf (the DB kept Ghidra placeholders like
`NoOpThunkTargetHandler`, `OrphanCallChain_*`, `DAT_*`, `classRuntimeClass`, or
older descriptive names).

This tool makes the DB mirror symbols.csv: for every named row it sets a Function
entity's name (namespace-aware, e.g. `A::B` -> namespace A + name B) or, for a
data/label address, creates a primary user label (it does NOT functionize data).
Names Ghidra cannot store as symbols (spaces/backticks -- e.g. `scalar deleting
destructor' spellings) are reported and skipped. Idempotent: rows whose name
already matches the DB are left untouched.

Run it when symbols.csv is final and before `export-project`.
Read-only by default; --apply writes and saves the DB.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import pyghidra

from tools.common import ghidra_env
from tools.common.pipe_csv import read_pipe_table
from tools.common.repo import repo_root_from_file

REPO_ROOT = repo_root_from_file(__file__, levels_up=2)
SYMBOLS = REPO_ROOT / "config" / "original_entities.csv"


def split_qualified(qualified: str) -> tuple[list[str], str]:
    parts = qualified.split("::")
    return parts[:-1], parts[-1]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Mirror curated config/original_entities.csv names into the Ghidra DB."
    )
    parser.add_argument("--apply", action="store_true", help="Write and save the DB (default: dry-run).")
    parser.add_argument("--quiet", action="store_true", help="Only print the summary line.")
    parser.add_argument("--limit", type=int, default=0, help="Stop after N changes (0 = no limit).")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    _fieldnames, rows = read_pipe_table(SYMBOLS)
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
        global_ns = program.getGlobalNamespace()

        def get_namespace(path: list[str]):
            parent = None
            for part in path:
                existing = st.getNamespace(part, parent)
                parent = existing if existing is not None else st.createClass(
                    parent, part, SourceType.USER_DEFINED
                )
            return parent

        if args.apply:
            txid = program.startTransaction("push source names")

        # Match states (source is authoritative; the PRIMARY entity is what counts):
        #   primary_exact      - primary function/symbol already == the source name
        #   secondary_only     - a *secondary* symbol matched but the primary is stale
        #                        (the old-loop bug: reported "already" and skipped, so the
        #                        primary never converged). Now a repair action.
        #   wrong_namespace    - primary is the right simple name in the wrong class
        #   wrong_simple_name  - primary is in the right class, wrong simple name
        #   no_function        - a source-owned address with no function -> label
        stats = {
            "primary_exact": 0,
            "fn": 0,
            "label": 0,
            "secondary_only": 0,
            "wrong_namespace": 0,
            "wrong_simple_name": 0,
            "skipped_illegal": 0,
            "failed": 0,
        }

        def secondary_matches(a, name: str) -> bool:
            prim = st.getPrimarySymbol(a)
            for s in st.getSymbols(a):
                if s is prim:
                    continue
                if name in (s.getName(), s.getName(True)):
                    return True
            return False

        for row in rows:
            name = (row.get("name") or "").strip()
            addr_text = (row.get("address") or "").strip()
            if not name or not addr_text:
                continue
            try:
                addr = int(addr_text, 16)
            except ValueError:
                continue
            if any(ch in name for ch in "` "):
                stats["skipped_illegal"] += 1
                if not args.quiet:
                    print(f"  skip (illegal chars) 0x{addr:08x} {name}")
                continue
            a = af.getAddress(addr)
            ns_path, simple = split_qualified(name)
            fn = fm.getFunctionAt(a)

            # Decide against the PRIMARY entity, never an arbitrary secondary symbol.
            if fn is not None:
                current_qualified = fn.getName(True)
                if current_qualified == name:
                    stats["primary_exact"] += 1
                    continue
                # Classify why it needs repair (for reporting only).
                if secondary_matches(a, name):
                    kind = "secondary_only"
                elif ns_path and fn.getName() == simple:
                    kind = "wrong_namespace"
                elif fn.getParentNamespace().getName(True) == "::".join(ns_path):
                    kind = "wrong_simple_name"
                else:
                    kind = "wrong_namespace"
                stats[kind] += 1
            else:
                prim = st.getPrimarySymbol(a)
                if prim is not None and prim.getName(True) == name:
                    stats["primary_exact"] += 1
                    continue

            if not args.apply:
                if not args.quiet:
                    tag = "fn" if fn is not None else "label"
                    print(f"  would set 0x{addr:08x} -> {name} ({tag})")
                stats["fn" if fn is not None else "label"] += 1
                if args.limit and (stats["fn"] + stats["label"]) >= args.limit:
                    break
                continue
            try:
                ns = get_namespace(ns_path) if ns_path else global_ns
                if fn is not None:
                    if ns is not None:
                        fn.setParentNamespace(ns)
                    fn.setName(simple, SourceType.USER_DEFINED)
                    stats["fn"] += 1
                else:
                    st.createLabel(a, simple, ns, SourceType.USER_DEFINED).setPrimary()
                    stats["label"] += 1
            except (DuplicateNameException, InvalidInputException) as exc:
                stats["failed"] += 1
                print(f"  !! 0x{addr:08x} -> {name} failed: {exc}")
            else:
                if args.limit and (stats["fn"] + stats["label"]) >= args.limit:
                    break

        if args.apply:
            program.endTransaction(txid, True)
            txid = None
            program.save("push source names", pyghidra.task_monitor())

        mode = "APPLIED" if args.apply else "DRY RUN"
        print(
            f"[{mode}] primary_exact={stats['primary_exact']} set_fn={stats['fn']} "
            f"set_label={stats['label']} "
            f"(repairs: secondary_only={stats['secondary_only']} "
            f"wrong_namespace={stats['wrong_namespace']} "
            f"wrong_simple_name={stats['wrong_simple_name']}) "
            f"skipped_illegal={stats['skipped_illegal']} failed={stats['failed']}"
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
