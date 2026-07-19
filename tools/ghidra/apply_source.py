#!/usr/bin/env python3
"""One-way apply: manual C++ source -> the live Ghidra DB.

The single sanctioned mutation path from the source model into Ghidra (the DB is
an analysis workspace and downstream projection; nothing flows back
automatically). It derives everything from the two canonical inputs:

  1. **The source model** (tools.source_model — the single scanner/parser):
     marker claims with names parsed from the C++ declarations, reviewed
     library identities as LIBRARY claims, `// VTABLE:` classes, and
     `// GLOBAL:` names.
  2. **The raw inventory** (config/original_entities.csv): fallback advisory
     names ONLY for claimed addresses whose source spelling could not be
     parsed. Unclaimed addresses are never touched — source has no opinion on
     them, so nothing DB-derived is re-applied to the DB.

Applied to the DB (dry-run by default; --apply writes and saves):
  - function names + class namespaces (decided against the PRIMARY entity —
    a matching *secondary* label never masks a stale primary);
  - labels for non-function addresses;
  - `Class::'vftable'` labels for every `// VTABLE:` annotation (class name
    parsed from the following `class X` declaration).

After --apply, run `just export-project` so the vendored .gzf carries the
result (`just ghidra-apply-source-full` chains build -> apply -> export).

Class datatypes/inheritance/signatures come from the recomp PDB via the
`just import-ghidra` step of `ghidra-apply-source-full` (reccmp's PDB importer);
the audit at the end reports class namespaces whose datatype name still diverges
from source (repair tool: `just ghidra-rename-class`).
"""

from __future__ import annotations

import argparse

import pyghidra

from tools.common import ghidra_env
from tools.common.pipe_csv import read_pipe_table
from tools.common.repo import repo_root_from_file
from tools.source_model import build_model

REPO_ROOT = repo_root_from_file(__file__, levels_up=2)
INVENTORY = REPO_ROOT / "config" / "original_entities.csv"
REVIEWED = REPO_ROOT / "config" / "reviewed_library_identities.csv"


def split_qualified(qualified: str) -> tuple[list[str], str]:
    parts = qualified.split("::")
    return parts[:-1], parts[-1]














def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="IMPERIALISM")
    parser.add_argument("--apply", action="store_true", help="Write and save the DB (default: dry-run).")
    parser.add_argument("--quiet", action="store_true", help="Only print the summary lines.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    model = build_model(REPO_ROOT, args.target)
    vtables = model.vtables
    # Claimed entities only: source spelling when parsed, reviewed name for
    # reviewed claims, inventory advisory ONLY as fallback for claimed
    # addresses whose spelling could not be parsed. Unclaimed addresses are
    # never pushed — the DB's own analysis stands.
    inventory = {}
    inv_path = REPO_ROOT / "config" / "original_entities.csv"
    if inv_path.is_file():
        _f, inv_rows = read_pipe_table(inv_path)
        for row in inv_rows:
            n = (row.get("name") or "").strip()
            a = (row.get("address") or "").strip()
            if n and a:
                try:
                    inventory[int(a, 16)] = n
                except ValueError:
                    pass
    wanted: dict[int, str] = {}
    derived = fallback = 0
    for addr, claim in model.functions.items():
        if claim.name:
            wanted[addr] = claim.name
            derived += 1
        elif addr in inventory:
            wanted[addr] = inventory[addr]
            fallback += 1
    # Source globals get labels too.
    for addr, gname in model.globals.items():
        wanted.setdefault(addr, gname)
    print(
        f"claims: {len(model.functions)} (named from source/reviewed: {derived}, "
        f"inventory fallback: {fallback}); globals: {len(model.globals)}; "
        f"vtable annotations: {len(vtables)}"
    )

    project = ghidra_env.open_project()
    consumer = program = None
    txid = None
    try:
        consumer, program = ghidra_env.open_program(project, writable=bool(args.apply))
        from ghidra.program.model.symbol import SourceType
        from ghidra.util.exception import DuplicateNameException, InvalidInputException

        af = program.getAddressFactory().getDefaultAddressSpace()
        st = program.getSymbolTable()
        fm = program.getFunctionManager()
        dtm = program.getDataTypeManager()
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
            txid = program.startTransaction("apply source model")

        stats = {"primary_exact": 0, "fn": 0, "label": 0, "vtable": 0,
                 "skipped_illegal": 0, "failed": 0}

        for addr in sorted(wanted):
            name = wanted[addr]
            if any(ch in name for ch in "` "):
                stats["skipped_illegal"] += 1
                continue
            a = af.getAddress(addr)
            ns_path, simple = split_qualified(name)
            fn = fm.getFunctionAt(a)
            if fn is not None:
                if fn.getName(True) == name:
                    stats["primary_exact"] += 1
                    continue
            else:
                prim = st.getPrimarySymbol(a)
                if prim is not None and prim.getName(True) == name:
                    stats["primary_exact"] += 1
                    continue
            if not args.apply:
                if not args.quiet:
                    print(f"  would set 0x{addr:08x} -> {name} ({'fn' if fn else 'label'})")
                stats["fn" if fn is not None else "label"] += 1
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

        # Vtable labels from // VTABLE: annotations.
        for addr, cls in sorted(vtables.items()):
            a = af.getAddress(addr)
            prim = st.getPrimarySymbol(a)
            wanted_label = f"{cls}::'vftable'"
            if prim is not None and prim.getName(True) == wanted_label:
                continue
            if not args.apply:
                if not args.quiet:
                    print(f"  would label vtable 0x{addr:08x} -> {wanted_label}")
                stats["vtable"] += 1
                continue
            try:
                ns = get_namespace([cls])
                st.createLabel(a, "'vftable'", ns, SourceType.USER_DEFINED).setPrimary()
                stats["vtable"] += 1
            except (DuplicateNameException, InvalidInputException) as exc:
                stats["failed"] += 1
                print(f"  !! vtable 0x{addr:08x} -> {wanted_label} failed: {exc}")

        if args.apply:
            program.endTransaction(txid, True)
            txid = None
            program.save("apply source model", pyghidra.task_monitor())

        # Live audit: class namespaces used by source vs DB datatype names.
        source_classes = {c for n in wanted.values() if "::" in n
                          for c in [n.rsplit("::", 1)[0]] if "::" not in c}
        source_classes |= set(vtables.values())
        dt_names = {dt.getName() for dt in dtm.getAllDataTypes()}
        drift = sorted(c for c in source_classes
                       if c not in dt_names and f"{c}Vtbl" in dt_names)
        if drift:
            print(f"audit: {len(drift)} class(es) with a Vtbl datatype but no class "
                  f"datatype under the source name (repair: just ghidra-rename-class):")
            for c in drift[:10]:
                print(f"    - {c}")

        mode = "APPLIED" if args.apply else "DRY RUN"
        print(
            f"[{mode}] primary_exact={stats['primary_exact']} set_fn={stats['fn']} "
            f"set_label={stats['label']} vtable_labels={stats['vtable']} "
            f"skipped_illegal={stats['skipped_illegal']} failed={stats['failed']}"
        )
        if args.apply:
            print("Run `just export-project` so the vendored .gzf carries the result.")
        return 0
    finally:
        if txid is not None:
            program.endTransaction(txid, False)
        if program is not None:
            program.release(consumer)
        project.close()


if __name__ == "__main__":
    raise SystemExit(main())
