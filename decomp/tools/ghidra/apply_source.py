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
from tools.common.vtable_extents import load_verified_vtable_extents
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
    parser.add_argument(
        "--prune-vtable-interiors-only",
        action="store_true",
        help="Only remove labels strictly inside verified vtable extents.",
    )
    parser.add_argument(
        "--demote-embedded-functions-only",
        action="store_true",
        help="Only demote configured internal-entry Function entities to labels.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help=(
            "Exit nonzero on any failure, and (dry-run) on any pending change — "
            "used by ghidra-apply-source-full to require convergence."
        ),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    model = build_model(REPO_ROOT, args.target)
    vtables = model.vtables
    extents = load_verified_vtable_extents(REPO_ROOT / "config" / "verified_vtable_extents.csv")
    embedded_labels: list[tuple[int, str]] = []
    embedded_path = REPO_ROOT / "config" / "embedded_function_labels.csv"
    if embedded_path.is_file():
        _fields, embedded_rows = read_pipe_table(embedded_path)
        embedded_labels = [
            (int((row.get("address") or "").strip(), 16), (row.get("name") or "").strip())
            for row in embedded_rows
        ]
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
                 "skipped_illegal": 0, "failed": 0, "stale_labels_dropped": 0,
                 "interior_vtable_labels_dropped": 0,
                 "embedded_functions_demoted": 0}

        def _drop_stale_same_name_labels(a, simple):
            """Non-primary labels whose simple name equals the target block the
            namespace move / rename with DuplicateNameException. They are
            redundant with the qualified primary being produced — delete them."""
            removed = 0
            for sym in list(st.getSymbols(a)):
                try:
                    if (not sym.isPrimary()
                            and sym.getSymbolType().toString() == "Label"
                            and sym.getName() == simple):
                        sym.delete()
                        removed += 1
                except Exception:  # noqa: BLE001
                    pass
            return removed

        # Labels strictly inside a verified vtable extent are stale entity
        # boundaries. The end address is intentionally excluded because a real
        # adjacent entity may begin immediately after the final slot.
        repair_vtable_interiors = (
            args.prune_vtable_interiors_only or not args.demote_embedded_functions_only
        )
        repair_embedded_functions = (
            args.demote_embedded_functions_only or not args.prune_vtable_interiors_only
        )
        for extent in (extents if repair_vtable_interiors else ()):
            for address in range(extent.address + 4, extent.end, 4):
                a = af.getAddress(address)
                labels = [
                    sym
                    for sym in st.getSymbols(a)
                    if sym.getSymbolType().toString() == "Label" and not sym.isDynamic()
                ]
                if not labels:
                    continue
                if not args.apply:
                    if not args.quiet:
                        names = ", ".join(sym.getName(True) for sym in labels)
                        print(
                            f"  would drop interior vtable label(s) at 0x{address:08x}: {names}"
                        )
                    stats["interior_vtable_labels_dropped"] += len(labels)
                    continue
                for sym in labels:
                    if sym.delete():
                        stats["interior_vtable_labels_dropped"] += 1

        for address, label_name in (embedded_labels if repair_embedded_functions else ()):
            a = af.getAddress(address)
            fn = fm.getFunctionAt(a)
            if fn is None:
                continue
            if not args.apply:
                if not args.quiet:
                    print(
                        f"  would demote embedded function 0x{address:08x} "
                        f"{fn.getName(True)} -> label {label_name}"
                    )
                stats["embedded_functions_demoted"] += 1
                continue
            fm.removeFunction(a)
            prim = st.getPrimarySymbol(a)
            if prim is None or prim.getName() != label_name:
                st.createLabel(a, label_name, global_ns, SourceType.USER_DEFINED).setPrimary()
            stats["embedded_functions_demoted"] += 1

        if args.prune_vtable_interiors_only or args.demote_embedded_functions_only:
            if args.apply:
                program.endTransaction(txid, True)
                txid = None
                program.save("repair entity boundaries", pyghidra.task_monitor())
            mode = "APPLIED" if args.apply else "DRY RUN"
            print(
                f"[{mode}] interior_vtable_labels_dropped="
                f"{stats['interior_vtable_labels_dropped']}"
                f" embedded_functions_demoted={stats['embedded_functions_demoted']}"
            )
            if args.strict and not args.apply and (
                stats["interior_vtable_labels_dropped"]
                or stats["embedded_functions_demoted"]
            ):
                print("STRICT: entity-boundary repairs are still pending.")
                return 1
            return 0

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
                    # A stale secondary label with the same simple name (often
                    # already qualified, e.g. `CMcWindow::OnQueryNewPalette`
                    # beside a Global-primary `OnQueryNewPalette`) collides with
                    # the namespace move / rename. It is redundant with the
                    # primary we are about to produce — drop it first.
                    if _drop_stale_same_name_labels(a, simple):
                        stats["stale_labels_dropped"] += 1
                    if ns is not None:
                        fn.setParentNamespace(ns)
                    try:
                        # After the namespace move the simple name may already be
                        # right — Ghidra throws DuplicateName on a same-name rename.
                        if fn.getName() != simple:
                            fn.setName(simple, SourceType.USER_DEFINED)
                    except DuplicateNameException:
                        if _drop_stale_same_name_labels(a, simple):
                            fn.setName(simple, SourceType.USER_DEFINED)
                            stats["stale_labels_dropped"] += 1
                        else:
                            raise
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

        # Live audit 1: source classes whose Vtbl datatype exists but whose class
        # datatype is missing under the source name.
        source_classes = {c for n in wanted.values() if "::" in n
                          for c in [n.rsplit("::", 1)[0]] if "::" not in c}
        source_classes |= set(vtables.values())
        dt_names = {dt.getName() for dt in dtm.getAllDataTypes()}
        drift = sorted(c for c in source_classes
                       if c not in dt_names and f"{c}Vtbl" in dt_names)

        # Live audit 2: DB class namespaces that own source-claimed functions but
        # are not the class the source model names — a stale/obsolete namespace
        # (the TSoundChannelNode pattern) surviving beside the source model.
        claimed_class = {a: n.rsplit("::", 1)[0] for a, n in wanted.items() if "::" in n}
        stale_ns: dict[str, int] = {}
        for fn2 in fm.getFunctions(True):
            try:
                addr2 = int(str(fn2.getEntryPoint()), 16)
            except ValueError:
                continue
            want_cls = claimed_class.get(addr2)
            if want_cls is None:
                continue
            have_cls = fn2.getParentNamespace().getName(True)
            if have_cls not in ("Global", want_cls):
                stale_ns[have_cls] = stale_ns.get(have_cls, 0) + 1
        if stale_ns:
            print(f"audit: {len(stale_ns)} DB namespace(s) own source-claimed functions "
                  f"under a different class than the source model:")
            for cls2, cnt in sorted(stale_ns.items())[:10]:
                print(f"    - {cls2} ({cnt} function(s))")
        if drift:
            print(f"audit: {len(drift)} class(es) with a Vtbl datatype but no class "
                  f"datatype under the source name (repair: just ghidra-rename-class):")
            for c in drift[:10]:
                print(f"    - {c}")

        mode = "APPLIED" if args.apply else "DRY RUN"
        print(
            f"[{mode}] primary_exact={stats['primary_exact']} set_fn={stats['fn']} "
            f"set_label={stats['label']} vtable_labels={stats['vtable']} "
            f"skipped_illegal={stats['skipped_illegal']} "
            f"stale_labels_dropped={stats['stale_labels_dropped']} failed={stats['failed']}"
            f" interior_vtable_labels_dropped={stats['interior_vtable_labels_dropped']}"
            f" embedded_functions_demoted={stats['embedded_functions_demoted']}"
        )
        if args.apply:
            print("Run `just export-project` so the vendored .gzf carries the result.")
        if args.strict:
            pending = 0 if args.apply else (
                stats["fn"] + stats["label"] + stats["vtable"]
                + stats["interior_vtable_labels_dropped"]
                + stats["embedded_functions_demoted"]
            )
            if stats["failed"] or pending:
                print(f"STRICT: not converged (failed={stats['failed']} pending={pending}).")
                return 1
        return 0
    finally:
        if txid is not None:
            program.endTransaction(txid, False)
        if program is not None:
            program.release(consumer)
        project.close()


if __name__ == "__main__":
    raise SystemExit(main())
