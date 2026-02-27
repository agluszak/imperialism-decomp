#!/usr/bin/env python3
"""
Inventory unnamed DAT_/PTR_DAT_ globals with xref analysis for rename planning.

Scans all symbols matching configurable name patterns, collects xref metadata
(reader/writer functions, namespaces, reference counts), identifies an "anchor
function" per symbol, and outputs a rich atlas CSV.

No automated naming — the atlas provides the metadata needed for manual or
semi-automated naming in a follow-up pass.

Usage:
  uv run impk inventory_unnamed_globals --out-csv tmp_decomp/unnamed_globals_atlas.csv
  uv run impk inventory_unnamed_globals --out-csv /dev/stdout --max-symbols 20
"""

from __future__ import annotations

import argparse
import re
from collections import Counter
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.csvio import write_csv_rows
from imperialism_re.core.ghidra_session import open_program

ATLAS_FIELDNAMES = [
    "address",
    "old_name",
    "data_type",
    "data_len",
    "total_refs",
    "code_refs",
    "data_refs",
    "read_refs",
    "write_refs",
    "unique_readers",
    "unique_writers",
    "anchor_fn",
    "anchor_fn_namespace",
    "anchor_fn_refs",
    "top_readers",
    "top_writers",
    "reader_namespaces",
    "writer_namespaces",
    "indirect_code_refs",
    "indirect_unique_fns",
    "indirect_anchor_fn",
    "indirect_anchor_fn_namespace",
    "indirect_top_fns",
]

RENAME_FIELDNAMES = ["address", "new_name", "type", "comment"]

# Patterns for auto-naming code-referenced globals (anchor_fn regex → name template).
# Each entry: (compiled_regex, name_formatter(match, addr_hex) → str)
_RENAME_RULES: list[tuple[re.Pattern, callable]] = []


def _rule(pattern: str):
    """Decorator to register a rename rule."""
    compiled = re.compile(pattern)

    def _decorator(func):
        _RENAME_RULES.append((compiled, func))
        return func

    return _decorator


@_rule(r"^InitializeCityBuildingHoverSelectionRects_")
def _city_build_hover(m, addr_hex, _idx_counter={"n": 0}):
    n = _idx_counter["n"]
    _idx_counter["n"] += 1
    return f"g_cityBuildHoverRect_{n}"


@_rule(r"^WrapperFor_AFX_CLASSINIT_")
def _afx_class_init(m, addr_hex):
    return f"g_afxClassInit_{addr_hex[-8:]}"


@_rule(r"^GetOrCreateMfcHandleMap$")
def _mfc_handle_map(m, addr_hex):
    return "g_pMfcHandleMap"


@_rule(r"^GetOrCreateDcHandleMapForThreadState$")
def _dc_handle_map(m, addr_hex):
    return "g_pDcHandleMap"


@_rule(r"^PreTranslateMessageForDialogAndDispatchHotkey$")
def _dialog_hotkey(m, addr_hex):
    return "g_dialogHotkeyState"


@_rule(r"^GetSharedEmptyStringRef$")
def _shared_empty_str(m, addr_hex):
    return "g_pSharedEmptyString"


@_rule(r"^WrapperFor_memcmp_")
def _memcmp_buffer(m, addr_hex):
    return f"g_memcmpBuffer_{addr_hex[-8:]}"


@_rule(r"^OrphanVtableAssignStub_.*TObject")
def _tobject_vtbl_init(m, addr_hex):
    return "g_pTObjectVtblInit"


@_rule(r"^RebuildActiveLocaleDateTimeNameTable")
def _locale_datetime(m, addr_hex):
    return "g_localeDateTimeNameTable"


@_rule(r"^WrapperFor_AppendPointerToGlobalVectorAsStatus_")
def _global_vector_status(m, addr_hex):
    return f"g_globalVectorStatus_{addr_hex[-8:]}"


@_rule(r"^InitStub_thunk_InitializeGlobalClipRegionHandleState_")
def _clip_region(m, addr_hex):
    return "g_clipRegionHandle"


def _format_top_n(counter: Counter, n: int = 5) -> str:
    """Format top-N entries as 'name(count);name(count);...'."""
    return ";".join(f"{name}({cnt})" for name, cnt in counter.most_common(n))


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Inventory unnamed DAT_/PTR_DAT_ globals with xref analysis.",
    )
    ap.add_argument("--out-csv", required=True, help="Atlas CSV output path")
    ap.add_argument(
        "--emit-rename-csv",
        default="",
        help="If set, emit rename candidate CSV for non-ftol code-referenced globals",
    )
    ap.add_argument(
        "--addr-min",
        default="0x00648000",
        help="Minimum address (hex, default 0x00648000)",
    )
    ap.add_argument(
        "--addr-max",
        default="0x006BFFFF",
        help="Maximum address (hex, default 0x006BFFFF)",
    )
    ap.add_argument(
        "--name-regex",
        default=r"^(DAT_|PTR_DAT_|_DAT_)",
        help="Regex for symbol names to include (default: DAT_/PTR_DAT_/_DAT_)",
    )
    ap.add_argument(
        "--min-code-refs",
        type=int,
        default=0,
        help="Minimum code xrefs to include (default 0)",
    )
    ap.add_argument(
        "--max-symbols",
        type=int,
        default=0,
        help="Max symbols to process, 0=all (for smoke testing)",
    )
    ap.add_argument(
        "--project-root",
        default=default_project_root(),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    root = resolve_project_root(args.project_root)
    out_csv = Path(args.out_csv)
    if args.out_csv != "/dev/stdout" and not out_csv.is_absolute():
        out_csv = root / out_csv
    out_csv.parent.mkdir(parents=True, exist_ok=True)

    addr_min = int(args.addr_min, 16)
    addr_max = int(args.addr_max, 16)
    name_pat = re.compile(args.name_regex)

    with open_program(root) as program:
        st = program.getSymbolTable()
        rm = program.getReferenceManager()
        fm = program.getFunctionManager()
        listing = program.getListing()
        global_ns = program.getGlobalNamespace()

        # --- Phase 1: Enumerate matching symbols ---
        symbols = []
        it = st.getAllSymbols(True)
        while it.hasNext():
            sym = it.next()
            name = sym.getName()
            if not name_pat.search(name):
                continue
            addr = sym.getAddress()
            offset = addr.getOffset() & 0xFFFFFFFF
            if offset < addr_min or offset > addr_max:
                continue
            symbols.append((sym, addr, offset, name))

        # Sort by address for deterministic output
        symbols.sort(key=lambda t: t[2])
        print(f"[enumerate] matched {len(symbols)} symbols in 0x{addr_min:08x}..0x{addr_max:08x}")

        if args.max_symbols > 0:
            symbols = symbols[: args.max_symbols]
            print(f"[enumerate] limited to {len(symbols)} symbols (--max-symbols)")

        # --- Phase 2 & 3: Xref analysis + anchor selection ---
        rows = []
        skipped_low_refs = 0

        for idx, (sym, addr, offset, old_name) in enumerate(symbols):
            # Data type and length
            data_at = listing.getDataAt(addr)
            if data_at is not None:
                data_type = str(data_at.getDataType().getName())
                data_len = str(data_at.getLength())
            else:
                data_type = ""
                data_len = ""

            # Collect references
            refs = rm.getReferencesTo(addr)
            code_refs = 0
            data_refs = 0
            read_refs = 0
            write_refs = 0
            reader_fns: Counter = Counter()  # fn_name -> count
            writer_fns: Counter = Counter()  # fn_name -> count
            reader_ns: set[str] = set()
            writer_ns: set[str] = set()
            all_fn_refs: Counter = Counter()  # fn_name -> total refs (read+write+other)
            fn_ns_map: dict[str, str] = {}  # fn_name -> namespace name

            # Phase 2b: indirect ref tracking (data ref → pointer slot → code)
            indirect_code_refs = 0
            indirect_fn_refs: Counter = Counter()
            indirect_fn_ns_map: dict[str, str] = {}
            data_ref_addrs: list = []  # collect for Phase 2b hop

            for ref in refs:
                ref_type = ref.getReferenceType()
                from_addr = ref.getFromAddress()

                # Classify as code ref (from within a function) vs data ref
                # (from another data location, e.g. pointer table).
                # Note: RefType.isData() is True for READ/WRITE/DATA, so we
                # cannot use it to distinguish code-from-data vs data-from-data.
                caller_fn = fm.getFunctionContaining(from_addr)
                if caller_fn is None:
                    data_refs += 1
                    data_ref_addrs.append(from_addr)
                    continue

                code_refs += 1
                is_read = ref_type.isRead()
                is_write = ref_type.isWrite()
                if is_read:
                    read_refs += 1
                if is_write:
                    write_refs += 1

                fn_name = caller_fn.getName()
                ns = caller_fn.getParentNamespace()
                ns_name = ns.getName() if ns is not None and ns != global_ns else "Global"

                all_fn_refs[fn_name] += 1
                fn_ns_map[fn_name] = ns_name

                if is_read:
                    reader_fns[fn_name] += 1
                    reader_ns.add(ns_name)
                if is_write:
                    writer_fns[fn_name] += 1
                    writer_ns.add(ns_name)
                # If neither read nor write (e.g. address-of/DATA ref from code),
                # still count as a reader for namespace tracking
                if not is_read and not is_write:
                    reader_fns[fn_name] += 1
                    reader_ns.add(ns_name)

            # Phase 2b: chase one hop back from data ref slots
            for slot_addr in data_ref_addrs:
                slot_refs = rm.getReferencesTo(slot_addr)
                for sr in slot_refs:
                    sr_from = sr.getFromAddress()
                    sr_fn = fm.getFunctionContaining(sr_from)
                    if sr_fn is None:
                        continue
                    indirect_code_refs += 1
                    fn_name = sr_fn.getName()
                    ns = sr_fn.getParentNamespace()
                    ns_name = ns.getName() if ns is not None and ns != global_ns else "Global"
                    indirect_fn_refs[fn_name] += 1
                    indirect_fn_ns_map[fn_name] = ns_name

            if code_refs < args.min_code_refs:
                skipped_low_refs += 1
                continue

            # Anchor selection: function with most refs, ties broken by
            # preferring class-namespaced functions over Global ones
            anchor_fn = ""
            anchor_fn_ns = ""
            anchor_fn_refs = 0
            if all_fn_refs:
                def _anchor_key(fn_name: str) -> tuple:
                    cnt = all_fn_refs[fn_name]
                    has_class = fn_ns_map.get(fn_name, "Global") != "Global"
                    return (cnt, has_class, fn_name)

                best_name = max(all_fn_refs, key=_anchor_key)
                anchor_fn = best_name
                anchor_fn_refs = all_fn_refs[best_name]
                anchor_fn_ns = fn_ns_map.get(best_name, "Global")

            # Indirect anchor selection (same logic as direct)
            indirect_anchor_fn = ""
            indirect_anchor_fn_ns = ""
            if indirect_fn_refs:
                def _indirect_anchor_key(fn_name: str) -> tuple:
                    cnt = indirect_fn_refs[fn_name]
                    has_class = indirect_fn_ns_map.get(fn_name, "Global") != "Global"
                    return (cnt, has_class, fn_name)

                best_ind = max(indirect_fn_refs, key=_indirect_anchor_key)
                indirect_anchor_fn = best_ind
                indirect_anchor_fn_ns = indirect_fn_ns_map.get(best_ind, "Global")

            total_refs = code_refs + data_refs
            row = {
                "address": f"0x{offset:08x}",
                "old_name": old_name,
                "data_type": data_type,
                "data_len": data_len,
                "total_refs": str(total_refs),
                "code_refs": str(code_refs),
                "data_refs": str(data_refs),
                "read_refs": str(read_refs),
                "write_refs": str(write_refs),
                "unique_readers": str(len(reader_fns)),
                "unique_writers": str(len(writer_fns)),
                "anchor_fn": anchor_fn,
                "anchor_fn_namespace": anchor_fn_ns,
                "anchor_fn_refs": str(anchor_fn_refs),
                "top_readers": _format_top_n(reader_fns),
                "top_writers": _format_top_n(writer_fns),
                "reader_namespaces": ";".join(sorted(reader_ns)),
                "writer_namespaces": ";".join(sorted(writer_ns)),
                "indirect_code_refs": str(indirect_code_refs),
                "indirect_unique_fns": str(len(indirect_fn_refs)),
                "indirect_anchor_fn": indirect_anchor_fn,
                "indirect_anchor_fn_namespace": indirect_anchor_fn_ns,
                "indirect_top_fns": _format_top_n(indirect_fn_refs),
            }
            rows.append(row)

            if (idx + 1) % 500 == 0:
                print(f"  [progress] {idx + 1}/{len(symbols)} symbols processed, {len(rows)} rows emitted")

    # --- Phase 4: Output ---
    # Sort: symbols with any code context (direct or indirect) rank highest
    rows.sort(
        key=lambda r: (
            int(r["code_refs"]) + int(r["indirect_code_refs"]),
            int(r["total_refs"]),
        ),
        reverse=True,
    )

    write_csv_rows(out_csv, rows, ATLAS_FIELDNAMES)

    print(f"\n[result] {len(rows)} symbols with >= {args.min_code_refs} code xrefs")
    print(f"[result] {skipped_low_refs} symbols skipped (below --min-code-refs)")
    print(f"[saved] {out_csv}")

    # Quick stats
    if rows:
        total_code = sum(int(r["code_refs"]) for r in rows)
        total_data = sum(int(r["data_refs"]) for r in rows)
        total_indirect = sum(int(r["indirect_code_refs"]) for r in rows)
        with_code = sum(1 for r in rows if int(r["code_refs"]) > 0)
        with_indirect = sum(1 for r in rows if int(r["indirect_code_refs"]) > 0)
        with_any_code = sum(
            1 for r in rows
            if int(r["code_refs"]) > 0 or int(r["indirect_code_refs"]) > 0
        )
        top_total = rows[0]
        top_code = max(rows, key=lambda r: int(r["code_refs"]))
        print(f"[stats] {with_code} symbols with direct code xrefs, {with_indirect} with indirect code xrefs")
        print(f"[stats] {with_any_code} with any code context, {len(rows) - with_any_code} truly data-only")
        print(f"[stats] total code xrefs: {total_code}, indirect: {total_indirect}, data: {total_data}")
        print(f"[stats] most total refs: {top_total['total_refs']} ({top_total['old_name']})")
        print(f"[stats] most code refs: {top_code['code_refs']} ({top_code['old_name']})")

        ns_counts: Counter = Counter()
        for r in rows:
            for ns in r["reader_namespaces"].split(";"):
                if ns:
                    ns_counts[ns] += 1
        if ns_counts:
            print(f"[stats] top referencing namespaces:")
            for ns, cnt in ns_counts.most_common(10):
                print(f"  {ns}: {cnt} symbols")

    # --- Phase 5: Emit rename CSV (optional) ---
    if args.emit_rename_csv:
        rename_path = Path(args.emit_rename_csv)
        if not rename_path.is_absolute():
            rename_path = root / rename_path
        rename_path.parent.mkdir(parents=True, exist_ok=True)

        rename_rows = []
        seen_names: set[str] = set()
        for r in rows:
            if int(r["code_refs"]) == 0:
                continue
            anchor = r["anchor_fn"]
            if not anchor or "ftol" in anchor.lower():
                continue

            addr_hex = r["address"]
            new_name = ""
            for pat, formatter in _RENAME_RULES:
                m = pat.search(anchor)
                if m:
                    new_name = formatter(m, addr_hex)
                    break

            if not new_name:
                # Fallback: g_<anchorFnShortened>_<addrSuffix>
                short = anchor[:40].replace(" ", "_")
                new_name = f"g_{short}_{addr_hex[-8:]}"

            # Deduplicate
            base = new_name
            seq = 1
            while new_name in seen_names:
                new_name = f"{base}_{seq}"
                seq += 1
            seen_names.add(new_name)

            rename_rows.append({
                "address": addr_hex,
                "new_name": new_name,
                "type": "",
                "comment": f"anchor: {anchor}",
            })

        write_csv_rows(rename_path, rename_rows, RENAME_FIELDNAMES)
        print(f"\n[rename] {len(rename_rows)} rename candidates written to {rename_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
