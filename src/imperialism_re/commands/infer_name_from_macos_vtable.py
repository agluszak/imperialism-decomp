#!/usr/bin/env python3
"""
Propose Windows function renames by correlating vtable slot positions with macOS debug names.

Algorithm:
  1. Load macos_vtable_layout.csv → class → {slot_index → method_name}
  2. Open Windows binary; for each class present in the vtable data:
     - Find g_vtbl_ClassName symbol in Windows symbol table
     - Walk 4-byte little-endian slots from that address
     - For each slot: resolve to Windows function, look up macOS name at same slot index
     - Emit rename candidate
  3. Confidence:
     - high: macOS slot exists, Windows function is unnamed (FUN_*, thunk_FUN_*, Cluster_*)
     - medium: macOS slot exists, Windows function is already named but differs from macOS
     - skip: names already match

Output CSV:
  address, class_name, proposed_name, slot_index, confidence, evidence, current_name

Usage:
  uv run impk infer_name_from_macos_vtable \\
      --vtable-layout-csv tmp_decomp/macos_vtable_layout.csv \\
      --out-csv tmp_decomp/macos_vtable_rename_candidates.csv
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.ghidra_session import open_program


def _is_generic_name(name: str) -> bool:
    return (
        name.startswith("FUN_")
        or name.startswith("thunk_FUN_")
        or name.startswith("Cluster_")
        or (name.startswith("thunk_") and "FUN_" in name)
    )


def _should_emit(confidence: str, filter_level: str) -> bool:
    if filter_level == "all":
        return True
    if filter_level == "low":
        return confidence in ("high", "medium", "low")
    if filter_level == "high":
        return confidence == "high"
    if filter_level == "medium":
        return confidence in ("high", "medium")
    return True


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Propose Windows renames from macOS vtable slot correlation.",
    )
    ap.add_argument(
        "--vtable-layout-csv",
        default="tmp_decomp/macos_vtable_layout.csv",
        help="macOS vtable layout CSV from extract_macos_vtable_layout (default: tmp_decomp/macos_vtable_layout.csv)",
    )
    ap.add_argument(
        "--out-csv",
        default="tmp_decomp/macos_vtable_rename_candidates.csv",
        help="Output rename candidates CSV (default: tmp_decomp/macos_vtable_rename_candidates.csv)",
    )
    ap.add_argument(
        "--confidence-filter",
        default="all",
        choices=["all", "low", "high", "medium"],
        help="Emit only candidates at this level or above: high < medium < low/all (default: all)",
    )
    ap.add_argument(
        "--classes",
        default="",
        help="Comma-separated class filter (default: all)",
    )
    ap.add_argument(
        "--windows-slot-map-csv",
        default="",
        help=(
            "Optional Windows runtime slot-map CSV "
            "(from extract_windows_runtime_vtable_slot_writes --out-best-csv). "
            "When set, use it instead of static memory walking."
        ),
    )
    ap.add_argument("--project-root", default=default_project_root())
    args = ap.parse_args()

    root = resolve_project_root(args.project_root)
    vtable_csv = Path(args.vtable_layout_csv)
    if not vtable_csv.is_absolute():
        vtable_csv = root / vtable_csv
    out_csv = Path(args.out_csv)
    if not out_csv.is_absolute():
        out_csv = root / out_csv
    out_csv.parent.mkdir(parents=True, exist_ok=True)

    class_filter: set[str] = {x.strip() for x in args.classes.split(",") if x.strip()}

    # Load macOS vtable layout: class → {slot_index → (method_name, layout_source)}
    macos_layout: dict[str, dict[int, tuple[str, str]]] = {}
    with vtable_csv.open("r", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            cls = row["class"]
            if class_filter and cls not in class_filter:
                continue
            slot = int(row["slot_index"])
            method = row["method_name"]
            layout_source = (row.get("layout_source") or "").strip() or "unknown"
            macos_layout.setdefault(cls, {})[slot] = (method, layout_source)

    print(f"[macos_layout] {len(macos_layout)} classes loaded")

    slot_map_csv = Path(args.windows_slot_map_csv) if args.windows_slot_map_csv else None
    if slot_map_csv is not None and not slot_map_csv.is_absolute():
        slot_map_csv = root / slot_map_csv

    rows: list[dict] = []

    if slot_map_csv is not None and slot_map_csv.exists():
        # Use reconstructed runtime slot mapping.
        by_class_slot: dict[tuple[str, int], dict[str, str]] = {}
        with slot_map_csv.open("r", encoding="utf-8", newline="") as fh:
            for row in csv.DictReader(fh):
                cls = (row.get("class_name") or "").strip()
                if not cls:
                    continue
                if class_filter and cls not in class_filter:
                    continue
                try:
                    slot_index = int((row.get("slot_index") or "").strip())
                except ValueError:
                    continue
                by_class_slot[(cls, slot_index)] = row

        for class_name, slot_map in sorted(macos_layout.items()):
            candidates_for_class = 0
            for slot_index, payload in sorted(slot_map.items()):
                macos_name, layout_source = payload
                mapped = by_class_slot.get((class_name, slot_index))
                if mapped is None:
                    continue
                win_addr = (mapped.get("target_addr") or "").strip()
                win_name = (mapped.get("target_name") or "").strip()
                if not win_addr or not win_name:
                    continue
                if win_name == macos_name:
                    continue
                if layout_source != "ctor_vtable_store":
                    confidence = "low"
                else:
                    confidence = "high" if _is_generic_name(win_name) else "medium"
                if not _should_emit(confidence, args.confidence_filter):
                    continue
                rows.append({
                    "address": win_addr,
                    "class_name": class_name,
                    "proposed_name": macos_name,
                    "slot_index": slot_index,
                    "confidence": confidence,
                    "evidence": f"windows_runtime_slot_{slot_index}:{layout_source}",
                    "current_name": win_name,
                })
                candidates_for_class += 1
            if candidates_for_class:
                print(f"[ok] {class_name}: {candidates_for_class} candidates (runtime-slot-map)")

    else:
        with open_program(root) as program:
            fm = program.getFunctionManager()
            sym_table = program.getSymbolTable()
            mem = program.getMemory()
            af = program.getAddressFactory().getDefaultAddressSpace()

            for class_name, slot_map in sorted(macos_layout.items()):
                vtbl_sym_name = f"g_vtbl{class_name}"

                # Search symbol table for g_vtblClassName
                vtbl_addr = None
                for sym in sym_table.getSymbols(vtbl_sym_name):
                    vtbl_addr = sym.getAddress()
                    break
                if vtbl_addr is None:
                    # Fallback: linear scan (slower but handles namespaced symbols)
                    for sym in sym_table.getAllSymbols(True):
                        if str(sym.getName()) == vtbl_sym_name:
                            vtbl_addr = sym.getAddress()
                            break
                if vtbl_addr is None:
                    continue

                vtbl_int = vtbl_addr.getOffset() & 0xFFFFFFFF

                # Walk Windows vtable slots (little-endian, 4 bytes each)
                candidates_for_class = 0
                slot_index = 0
                offset = 0
                while slot_index <= 200:
                    slot_addr = af.getAddress(f"{vtbl_int + offset:08x}")
                    try:
                        dword_bytes = bytearray(4)
                        cnt = mem.getBytes(slot_addr, dword_bytes)
                        if cnt < 4:
                            break
                        fn_ptr = int.from_bytes(dword_bytes, "little")
                    except Exception:
                        break

                    fn_addr_obj = af.getAddress(f"{fn_ptr:08x}")
                    win_fn = fm.getFunctionAt(fn_addr_obj)
                    if win_fn is None:
                        break

                    payload = slot_map.get(slot_index)
                    if payload is not None:
                        macos_name, layout_source = payload
                        win_name = str(win_fn.getName())
                        if win_name == macos_name:
                            pass  # already correct, skip
                        else:
                            if layout_source != "ctor_vtable_store":
                                confidence = "low"
                            elif _is_generic_name(win_name):
                                confidence = "high"
                            else:
                                confidence = "medium"
                            if _should_emit(confidence, args.confidence_filter):
                                rows.append({
                                    "address": f"0x{fn_ptr:08x}",
                                    "class_name": class_name,
                                    "proposed_name": macos_name,
                                    "slot_index": slot_index,
                                    "confidence": confidence,
                                    "evidence": f"macos_slot_{slot_index}:{layout_source}",
                                    "current_name": win_name,
                                })
                                candidates_for_class += 1

                    slot_index += 1
                    offset += 4

                if candidates_for_class:
                    print(
                        f"[ok] {class_name}: {candidates_for_class} candidates "
                        f"({slot_index} slots walked)"
                    )

    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=[
                "address",
                "class_name",
                "proposed_name",
                "slot_index",
                "confidence",
                "evidence",
                "current_name",
            ],
        )
        w.writeheader()
        w.writerows(rows)

    high_count = sum(1 for r in rows if r["confidence"] == "high")
    med_count = sum(1 for r in rows if r["confidence"] == "medium")
    low_count = sum(1 for r in rows if r["confidence"] == "low")
    print(
        f"[saved] {out_csv} rows={len(rows)} "
        f"(high={high_count}, medium={med_count}, low={low_count})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
