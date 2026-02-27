#!/usr/bin/env python3
"""
Apply inheritance evidence comments from class_inheritance_edges CSV.

Effects:
  1) Adds/updates function comments at evidence function addresses.
  2) Adds/updates comments on g_pClassDesc<Derived> symbols for strong pairs.

Strength rule for class-desc annotation:
  - high_conf_count >= 2 OR total_support >= 3

Usage:
  .venv/bin/python new_scripts/apply_inheritance_edge_comments.py \
    --csv tmp_decomp/class_inheritance_edges_batch358.csv --apply
"""

from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from pathlib import Path

import pyghidra

GHIDRA_DIR = Path(
    "/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC"
)
PROJECT_NAME = "imperialism-decomp"
PROGRAM_PATH = "/Imperialism.exe"
MARKER = "[InheritanceEvidence]"


def open_project_with_lock_cleanup(root: Path):
    try:
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)
    except Exception:
        for lock_file in (root / f"{PROJECT_NAME}.lock", root / f"{PROJECT_NAME}.lock~"):
            if lock_file.exists():
                lock_file.unlink()
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)


def parse_hex(text: str) -> int:
    t = text.strip()
    if t.lower().startswith("0x"):
        return int(t, 16)
    return int(t, 16)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True, help="class_inheritance_edges CSV")
    ap.add_argument("--apply", action="store_true", help="Write comments")
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    root = Path(args.project_root).resolve()
    in_csv = Path(args.csv)
    if not in_csv.is_absolute():
        in_csv = root / in_csv
    if not in_csv.exists():
        print(f"[error] missing csv: {in_csv}")
        return 1

    rows = list(csv.DictReader(in_csv.open("r", encoding="utf-8")))
    if not rows:
        print("[done] no rows")
        return 0

    by_func: dict[int, list[dict[str, str]]] = defaultdict(list)
    by_pair: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for r in rows:
        try:
            fa = parse_hex(r.get("function_addr", "").strip())
        except Exception:
            continue
        by_func[fa].append(r)
        by_pair[(r["base_class"], r["derived_class"])].append(r)

    # Pick strong per-derived parent candidate.
    best_parent_for_derived: dict[str, tuple[str, int, int, set[str]]] = {}
    for (base, derived), pr in by_pair.items():
        total = len(pr)
        high = sum(1 for x in pr if x.get("confidence") == "high")
        kinds = {x.get("evidence_kind", "") for x in pr}
        score = high * 100 + total
        prev = best_parent_for_derived.get(derived)
        if prev is None or score > (prev[1] * 100 + prev[2]):
            best_parent_for_derived[derived] = (base, high, total, kinds)

    strong_desc = {}
    for derived, (base, high, total, kinds) in best_parent_for_derived.items():
        if high >= 2 or total >= 3:
            strong_desc[derived] = (base, high, total, kinds)

    print(
        f"[plan] rows={len(rows)} functions_to_comment={len(by_func)} "
        f"strong_desc_annotations={len(strong_desc)} apply={args.apply}"
    )
    for derived in sorted(strong_desc):
        base, high, total, kinds = strong_desc[derived]
        print(
            f"  [desc] {derived} -> {base} "
            f"(high={high},total={total},kinds={','.join(sorted(kinds))})"
        )

    if not args.apply:
        return 0

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()
        st = program.getSymbolTable()
        listing = program.getListing()
        from ghidra.program.model.listing import CodeUnit

        tx = program.startTransaction("Apply inheritance evidence comments")
        fn_ok = fn_skip = fn_fail = 0
        sym_ok = sym_skip = sym_fail = 0
        try:
            for fa, frs in by_func.items():
                f = fm.getFunctionAt(af.getAddress(f"0x{fa:08x}"))
                if f is None:
                    fn_fail += 1
                    continue
                lines = []
                for r in frs:
                    lines.append(
                        f"{MARKER} {r['derived_class']} derives from {r['base_class']} "
                        f"({r['evidence_kind']}, {r['confidence']})"
                    )
                add_block = "\n".join(sorted(set(lines)))
                cur = f.getComment() or ""
                if add_block in cur:
                    fn_skip += 1
                    continue
                new_c = (cur + "\n" + add_block).strip() if cur else add_block
                try:
                    f.setComment(new_c)
                    fn_ok += 1
                except Exception:
                    fn_fail += 1

            for derived, (base, high, total, kinds) in strong_desc.items():
                sym_name = f"g_pClassDesc{derived}"
                syms = st.getSymbols(sym_name)
                if syms is None or not syms.hasNext():
                    sym_fail += 1
                    continue
                s = syms.next()
                line = (
                    f"{MARKER} likely_base={base}; high={high}; total={total}; "
                    f"kinds={','.join(sorted(kinds))}"
                )
                cu = listing.getCodeUnitAt(s.getAddress())
                if cu is None:
                    sym_fail += 1
                    continue
                cur = cu.getComment(CodeUnit.EOL_COMMENT) or ""
                if line in cur:
                    sym_skip += 1
                    continue
                new_c = (cur + "\n" + line).strip() if cur else line
                try:
                    cu.setComment(CodeUnit.EOL_COMMENT, new_c)
                    sym_ok += 1
                except Exception:
                    sym_fail += 1
        finally:
            program.endTransaction(tx, True)

        program.save("apply inheritance edge comments", None)
        print(
            f"[done] fn_ok={fn_ok} fn_skip={fn_skip} fn_fail={fn_fail} "
            f"sym_ok={sym_ok} sym_skip={sym_skip} sym_fail={sym_fail}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
