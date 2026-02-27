#!/usr/bin/env python3
"""
Create/update class structure datatypes from mined field-candidate CSV rows.

Designed for conservative class-model extraction passes where we have only
offset evidence and want generic placeholder fields, not speculative semantics.

Supported CSV columns (flexible):
  - class_name
  - offset_hex and/or offset_dec
  - hit_count (optional)
  - confidence (optional: low|medium|high)
  - suggested_field_name (optional)
  - suggested_type (optional; defaults to uint)
  - sample_methods (optional, copied into field comments)

Usage examples:
  # Dry-run summary
  .venv/bin/python new_scripts/apply_class_structs_from_candidates.py \
    --csv tmp_decomp/class_field_candidates_batch356_top5.csv \
    --classes TViewMgr TMultiplayerMgr TEditText TAmtBarCluster \
    --min-hit 2

  # Apply filtered batch
  .venv/bin/python new_scripts/apply_class_structs_from_candidates.py \
    --csv tmp_decomp/class_field_candidates_batch356_top5.csv \
    --classes TViewMgr TMultiplayerMgr TEditText TAmtBarCluster \
    --min-hit 2 --apply
"""

from __future__ import annotations

import argparse
import csv
import re
from collections import defaultdict
from pathlib import Path

import pyghidra

GHIDRA_DIR = Path(
    "/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC"
)
PROJECT_NAME = "imperialism-decomp"
PROGRAM_PATH = "/Imperialism.exe"

CONF_RANK = {"low": 1, "medium": 2, "high": 3}


def parse_hex_maybe(text: str | None) -> int | None:
    if text is None:
        return None
    s = text.strip()
    if not s:
        return None
    if s.lower().startswith("0x"):
        return int(s, 16)
    return int(s, 16)


def parse_int_maybe(text: str | None) -> int | None:
    if text is None:
        return None
    s = text.strip()
    if not s:
        return None
    return int(s, 10)


def open_project_with_lock_cleanup(root: Path):
    try:
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)
    except Exception:
        for lock_file in (root / f"{PROJECT_NAME}.lock", root / f"{PROJECT_NAME}.lock~"):
            if lock_file.exists():
                lock_file.unlink()
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)


def sanitize_name(name: str, fallback: str) -> str:
    n = (name or "").strip()
    if not n:
        n = fallback
    n = re.sub(r"[^0-9A-Za-z_]", "_", n)
    if not n:
        n = fallback
    if n[0].isdigit():
        n = f"f_{n}"
    return n


def type_key(raw: str | None) -> str:
    t = (raw or "").strip().lower()
    if not t:
        return "uint"
    return t


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True, help="Input candidate CSV")
    ap.add_argument("--classes", nargs="*", default=[], help="Optional class-name allow list")
    ap.add_argument("--min-hit", type=int, default=1, help="Minimum hit_count to accept")
    ap.add_argument(
        "--min-confidence",
        choices=["low", "medium", "high"],
        default="low",
        help="Minimum confidence if confidence column exists",
    )
    ap.add_argument(
        "--require-aligned",
        action="store_true",
        help="Only include offsets aligned to 4 bytes",
    )
    ap.add_argument(
        "--category",
        default="/imperialism/classes",
        help="Datatype category path for emitted structures",
    )
    ap.add_argument(
        "--force-replace-existing",
        action="store_true",
        help="Replace existing datatype with same class name",
    )
    ap.add_argument(
        "--create-empty-for-classes",
        action="store_true",
        help="When --classes is set, create vtable-only structs even if no offset rows pass filters",
    )
    ap.add_argument("--apply", action="store_true", help="Apply changes (default: dry-run)")
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

    wanted = set(args.classes)
    min_conf_rank = CONF_RANK[args.min_confidence]

    rows = list(csv.DictReader(in_csv.open("r", encoding="utf-8")))
    if not rows:
        print(f"[done] no rows in {in_csv}")
        return 0

    # class -> off -> best candidate row by confidence/hit
    grouped: dict[str, dict[int, dict[str, str]]] = defaultdict(dict)
    dropped = 0
    for r in rows:
        cname = (r.get("class_name") or "").strip()
        if not cname:
            dropped += 1
            continue
        if wanted and cname not in wanted:
            continue

        off = parse_int_maybe(r.get("offset_dec"))
        if off is None:
            hx = parse_hex_maybe(r.get("offset_hex"))
            off = hx if hx is not None else None
        if off is None:
            dropped += 1
            continue
        if off < 0:
            dropped += 1
            continue
        if args.require_aligned and (off % 4 != 0):
            dropped += 1
            continue

        hit_count = parse_int_maybe(r.get("hit_count")) or 1
        if hit_count < args.min_hit:
            continue

        conf_s = (r.get("confidence") or "high").strip().lower()
        conf_rank = CONF_RANK.get(conf_s, 3)
        if conf_rank < min_conf_rank:
            continue

        prev = grouped[cname].get(off)
        if prev is None:
            grouped[cname][off] = r
            continue

        prev_conf = CONF_RANK.get((prev.get("confidence") or "high").strip().lower(), 3)
        prev_hit = parse_int_maybe(prev.get("hit_count")) or 1
        # Prefer higher confidence, then higher hit_count.
        if (conf_rank, hit_count) > (prev_conf, prev_hit):
            grouped[cname][off] = r

    classes = sorted(grouped.keys())
    if args.create_empty_for_classes and wanted:
        for cname in sorted(wanted):
            grouped.setdefault(cname, {})
        classes = sorted(grouped.keys())
    total_fields = sum(len(grouped[c]) for c in classes)
    print(
        f"[plan] csv={in_csv} classes={len(classes)} total_fields={total_fields} "
        f"dropped_rows={dropped} apply={args.apply}"
    )
    for cname in classes:
        offs = sorted(grouped[cname].keys())
        print(f"[plan] {cname}: fields={len(offs)} offsets={','.join(hex(x) for x in offs)}")

    if not args.apply:
        return 0

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        from ghidra.program.model.data import (
            CategoryPath,
            DataTypeConflictHandler,
            PointerDataType,
            StructureDataType,
            UnsignedIntegerDataType,
            VoidDataType,
        )

        dtm = program.getDataTypeManager()
        cat = CategoryPath(args.category)

        p_void = PointerDataType(VoidDataType.dataType)
        u32 = UnsignedIntegerDataType.dataType

        tx = program.startTransaction("Apply class structs from candidates")
        created = replaced = skipped_existing = failed = 0
        try:
            for cname in classes:
                existing = dtm.getDataType(cat, cname)
                if existing is not None and not args.force_replace_existing:
                    skipped_existing += 1
                    print(f"[skip-existing] {cname} ({existing.getClass().getSimpleName()})")
                    continue

                offsets = sorted(grouped[cname].keys())
                max_off = max(offsets + [0])
                size = max(4, max_off + 4)
                st = StructureDataType(cat, cname, size)

                # Always keep a conventional vtable pointer at offset 0 for class-like objects.
                st.replaceAtOffset(0, p_void, 4, "pVtable", "auto: class vtable pointer")

                used_names: set[str] = {"pVtable"}
                for off in offsets:
                    if off == 0:
                        continue
                    row = grouped[cname][off]
                    fallback_name = f"dwField_{off:02X}"
                    fname = sanitize_name(row.get("suggested_field_name") or "", fallback_name)
                    if fname in used_names:
                        fname = f"{fname}_{off:02X}"
                    used_names.add(fname)

                    tkey = type_key(row.get("suggested_type"))
                    # Keep types conservative for now; widen later from usage proofs.
                    dtype = u32 if tkey in {"uint", "dword", "int", "ulong", "udword"} else u32

                    methods = (row.get("sample_methods") or "").strip()
                    cmt = f"auto: hit_count={row.get('hit_count','?')}"
                    if methods:
                        cmt = f"{cmt}; methods={methods}"
                    st.replaceAtOffset(off, dtype, 4, fname, cmt)

                try:
                    dtm.addDataType(st, DataTypeConflictHandler.REPLACE_HANDLER)
                    if existing is None:
                        created += 1
                        print(f"[create] {cname} size=0x{size:x} fields={len(offsets) + 1}")
                    else:
                        replaced += 1
                        print(f"[replace] {cname} size=0x{size:x} fields={len(offsets) + 1}")
                except Exception as ex:
                    failed += 1
                    print(f"[fail] {cname} err={ex}")
        finally:
            program.endTransaction(tx, True)

        program.save("apply class structs from candidate offsets", None)
        print(
            f"[done] created={created} replaced={replaced} "
            f"skipped_existing={skipped_existing} failed={failed}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
