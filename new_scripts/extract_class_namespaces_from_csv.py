#!/usr/bin/env python3
"""
Create/convert Ghidra class namespaces from CSV rows and attach class helpers.

Expected CSV columns:
  - type_name (required)
  - optional addresses: create, getter, ctor, dtor

Usage:
  .venv/bin/python new_scripts/extract_class_namespaces_from_csv.py <csv> [<csv> ...] [--project-root PATH]
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

import pyghidra

GHIDRA_DIR = Path(
    "/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC"
)
PROJECT_NAME = "imperialism-decomp"
PROGRAM_PATH = "/Imperialism.exe"


def parse_hex(text: str | None) -> int | None:
    if text is None:
        return None
    t = text.strip()
    if not t or t == "-":
        return None
    if t.lower().startswith("0x"):
        return int(t, 16)
    return int(t, 16)


def fmt(v: int) -> str:
    return f"0x{v:08x}"


def open_project_with_lock_cleanup(root: Path):
    try:
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)
    except Exception:
        for lock_file in (root / f"{PROJECT_NAME}.lock", root / f"{PROJECT_NAME}.lock~"):
            if lock_file.exists():
                lock_file.unlink()
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)


def load_rows(csv_paths: list[Path]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for p in csv_paths:
        with p.open("r", encoding="utf-8", newline="") as fh:
            rows.extend(csv.DictReader(fh))
    return rows


def merge_rows(rows: list[dict[str, str]]) -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    for row in rows:
        t = (row.get("type_name") or "").strip()
        if not t:
            continue
        if t not in out:
            out[t] = {"type_name": t, "create": "", "getter": "", "ctor": "", "dtor": ""}
        for col in ("create", "getter", "ctor", "dtor"):
            v = (row.get(col) or "").strip()
            if v and not out[t][col]:
                out[t][col] = v
    return out


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("csv_paths", nargs="+", help="CSV files with class rows")
    parser.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    args = parser.parse_args()

    csv_paths = [Path(p) for p in args.csv_paths]
    missing = [str(p) for p in csv_paths if not p.exists()]
    if missing:
        print(f"missing csv(s): {', '.join(missing)}")
        return 1

    root = Path(args.project_root).resolve()
    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    rows = load_rows(csv_paths)
    merged = merge_rows(rows)
    if not merged:
        print("no class rows")
        return 0

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        from ghidra.program.model.symbol import SourceType

        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()
        st = program.getSymbolTable()
        global_ns = program.getGlobalNamespace()

        tx = program.startTransaction("Extract class namespaces from CSV")
        class_created = 0
        class_existing = 0
        class_converted = 0
        class_failed = 0
        fn_attached = 0
        fn_already = 0
        fn_failed = 0

        try:
            for t, row in sorted(merged.items(), key=lambda kv: kv[0].lower()):
                class_ns = None

                try:
                    class_sym = st.getClassSymbol(t, global_ns)
                    if class_sym is not None:
                        class_ns = class_sym.getObject()
                        class_existing += 1
                    else:
                        ns = st.getNamespace(t, global_ns)
                        if ns is not None:
                            class_ns = st.convertNamespaceToClass(ns)
                            class_converted += 1
                        else:
                            class_ns = st.createClass(global_ns, t, SourceType.USER_DEFINED)
                            class_created += 1
                except Exception as ex:
                    class_failed += 1
                    print(f"[class-fail] {t} err={ex}")
                    continue

                for col in ("create", "getter", "ctor", "dtor"):
                    addr_int = parse_hex(row.get(col))
                    if addr_int is None:
                        continue
                    addr = af.getAddress(fmt(addr_int))
                    func = fm.getFunctionAt(addr)
                    if func is None:
                        fn_failed += 1
                        print(f"[fn-miss] {t} {col} {fmt(addr_int)}")
                        continue
                    try:
                        if func.getParentNamespace() == class_ns:
                            fn_already += 1
                            continue
                        func.setParentNamespace(class_ns)
                        fn_attached += 1
                    except Exception as ex:
                        fn_failed += 1
                        print(f"[fn-attach-fail] {t} {col} {fmt(addr_int)} err={ex}")
        finally:
            program.endTransaction(tx, True)

        program.save("extract class namespaces from csv", None)
        print(
            "[done] "
            f"types={len(merged)} "
            f"class_created={class_created} class_existing={class_existing} "
            f"class_converted={class_converted} class_failed={class_failed} "
            f"fn_attached={fn_attached} fn_already={fn_already} fn_failed={fn_failed}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
