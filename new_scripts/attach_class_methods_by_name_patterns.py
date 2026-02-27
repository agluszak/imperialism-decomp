#!/usr/bin/env python3
"""
Attach global functions to existing class namespaces using conservative name patterns.

Patterns:
  - [thunk_]Create<Class>Instance
  - [thunk_]Construct<Class>[BaseState]
  - [thunk_]Destruct<Class>[BaseState|AndMaybeFree]
  - [thunk_]Delete<Class>[AndMaybeFree]
  - [thunk_]Get<Class>ClassNamePointer
  - [thunk_]Get<Class>RuntimeClassDescriptor

Only attaches when:
  - function is currently in Global namespace
  - inferred <Class> already exists as a class namespace

Usage:
  .venv/bin/python new_scripts/attach_class_methods_by_name_patterns.py [--apply] [--project-root PATH]
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

import pyghidra

GHIDRA_DIR = Path(
    "/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC"
)
PROJECT_NAME = "imperialism-decomp"
PROGRAM_PATH = "/Imperialism.exe"

PAT = re.compile(r"^(?:thunk_)?(?:Create|Construct|Destruct|Delete|Get)([A-Za-z0-9_]+)$")
SUFFIXES = (
    "ClassNamePointer",
    "RuntimeClassDescriptor",
    "AndMaybeFree",
    "BaseState",
    "Instance",
)


def open_project_with_lock_cleanup(root: Path):
    try:
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)
    except Exception:
        for lock_file in (root / f"{PROJECT_NAME}.lock", root / f"{PROJECT_NAME}.lock~"):
            if lock_file.exists():
                lock_file.unlink()
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)


def infer_class_name(func_name: str) -> str | None:
    raw = func_name.strip()
    if raw.startswith("?"):
        raw = raw[1:]
    if "@@" in raw:
        raw = raw.split("@@", 1)[0]
    m = PAT.match(raw)
    if not m:
        return None
    stem = m.group(1)
    for s in SUFFIXES:
        if stem.endswith(s) and len(stem) > len(s):
            stem = stem[: -len(s)]
            break
    if not stem:
        return None
    return stem


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true", help="Write namespace attachments")
    ap.add_argument("--start", default="", help="Optional inclusive start address (hex)")
    ap.add_argument("--end", default="", help="Optional inclusive end address (hex)")
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    def parse_hex_opt(text: str) -> int | None:
        t = (text or "").strip()
        if not t:
            return None
        if t.lower().startswith("0x"):
            return int(t, 16)
        return int(t, 16)

    addr_start = parse_hex_opt(args.start)
    addr_end = parse_hex_opt(args.end)

    root = Path(args.project_root).resolve()
    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        st = program.getSymbolTable()
        fm = program.getFunctionManager()
        global_ns = program.getGlobalNamespace()

        # Collect known class namespaces once.
        class_map = {}
        it_cls = st.getClassNamespaces()
        while it_cls.hasNext():
            ns = it_cls.next()
            class_map[ns.getName()] = ns

        candidates = []
        it = fm.getFunctions(True)
        while it.hasNext():
            f = it.next()
            ep = int(f.getEntryPoint().getOffset() & 0xFFFFFFFF)
            if addr_start is not None and ep < addr_start:
                continue
            if addr_end is not None and ep > addr_end:
                continue
            if f.getParentNamespace() != global_ns:
                continue
            cls_name = infer_class_name(f.getName())
            if not cls_name:
                continue
            cls_ns = class_map.get(cls_name)
            if cls_ns is None:
                continue
            candidates.append((f, cls_name, cls_ns))

        print(f"[candidates] {len(candidates)}")
        for f, cls_name, _ in candidates[:200]:
            print(f"  {f.getEntryPoint()} {f.getName()} -> {cls_name}")
        if len(candidates) > 200:
            print(f"  ... ({len(candidates) - 200} more)")

        if not args.apply:
            print("[dry-run] pass --apply to write changes")
            return 0

        tx = program.startTransaction("Attach class methods by name patterns")
        ok = 0
        skip = 0
        fail = 0
        try:
            for f, _cls_name, cls_ns in candidates:
                try:
                    if f.getParentNamespace() == cls_ns:
                        skip += 1
                        continue
                    f.setParentNamespace(cls_ns)
                    ok += 1
                except Exception as ex:
                    fail += 1
                    print(f"[fail] {f.getEntryPoint()} {f.getName()} err={ex}")
        finally:
            program.endTransaction(tx, True)

        program.save("attach class methods by name patterns", None)
        print(f"[done] ok={ok} skip={skip} fail={fail}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
