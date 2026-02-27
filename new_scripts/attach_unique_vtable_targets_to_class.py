#!/usr/bin/env python3
"""
Attach globally-scoped functions to class namespaces via unique vtable ownership.

Rules:
- Read symbols named `g_vtblT*` (excluding slot/candidate/helper aliases).
- Walk dword entries from each vtable and collect valid function-entry targets.
- Build ownership map: target_function -> set(class_names).
- Attach only when ownership set size == 1 and function is currently global.

Usage:
  .venv/bin/python new_scripts/attach_unique_vtable_targets_to_class.py
  .venv/bin/python new_scripts/attach_unique_vtable_targets_to_class.py --apply
"""

from __future__ import annotations

import argparse
import re
from collections import defaultdict
from pathlib import Path

import pyghidra

GHIDRA_DIR = Path(
    "/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC"
)
PROJECT_NAME = "imperialism-decomp"
PROGRAM_PATH = "/Imperialism.exe"

VTBL_NAME_RE = re.compile(r"^g_vtbl(T[A-Za-z0-9_]+)$")
VTBL_SLOT_RE = re.compile(r"^g_vtbl_([A-Za-z0-9_]+)_Slot([0-9]+)$")


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


def collect_vtable_anchors(program, class_map: dict[str, object]) -> dict[str, set[int]]:
    st = program.getSymbolTable()
    out: dict[str, set[int]] = defaultdict(set)
    it_sym = st.getSymbolIterator()
    while it_sym.hasNext():
        sym = it_sym.next()
        name = sym.getName()

        m = VTBL_NAME_RE.match(name)
        if m:
            tname = m.group(1)
            if tname in class_map:
                out[tname].add(parse_hex(str(sym.getAddress())))
            continue

        m = VTBL_SLOT_RE.match(name)
        if not m:
            continue
        tname = m.group(1)
        if tname not in class_map:
            continue
        slot_idx = int(m.group(2))
        slot_addr = parse_hex(str(sym.getAddress()))
        base_addr = slot_addr - slot_idx * 4
        if base_addr >= 0:
            out[tname].add(base_addr)

    return out


def vtbl_function_targets(program, vtbl_addr: int, max_slots: int, max_hole_run: int) -> list[int]:
    af = program.getAddressFactory().getDefaultAddressSpace()
    mem = program.getMemory()
    fm = program.getFunctionManager()

    out: list[int] = []
    holes = 0
    saw_valid = False

    for i in range(max_slots):
        slot_addr = vtbl_addr + i * 4
        try:
            ptr = mem.getInt(af.getAddress(f"0x{slot_addr:08x}")) & 0xFFFFFFFF
        except Exception:
            holes += 1
            if saw_valid and holes >= max_hole_run:
                break
            continue

        f = fm.getFunctionAt(af.getAddress(f"0x{ptr:08x}"))
        if f is None or parse_hex(str(f.getEntryPoint())) != ptr:
            holes += 1
            if saw_valid and holes >= max_hole_run:
                break
            continue

        out.append(ptr)
        saw_valid = True
        holes = 0

    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true", help="Write namespace attachments")
    ap.add_argument("--max-slots", type=int, default=180)
    ap.add_argument("--max-hole-run", type=int, default=6)
    ap.add_argument("--min-targets-per-vtbl", type=int, default=4)
    ap.add_argument("--max-print", type=int, default=200)
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    root = Path(args.project_root).resolve()
    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        st = program.getSymbolTable()
        fm = program.getFunctionManager()
        global_ns = program.getGlobalNamespace()

        class_map = {}
        it_cls = st.getClassNamespaces()
        while it_cls.hasNext():
            ns = it_cls.next()
            class_map[ns.getName()] = ns

        vtbl_targets: dict[str, set[int]] = defaultdict(set)
        anchors = collect_vtable_anchors(program, class_map)
        vtbl_count = 0
        for tname, addr_set in anchors.items():
            for vtbl_addr in sorted(addr_set):
                vtbl_count += 1
                targets = vtbl_function_targets(program, vtbl_addr, args.max_slots, args.max_hole_run)
                if len(targets) < args.min_targets_per_vtbl:
                    continue
                vtbl_targets[tname].update(targets)

        owner_map: dict[int, set[str]] = defaultdict(set)
        for tname, targets in vtbl_targets.items():
            for tgt in targets:
                owner_map[tgt].add(tname)

        unique_candidates = []
        for tgt, owners in sorted(owner_map.items()):
            if len(owners) != 1:
                continue
            tname = next(iter(owners))
            func = fm.getFunctionAt(program.getAddressFactory().getDefaultAddressSpace().getAddress(f"0x{tgt:08x}"))
            if func is None:
                continue
            if func.getParentNamespace() != global_ns:
                continue
            unique_candidates.append((tgt, func, tname))

        print(
            "[summary] "
            f"vtbl_symbols_seen={vtbl_count} "
            f"vtbl_with_targets={len(vtbl_targets)} "
            f"owned_targets={len(owner_map)} "
            f"unique_global_candidates={len(unique_candidates)}"
        )
        for tgt, func, tname in unique_candidates[: args.max_print]:
            print(f"0x{tgt:08x} {func.getName()} -> {tname}")
        if len(unique_candidates) > args.max_print:
            print(f"... ({len(unique_candidates) - args.max_print} more)")

        if not args.apply:
            print("[dry-run] pass --apply to attach unique candidates")
            return 0

        tx = program.startTransaction("Attach unique vtable targets to class")
        ok = 0
        skip = 0
        fail = 0
        try:
            for _tgt, func, tname in unique_candidates:
                cls_ns = class_map.get(tname)
                if cls_ns is None:
                    skip += 1
                    continue
                if func.getParentNamespace() == cls_ns:
                    skip += 1
                    continue
                try:
                    func.setParentNamespace(cls_ns)
                    ok += 1
                except Exception as ex:
                    fail += 1
                    print(f"[fail] {func.getEntryPoint()} {func.getName()} -> {tname} err={ex}")
        finally:
            program.endTransaction(tx, True)

        program.save("attach unique vtable targets to class", None)
        print(f"[done] ok={ok} skip={skip} fail={fail}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
