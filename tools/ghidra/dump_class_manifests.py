#!/usr/bin/env python3
"""Stage 0: batch-dump per-class manifests from the Ghidra DB (read-only).

For every MFC ``CRuntimeClass`` descriptor in the binary this recovers — using the
same intact runtime-class data ``apply_mfc_rtti`` mines — the class's vtable,
object size (``m_nObjectSize``), inheritance chain (``m_pBaseClass``), and the
resolved per-slot bodies, classifies each slot with the shared
``class_codegen.classify_slots``, and writes ``config/classes/<Class>.yml``.

The ``generated:`` region is refreshed wholesale; any existing ``curated:`` region
is preserved verbatim (curated always wins, keyed by slot index). Nothing
consumes the manifests yet — this is the inspectable single-artifact-per-class
that replaces the cross-file hunt, and it is fully reversible (delete the files).

Usage:
  uv run python -m tools.ghidra.dump_class_manifests [--only Name] [--limit N] [--out-dir DIR]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from tools.common import class_manifest as cm
from tools.common import ghidra_env
from tools.common.repo import repo_root_from_file
from tools.workflow.class_codegen import ClassifiedSlot, classify_slots

SCHEMA_MAGIC = 0xFFFF
DESC_SIZE = 0x18
IMG_LO, IMG_HI = 0x400000, 0x700000
MAX_SLOTS = 512

REPO_ROOT = repo_root_from_file(__file__)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Batch-dump per-class manifests from Ghidra.")
    p.add_argument("--only", default=None, help="Restrict to a single class name.")
    p.add_argument("--limit", type=int, default=0, help="Process at most N classes (0 = all).")
    p.add_argument(
        "--out-dir",
        default=str(REPO_ROOT / "config" / "classes"),
        help="Output directory for the <Class>.yml manifests.",
    )
    p.add_argument("--quiet", action="store_true", help="Suppress per-class progress.")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    out_dir = Path(args.out_dir)

    project = ghidra_env.open_project()
    consumer = None
    program = None
    try:
        consumer, program = ghidra_env.open_program(project)
        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()
        listing = program.getListing()
        mem = program.getMemory()
        refmgr = program.getReferenceManager()

        def A(x: int):
            return af.getAddress(x)

        def rd(a: int) -> int:
            return mem.getInt(A(a)) & 0xFFFFFFFF

        def in_image(a: int) -> bool:
            return IMG_LO <= a < IMG_HI

        def read_cstr(addr: int, limit: int = 96) -> str:
            bs = bytearray()
            for i in range(limit):
                try:
                    b = mem.getByte(A(addr + i)) & 0xFF
                except Exception:  # noqa: BLE001
                    break
                if b == 0:
                    break
                if b < 0x20 or b > 0x7E:
                    return ""
                bs.append(b)
            return bs.decode("latin1", "replace")

        # ---- descriptor discovery (structural signature scan) ----
        def looks_like_descriptor(addr: int) -> str | None:
            try:
                name_ptr = rd(addr)
                size = rd(addr + 4)
                schema = rd(addr + 8)
                base = rd(addr + 0x10)
            except Exception:  # noqa: BLE001
                return None
            if schema != SCHEMA_MAGIC or not in_image(name_ptr):
                return None
            if not (4 <= size <= 0x20000):
                return None
            if base != 0 and not in_image(base):
                return None
            name = read_cstr(name_ptr)
            if not name or not name[0].isalpha():
                return None
            return name

        def find_descriptors() -> dict[int, str]:
            found: dict[int, str] = {}
            for blk in mem.getBlocks():
                if not blk.isInitialized() or blk.isExecute():
                    continue
                start = int(blk.getStart().getOffset())
                end = int(blk.getEnd().getOffset())
                a = start
                while a <= end - DESC_SIZE:
                    nm = looks_like_descriptor(a)
                    if nm is not None:
                        found[a] = nm
                        a += DESC_SIZE
                    else:
                        a += 4
            return found

        # ---- thunk resolution ----
        def resolve(entry: int) -> int:
            target = entry
            for _ in range(8):
                addr = A(target)
                fn = fm.getFunctionContaining(addr)
                if fn is not None and fn.isThunk():
                    tf = fn.getThunkedFunction(True)
                    if tf is not None:
                        nxt = int(tf.getEntryPoint().getOffset())
                        if nxt == target:
                            break
                        target = nxt
                        continue
                if fn is not None and int(fn.getEntryPoint().getOffset()) == target:
                    break
                ins = listing.getInstructionAt(addr)
                if ins is None:
                    break
                if ins.getMnemonicString().lower() == "jmp" and len(ins.getFlows()) == 1:
                    target = int(ins.getFlows()[0].getOffset())
                else:
                    break
            return target

        # ---- vtable discovery via the reference graph ----
        def descriptor_to_vtable(desc: int) -> int | None:
            for r in refmgr.getReferencesTo(A(desc)):
                fn = fm.getFunctionContaining(r.getFromAddress())
                if fn is None:
                    continue
                getter = int(fn.getEntryPoint().getOffset())
                for r2 in refmgr.getReferencesTo(A(getter)):
                    fa = int(r2.getFromAddress().getOffset())
                    ins = listing.getInstructionAt(A(fa))
                    if ins is not None and ins.getMnemonicString().lower() == "jmp":
                        for r3 in refmgr.getReferencesTo(A(fa)):
                            fa3 = int(r3.getFromAddress().getOffset())
                            if listing.getInstructionAt(A(fa3)) is None:
                                return fa3
                    elif ins is None:
                        return fa
            return None

        def slot_record(index: int, entry: int) -> dict:
            rec: dict = {
                "index": index,
                "byte_offset": index * 4,
                "slot_label": f"0x{index * 4:02x}",
                "is_null": entry == 0,
            }
            if entry == 0:
                rec["target_addr"] = "0x00000000"
                return rec
            target = resolve(entry)
            rec["target_addr"] = f"0x{target:08x}"
            fn = fm.getFunctionContaining(A(target))
            if fn is not None:
                rec["is_thunk"] = bool(fn.isThunk())
                rec["ghidra_name"] = fn.getName(True)
                rec["size"] = fn.getBody().getNumAddresses()
                rec["prototype"] = fn.getSignature(True).getPrototypeString()
            else:
                rec["ghidra_name"] = None
            return rec

        def extract_slots(vtable: int, all_vtables: set[int]) -> list[dict]:
            """Resolve a vtable's slots up to its boundary.

            The boundary is precise: the next table begins where a *slot address*
            (``vtable + 4*i``) is itself a known vtable start — far more reliable
            than the slot-points-at-a-getter heuristic, which false-positives on the
            many shared dispatch slots that resolve to a getter-named body. We also
            stop on genuine trailing garbage (an in-image entry that resolves to no
            function), and trim trailing nulls (ambiguous padding vs. abstract
            slots)."""
            slots: list[dict] = []
            for i in range(MAX_SLOTS):
                if i > 0 and (vtable + 4 * i) in all_vtables:
                    break
                try:
                    entry = rd(vtable + 4 * i)
                except Exception:  # noqa: BLE001
                    break
                rec = slot_record(i, entry)
                if i > 0 and not rec["is_null"] and not in_image(int(rec["target_addr"], 16)):
                    break
                if i > 0 and not rec["is_null"] and rec.get("ghidra_name") is None:
                    break
                slots.append(rec)
            while slots and slots[-1]["is_null"]:
                slots.pop()
            return slots

        # ---- RTTI ancestry ----
        def walk_ancestry(desc: int) -> list[str]:
            names: list[str] = []
            seen: set[int] = set()
            cur = desc
            while cur and in_image(cur) and cur not in seen:
                seen.add(cur)
                try:
                    name = read_cstr(rd(cur))
                    base = rd(cur + 0x10)
                except Exception:  # noqa: BLE001
                    break
                if not name:
                    break
                names.append(name)
                if base == 0:
                    break
                cur = base
            return names

        # ------------------------------------------------------------------ #
        descs = find_descriptors()
        by_name: dict[str, int] = {}
        for addr, nm in sorted(descs.items()):
            by_name.setdefault(nm, addr)

        # First pass: locate every class's vtable so the slot extractor knows the
        # full set of table starts (the precise extent boundary). This is computed
        # for ALL classes even under --only, since a boundary may be another class.
        vtable_of: dict[str, int] = {}
        for nm, desc_addr in sorted(by_name.items()):
            vt = descriptor_to_vtable(desc_addr)
            if vt is not None:
                vtable_of[nm] = vt
        all_vtables = set(vtable_of.values())

        items = sorted(by_name.items())
        if args.only:
            items = [(n, a) for n, a in items if n == args.only]
        if args.limit:
            items = items[: args.limit]

        written = 0
        skipped = 0
        for cls, desc_addr in items:
            vt = vtable_of.get(cls)
            if vt is None:
                skipped += 1
                if not args.quiet:
                    print(f"[dump-manifests] {cls}: no vtable located; skipped.", file=sys.stderr)
                continue

            object_size = rd(desc_addr + 4)
            ancestry = walk_ancestry(desc_addr)
            base = ancestry[1] if len(ancestry) > 1 else None
            root = "TObject" if "TObject" in ancestry[1:] else "CObject"

            class_slots = extract_slots(vt, all_vtables)
            base_slots: list[dict] = []
            if base and base in vtable_of:
                base_slots = extract_slots(vtable_of[base], all_vtables)

            classified: list[ClassifiedSlot] = classify_slots(class_slots, base_slots, {})

            slot_dicts = []
            for s in classified:
                d: dict = {
                    "index": s.index,
                    "byte": s.byte_offset,
                    "target": int(s.target_addr or "0", 16),
                    "kind": s.kind,
                    "is_thunk": bool(
                        next(
                            (cs.get("is_thunk") for cs in class_slots if cs["index"] == s.index),
                            False,
                        )
                    ),
                    "is_null": s.kind == "null",
                }
                if s.qualified_name:
                    d["ghidra_name"] = s.qualified_name
                if s.size:
                    d["size"] = s.size
                if s.prototype:
                    d["prototype"] = s.prototype
                slot_dicts.append(d)

            generated = {
                "vtable_addr": f"0x{vt:08x}",
                "object_size": object_size,
                "base": base or "",
                "ancestry": ancestry,
                "root": root,
                "slots": slot_dicts,
            }

            out_path = out_dir / f"{cls}.yml"
            existing = cm.load_manifest(out_path) if out_path.exists() else None
            manifest = cm.merge_refresh(existing, generated, cls)
            if cm.write_manifest(out_path, manifest):
                written += 1
            if not args.quiet:
                kinds: dict[str, int] = {}
                for s in classified:
                    kinds[s.kind] = kinds.get(s.kind, 0) + 1
                summary = " ".join(f"{k}={v}" for k, v in sorted(kinds.items()))
                print(f"[dump-manifests] {cls}: vt=0x{vt:08x} size=0x{object_size:x} "
                      f"base={base or '<root>'} slots={len(classified)} ({summary})")

        print(f"[dump-manifests] wrote/updated {written} manifest(s); skipped {skipped} "
              f"(no vtable) of {len(items)} class(es).", file=sys.stderr)
    finally:
        if program is not None:
            program.release(consumer)
        project.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
