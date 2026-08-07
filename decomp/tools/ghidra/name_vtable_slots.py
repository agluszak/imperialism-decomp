#!/usr/bin/env python3
"""Name + expand a class's ``<Class>Vtbl`` struct from its recovered header.

Ghidra carries a ``<Class>Vtbl`` struct (the class struct's ``vftable`` field
points at it), but it is typically truncated to the first slot or two and its
fields keep junk auto-names. As a result, a virtual dispatch through a receiver
typed as that class decompiles as a raw ``*(code **)(p + 0xNN)`` instead of
``obj->vftable->Method(...)``.

This tool reads the recovered header's slot map (either the bottom
``// slot 0xNN byte 0xMM 0xADDR kind Method`` block or the inline
``virtual ... Method(...); // 0xNN 0xADDR`` decls), then plans, for the live
Ghidra ``<Class>Vtbl`` struct:

  * grow it to cover every slot in the header (slots * 4 bytes), and
  * name each function-pointer field with the real method name.

It also confirms the class struct's ``vftable`` field points at ``<Class>Vtbl``.

Dry-run by default — prints the plan and mutates nothing. Pass ``--apply`` to
write the struct names/length to the Ghidra DB and save. The decompiler then
renders dispatches through that class as ``obj->vftable->Method(...)``. Function
pointer *signatures* (argument types) are left as a follow-up; this pass is about
slot identity (names), which is what turns raw vtable offsets into methods.
"""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from pathlib import Path

from tools.common import ghidra_env
from tools.common.repo import repo_root_from_file, resolve_repo_path

# Bottom generated block: `//   slot 0x0a  byte 0x28  0x005d5100  override  LoadTurnEventCursorTable`
_BLOCK = re.compile(
    r"//\s*slot\s+0x([0-9a-fA-F]+)\s+byte\s+0x([0-9a-fA-F]+)\s+0x([0-9a-fA-F]+)\s+(\S+)\s+(.*?)\s*$"
)
# Inline decl: `virtual <ret> Method(<params>) [const] [override]; // 0x2a 0x48b070`
_INLINE = re.compile(
    r"\bvirtual\b.*?(~?[A-Za-z_]\w*)\s*\([^;]*\)\s*(?:const\b\s*)?(?:override\b\s*)?;"
    r"\s*//\s*0x([0-9a-fA-F]+)(?:\s+0x([0-9a-fA-F]+))?"
)


@dataclass(frozen=True)
class SlotInfo:
    index: int
    name: str
    addr: int | None
    kind: str


def _clean_name(cls: str, raw: str, kind: str) -> str:
    if kind == "scalar_dtor":
        return f"~{cls}"
    token = raw.strip().split()[0] if raw.strip() else ""
    if not token or not re.fullmatch(r"~?[A-Za-z_]\w*", token):
        return ""
    return token


def parse_header_slots(repo_root: Path, cls: str) -> dict[int, SlotInfo]:
    """Slot -> SlotInfo from the recovered header (bottom block preferred)."""
    path = resolve_repo_path(repo_root, f"include/game/{cls}.h")
    if not path.exists():
        return {}  # e.g. an MFC base (CObject) with no recovered header — stops the chain
    text = path.read_text(encoding="utf-8", errors="ignore")

    block: dict[int, SlotInfo] = {}
    for line in text.splitlines():
        m = _BLOCK.search(line)
        if not m:
            continue
        idx = int(m.group(1), 16)
        addr = int(m.group(3), 16)
        kind = m.group(4)
        name = _clean_name(cls, m.group(5), kind)
        if name:
            block[idx] = SlotInfo(idx, name, addr, kind)
    if block:
        return block

    inline: dict[int, SlotInfo] = {}
    for m in _INLINE.finditer(text):
        name = m.group(1)
        idx = int(m.group(2), 16)
        addr = int(m.group(3), 16) if m.group(3) else None
        if re.fullmatch(r"~?[A-Za-z_]\w*", name):
            inline.setdefault(idx, SlotInfo(idx, name, addr, "decl"))
    return inline


_BASE_RE = re.compile(r"\bclass\s+([A-Za-z_]\w*)\s*:\s*public\s+([A-Za-z_]\w*)\b")


def _base_of(repo_root: Path, cls: str) -> str | None:
    path = resolve_repo_path(repo_root, f"include/game/{cls}.h")
    if not path.exists():
        return None
    for m in _BASE_RE.finditer(path.read_text(encoding="utf-8", errors="ignore")):
        if m.group(1) == cls:
            return m.group(2)
    return None


def merged_header_slots(
    repo_root: Path, cls: str, cache: dict[str, dict[int, SlotInfo]] | None = None
) -> dict[int, SlotInfo]:
    """Slot map for ``cls`` with inherited slots filled from the base chain.

    Single inheritance keeps slot index == byte offset / 4 across the chain, so a
    derived class inherits each base slot's method identity at the same index and
    overrides win. This fills the inherited slots that inline-format headers omit.
    """
    cache = cache if cache is not None else {}
    if cls in cache:
        return cache[cls]
    cache[cls] = {}  # guard against cycles
    merged: dict[int, SlotInfo] = {}
    base = _base_of(repo_root, cls)
    if base is not None:
        merged.update(merged_header_slots(repo_root, base, cache))
    merged.update(parse_header_slots(repo_root, cls))  # derived wins
    cache[cls] = merged
    return merged


def _find_struct(dtm, name: str):
    from ghidra.program.model.data import Structure

    it = dtm.getAllDataTypes()
    while it.hasNext():
        dt = it.next()
        if dt.getName() == name and isinstance(dt, Structure):
            return dt
    return None


def _vtbl_for_class(dtm, cls: str):
    """Return (vtbl_struct, source) — via the class struct's vftable field, else by name."""
    cls_struct = _find_struct(dtm, cls)
    if cls_struct is not None:
        for comp in cls_struct.getComponents():
            if comp.getFieldName() == "vftable":
                dt = comp.getDataType()
                base = dt.getDataType() if hasattr(dt, "getDataType") else None
                if base is not None:
                    resolved = _find_struct(dtm, base.getName())
                    if resolved is not None:
                        return resolved, f"{cls}.vftable -> {base.getName()}"
    by_name = _find_struct(dtm, f"{cls}Vtbl")
    if by_name is not None:
        return by_name, f"{cls}Vtbl (by name)"
    return None, ""


def _dedupe(slots: dict[int, SlotInfo]) -> dict[int, str]:
    """slot -> unique field name (suffix collisions with _<slot>)."""
    used: set[str] = set()
    out: dict[int, str] = {}
    for idx in sorted(slots):
        name = slots[idx].name
        final = name
        if final in used:
            final = f"{name}_{idx:02x}"
        used.add(final)
        out[idx] = final
    return out


def plan(dtm, cls: str, slots: dict[int, SlotInfo]):
    vtbl, source = _vtbl_for_class(dtm, cls)
    if vtbl is None:
        return None
    names = _dedupe(slots)
    max_slot = max(slots)
    need_len = (max_slot + 1) * 4
    cur_len = vtbl.getLength()

    cur_field: dict[int, str] = {}
    for comp in vtbl.getComponents():
        if comp.getOffset() % 4 == 0:
            cur_field[comp.getOffset() // 4] = str(comp.getFieldName())

    rows = []
    renames = grows = 0
    for idx in sorted(slots):
        off = idx * 4
        new = names[idx]
        old = cur_field.get(idx)
        if off >= cur_len:
            status = "ADD"
            grows += 1
        elif old != new:
            status = "RENAME"
            renames += 1
        else:
            status = "ok"
        rows.append((idx, off, status, old, new, slots[idx].kind))
    return vtbl, source, cur_len, need_len, rows, renames, grows, names


def apply(program, vtbl, need_len, names):
    from ghidra.program.model.data import DataTypeConflictHandler, FunctionDefinitionDataType, PointerDataType

    dtm = program.getDataTypeManager()
    # A generic function-pointer used for slots that don't already carry one.
    generic = dtm.addDataType(
        FunctionDefinitionDataType("_vslot_fn"), DataTypeConflictHandler.KEEP_HANDLER
    )
    generic_ptr = PointerDataType(generic, dtm)

    if vtbl.getLength() < need_len:
        vtbl.growStructure(need_len - vtbl.getLength())

    existing: dict[int, object] = {}
    for comp in vtbl.getComponents():
        if comp.getOffset() % 4 == 0 and comp.getDataType() is not None:
            dt = comp.getDataType()
            if hasattr(dt, "getDataType"):  # pointer-like; keep real fnptrs
                existing[comp.getOffset() // 4] = dt
    for idx, name in names.items():
        off = idx * 4
        field_dt = existing.get(idx, generic_ptr)
        vtbl.replaceAtOffset(off, field_dt, 4, name, None)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("classes", nargs="*", help="Class name(s), e.g. TViewMgr TView")
    p.add_argument(
        "--all",
        action="store_true",
        help="Process every include/game/*.h class that has a slot map + <Class>Vtbl.",
    )
    p.add_argument("--apply", action="store_true", help="Write to the Ghidra DB (default: dry-run).")
    p.add_argument("--quiet", action="store_true", help="Only print per-class summary lines.")
    return p.parse_args()


def _all_class_names(repo_root: Path) -> list[str]:
    include_dir = resolve_repo_path(repo_root, "include/game")
    return sorted(p.stem for p in include_dir.glob("*.h"))


def main() -> int:
    args = parse_args()
    repo_root = repo_root_from_file(__file__)
    class_names = list(args.classes)
    if args.all:
        class_names = _all_class_names(repo_root)
    if not class_names:
        raise SystemExit("Pass class name(s) or --all.")
    slot_cache: dict[str, dict[int, SlotInfo]] = {}
    per_class_slots = {cls: merged_header_slots(repo_root, cls, slot_cache) for cls in class_names}

    project = ghidra_env.open_project()
    consumer = program = None
    txid = None
    n_planned = n_skipped_noslots = n_skipped_novtbl = total_renames = total_grows = 0
    try:
        consumer, program = ghidra_env.open_program(project, writable=args.apply)
        dtm = program.getDataTypeManager()
        applied = []
        for cls in class_names:
            slots = per_class_slots[cls]
            if not slots:
                n_skipped_noslots += 1
                continue
            planned = plan(dtm, cls, slots)
            if planned is None:
                n_skipped_novtbl += 1
                if not args.quiet and not args.all:
                    print(f"[{cls}] no <Class>Vtbl struct; skipping")
                continue
            vtbl, source, cur_len, need_len, rows, renames, grows, names = planned
            if renames == 0 and grows == 0:
                continue
            n_planned += 1
            total_renames += renames
            total_grows += grows
            print(f"=== {cls}  ({vtbl.getName()} via {source})  "
                  f"len 0x{cur_len:x}->0x{need_len:x}  {renames} rename / {grows} new")
            if not args.quiet:
                for idx, off, status, old, new, kind in rows:
                    if status == "ok":
                        continue
                    old_s = old if old is not None else "-"
                    print(f"    slot {idx:>2} +0x{off:02x}  {status:6}  {old_s:36} -> {new}   [{kind}]")
            if args.apply:
                applied.append((vtbl, need_len, names))

        if args.apply and applied:
            txid = program.startTransaction("name vtable slots from headers")
            n_ok = n_err = 0
            for vtbl, need_len, names in applied:
                try:
                    apply(program, vtbl, need_len, names)
                    n_ok += 1
                except Exception as exc:  # noqa: BLE001 — skip one bad struct, keep the batch
                    n_err += 1
                    print(f"  ! apply failed for {vtbl.getName()}: {exc}")
            program.endTransaction(txid, True)
            txid = None
            import pyghidra

            program.save("name vtable slots from headers", pyghidra.task_monitor())
            print(f"apply: {n_ok} ok, {n_err} failed")

        print(
            f"\nclasses: {n_planned} planned, "
            f"{n_skipped_noslots} no-slot-map, {n_skipped_novtbl} no-vtbl-struct; "
            f"{total_renames} renames, {total_grows} new slots"
        )
        print("Applied." if args.apply else "(dry-run; pass --apply to write to the Ghidra DB)")
    finally:
        if txid is not None:
            program.endTransaction(txid, False)
        if program is not None:
            program.release(consumer)
        project.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
