#!/usr/bin/env python3
"""Teach Ghidra the binary's MFC runtime-class (DECLARE_DYNAMIC) data.

Imperialism.exe was built with compiler RTTI off (no ``??_R`` records), so
Ghidra's PE RTTI analyzer finds nothing. But MFC's own runtime-class mechanism
is fully intact: ~800 ``CRuntimeClass`` descriptors, each a 24-byte record

    +0x00 char*          m_lpszClassName
    +0x04 int            m_nObjectSize
    +0x08 int            m_wSchema        (0xffff)
    +0x0c void*          m_pfnCreateObject
    +0x10 CRuntimeClass* m_pBaseClass     (0 at the root, CObject)
    +0x14 CRuntimeClass* m_pNextClass

This applier mines those descriptors and writes the recovered structure back
into the Ghidra database so the decompiled code we promote is better:

  1. defines/locates a ``CRuntimeClass`` struct and applies it at every
     descriptor; names the descriptor + its class-name string;
  2. creates a Ghidra class namespace per class and records the DECLARE_DYNAMIC
     inheritance edge (descriptor placed in the derived class, parent noted);
  3. locates each class's vtable (descriptor <- getter <- [ILT thunk] <- slot0),
     labels it ``<Class>::vftable``;
  4. propagates virtual names base->derived: an anonymous override (a derived
     slot whose body differs from the base's but has only an auto/thunk name) is
     renamed ``<Class>::<BaseVirtualName>`` and filed under the class namespace.

Idempotent and re-runnable; it never overwrites a USER_DEFINED name. Dry-run by
default — pass ``--apply`` to open the project writable and ``program.save()``.

Usage:
  uv run python -m tools.ghidra.apply_mfc_rtti [--apply] [--limit N] [--only Name]
"""

from __future__ import annotations

import argparse
import re

import pyghidra

from tools.common import ghidra_env

SCHEMA_MAGIC = 0xFFFF
DESC_SIZE = 0x18
IMG_LO, IMG_HI = 0x400000, 0x700000

# Placeholder/provisional name fragments we must NOT propagate base->derived
# (Hard Rule 6: never spread style/auto names). Real MFC/method names pass.
_PROVISIONAL = re.compile(
    r"(Slot[0-9A-Fa-f]{1,3}\b|_At[0-9A-Fa-f]{6}|VtableSlot|_Target\b|WrapperFor_|"
    r"NoOp|Unknown|Helper_|Maybe|Dummy)"
)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Apply MFC CRuntimeClass data into Ghidra.")
    p.add_argument("--apply", action="store_true", help="Write changes (default: dry-run).")
    p.add_argument("--limit", type=int, default=0, help="Process at most N descriptors (0 = all).")
    p.add_argument("--only", default=None, help="Restrict to a single class name (for prototyping).")
    p.add_argument("--verbose", action="store_true", help="Print every planned change.")
    return p.parse_args()


def run(program, args) -> dict:
    from ghidra.program.model.data import (
        CategoryPath,
        CharDataType,
        DataTypeConflictHandler,
        IntegerDataType,
        PointerDataType,
        StructureDataType,
    )
    from ghidra.program.model.symbol import SourceType

    af = program.getAddressFactory().getDefaultAddressSpace()
    mem = program.getMemory()
    listing = program.getListing()
    fm = program.getFunctionManager()
    st = program.getSymbolTable()
    refmgr = program.getReferenceManager()
    dtm = program.getDataTypeManager()

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
            except Exception:
                break
            if b == 0:
                break
            if b < 0x20 or b > 0x7E:
                return ""
            bs.append(b)
        return bs.decode("latin1", "replace")

    # ------------------------------------------------------------------ #
    # 1. CRuntimeClass datatype
    # ------------------------------------------------------------------ #
    def ensure_runtime_class_dt():
        cat = CategoryPath("/MFC")
        existing = dtm.getDataType(cat, "CRuntimeClass")
        if existing is not None:
            return existing
        s = StructureDataType(cat, "CRuntimeClass", 0)
        charptr = PointerDataType(CharDataType.dataType)
        s.add(charptr, 4, "m_lpszClassName", None)
        s.add(IntegerDataType.dataType, 4, "m_nObjectSize", None)
        s.add(IntegerDataType.dataType, 4, "m_wSchema", None)
        s.add(PointerDataType(), 4, "m_pfnCreateObject", None)
        # self-referential pointers
        selfptr = PointerDataType(s)
        s.add(selfptr, 4, "m_pBaseClass", None)
        s.add(selfptr, 4, "m_pNextClass", None)
        return dtm.addDataType(s, DataTypeConflictHandler.DEFAULT_HANDLER)

    # ------------------------------------------------------------------ #
    # Descriptor discovery (structural signature scan)
    # ------------------------------------------------------------------ #
    def looks_like_descriptor(addr: int) -> str | None:
        try:
            name_ptr = rd(addr)
            size = rd(addr + 4)
            schema = rd(addr + 8)
            base = rd(addr + 0x10)
        except Exception:
            return None
        if schema != SCHEMA_MAGIC:
            return None
        if not in_image(name_ptr):
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
        block_it = mem.getBlocks()
        for blk in block_it:
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

    # ------------------------------------------------------------------ #
    # vtable discovery via the reference graph
    # ------------------------------------------------------------------ #
    def real_function(addr: int):
        """Resolve to the real body, following Ghidra thunks AND raw single-flow
        JMP stubs (ILT entries Ghidra never defined as functions)."""
        target = addr
        for _ in range(8):
            a = A(target)
            fn = fm.getFunctionContaining(a)
            if fn is not None and fn.isThunk():
                tf = fn.getThunkedFunction(True)
                if tf is not None:
                    nxt = int(tf.getEntryPoint().getOffset())
                    if nxt == target:
                        return fn
                    target = nxt
                    continue
            if fn is not None:
                return fn
            ins = listing.getInstructionAt(a)
            if ins is not None and ins.getMnemonicString().lower() == "jmp" and len(ins.getFlows()) == 1:
                target = int(ins.getFlows()[0].getOffset())
                continue
            return None
        return fm.getFunctionContaining(A(target))

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

    def vtable_target(vt: int, slot: int) -> int | None:
        try:
            entry = rd(vt + 4 * slot)
        except Exception:
            return None
        if entry == 0 or not in_image(entry):
            return None
        fn = real_function(entry)
        return int(fn.getEntryPoint().getOffset()) if fn is not None else None

    # ------------------------------------------------------------------ #
    # Naming helpers
    # ------------------------------------------------------------------ #
    def is_auto_name(name: str) -> bool:
        return (
            name.startswith("FUN_")
            or name.startswith("thunk_FUN_")
            or name.startswith("LAB_")
            or name.startswith("SUB_")
        )

    def is_default_data_name(name: str) -> bool:
        """A Ghidra-generated data label safe to replace with a class-scoped name."""
        return name.startswith(("PTR_", "DAT_", "s_", "CRuntimeClass_", "u_"))

    def is_propagatable(method_name: str) -> bool:
        if not method_name or is_auto_name(method_name) or method_name.startswith("thunk_"):
            return False
        return _PROVISIONAL.search(method_name) is None

    def get_or_make_class(name: str):
        existing = st.getNamespace(name, None)
        if existing is not None:
            return existing
        return st.createClass(None, name, SourceType.USER_DEFINED)

    def is_rtti_getter_fn(fn) -> bool:
        nm = fn.getName() if fn is not None else ""
        return nm == "GetRuntimeClass" or "ClassNamePointer" in nm

    def vtable_extent(vt: int) -> list[int | None]:
        """Return resolved slot targets (None = null/abstract) up to the table's
        end: the next class's slot-0 RTTI getter, or a non-pointer slot. Trailing
        nulls are trimmed (padding, not abstract slots, are ambiguous — we keep
        the conservative shorter table)."""
        out: list[int | None] = []
        for i in range(300):
            try:
                entry = rd(vt + 4 * i)
            except Exception:
                break
            if entry == 0:
                out.append(None)
                continue
            if not in_image(entry):
                break
            fn = real_function(entry)
            if fn is None:
                break
            if i > 0 and is_rtti_getter_fn(fn):
                break  # next class's vtable begins here
            out.append(int(fn.getEntryPoint().getOffset()))
        while out and out[-1] is None:
            out.pop()
        return out

    def sanitize_field(name: str, slot: int) -> str:
        base = name.split("::")[-1]
        if is_auto_name(base) or not base or not (base[0].isalpha() or base[0] == "_"):
            return f"slot_0x{slot * 4:02x}"
        return base

    stats = {
        "descriptors": 0,
        "typed": 0,
        "named_desc": 0,
        "classes": 0,
        "vtables": 0,
        "slots_renamed": 0,
        "skipped_named": 0,
        "vtbl_structs": 0,
        "class_structs": 0,
        "ctors_named": 0,
        "this_typed": 0,
    }
    changes: list[str] = []
    # collected per class for the struct-building pass
    class_info: dict[str, dict] = {}

    rt_dt = ensure_runtime_class_dt() if args.apply else None

    descs = find_descriptors()
    # class name -> descriptor addr (first wins; dedupe)
    by_name: dict[str, int] = {}
    for addr, nm in sorted(descs.items()):
        by_name.setdefault(nm, addr)

    items = sorted(descs.items())
    if args.only:
        items = [(a, n) for a, n in items if n == args.only]
    if args.limit:
        items = items[: args.limit]

    stats["descriptors"] = len(items)

    def base_name_of(desc_addr: int) -> str | None:
        base = rd(desc_addr + 0x10)
        if base == 0 or not in_image(base):
            return None
        return read_cstr(rd(base))

    for desc_addr, cls in items:
        base_nm = base_name_of(desc_addr)
        # ---- type + name the descriptor ----
        if args.apply:
            try:
                end = A(desc_addr + DESC_SIZE - 1)
                listing.clearCodeUnits(A(desc_addr), end, False)
                listing.createData(A(desc_addr), rt_dt)
                stats["typed"] += 1
            except Exception as exc:  # noqa: BLE001
                changes.append(f"  !! type {cls}@0x{desc_addr:08x} failed: {exc}")
            try:
                ns = get_or_make_class(cls)
                stats["classes"] += 1
                prim = st.getPrimarySymbol(A(desc_addr))
                if prim is None or is_auto_name(prim.getName()) or is_default_data_name(prim.getName()):
                    st.createLabel(A(desc_addr), "classRuntimeClass", ns, SourceType.USER_DEFINED)
                    stats["named_desc"] += 1
            except Exception as exc:  # noqa: BLE001
                changes.append(f"  !! name {cls}@0x{desc_addr:08x} failed: {exc}")
        if args.verbose or not args.apply:
            changes.append(
                f"  {cls} desc@0x{desc_addr:08x} base={base_nm or '<root>'}"
            )

        # collect for the struct pass (ctor + size from the descriptor)
        info = class_info.setdefault(cls, {})
        info["desc"] = desc_addr
        info["base"] = base_nm
        info["size"] = rd(desc_addr + 4)
        ctor = rd(desc_addr + 0x0C)
        info["ctor"] = ctor if in_image(ctor) else None

        # ---- vtable + slot-name propagation ----
        vt = descriptor_to_vtable(desc_addr)
        if vt is None:
            continue
        info["vtable"] = vt
        stats["vtables"] += 1
        if args.apply:
            try:
                prim = st.getPrimarySymbol(A(vt))
                if prim is None or is_auto_name(prim.getName()):
                    st.createLabel(A(vt), "vftable", get_or_make_class(cls), SourceType.USER_DEFINED)
            except Exception as exc:  # noqa: BLE001
                changes.append(f"  !! vftable {cls}@0x{vt:08x} failed: {exc}")

        base_addr = by_name.get(base_nm) if base_nm else None
        base_vt = descriptor_to_vtable(base_addr) if base_addr else None
        if base_vt is None:
            continue
        # Walk shared slot range; rename anonymous overrides after the base virtual.
        for slot in range(256):
            der = vtable_target(vt, slot)
            base_t = vtable_target(base_vt, slot)
            if der is None and base_t is None:
                # both ran out — stop when neither has a slot
                if slot > 0:
                    break
                continue
            if der is None or base_t is None or der == base_t:
                continue  # null/inherited/out-of-range — nothing to name
            base_fn = real_function(base_t)
            der_fn = real_function(der)
            if base_fn is None or der_fn is None:
                continue
            base_method = base_fn.getName().split("::")[-1]
            if not is_propagatable(base_method):
                continue  # base slot unnamed or provisional — nothing to propagate
            if not is_auto_name(der_fn.getName()):
                stats["skipped_named"] += 1
                continue
            new_name = f"{base_method}"
            if args.apply:
                try:
                    der_fn.setParentNamespace(get_or_make_class(cls))
                    der_fn.setName(new_name, SourceType.USER_DEFINED)
                except Exception as exc:  # noqa: BLE001
                    changes.append(f"  !! rename 0x{der:08x}->{cls}::{new_name} failed: {exc}")
                    continue
            stats["slots_renamed"] += 1
            if args.verbose or not args.apply:
                changes.append(
                    f"    slot 0x{slot*4:02x}: override 0x{der:08x} -> {cls}::{new_name}"
                )

    # ------------------------------------------------------------------ #
    # Struct pass: vtable structs + class structs (vptr) + DYNCREATE ctors +
    # gated this-typing. Only the vtable-entry override methods are this-typed
    # (they are genuinely this class's virtuals; inherited slots are typed when
    # their owning base is processed), so we never rely on Ghidra's broad and
    # frequently-wrong __thiscall labelling.
    # ------------------------------------------------------------------ #
    if args.apply:
        from ghidra.program.model.data import (
            ArrayDataType,
            FunctionDefinitionDataType,
            StructureDataType as _SDT,
            Undefined1DataType,
        )

        classes_cat = CategoryPath("/MFC/classes")
        vtbl_cat = CategoryPath("/MFC/vtables")
        vfn = dtm.addDataType(
            FunctionDefinitionDataType(CategoryPath("/MFC"), "vfn"),
            DataTypeConflictHandler.DEFAULT_HANDLER,
        )
        vfn_ptr_dt = PointerDataType(vfn)

        def ensure_vtbl_struct(cls: str, vt: int):
            slots = vtable_extent(vt)
            name = f"{cls}Vtbl"
            existing = dtm.getDataType(vtbl_cat, name)
            if existing is not None:
                return existing, slots
            if not slots:
                return None, slots
            s = _SDT(vtbl_cat, name, 0)
            for i, tgt in enumerate(slots):
                fld = f"slot_0x{i*4:02x}"
                if tgt is not None:
                    fn = real_function(tgt)
                    if fn is not None:
                        fld = sanitize_field(fn.getName(), i)
                s.add(vfn_ptr_dt, 4, fld, None)
            return dtm.addDataType(s, DataTypeConflictHandler.DEFAULT_HANDLER), slots

        def ensure_class_struct(cls: str, vtbl_dt, size: int):
            vptr = PointerDataType(vtbl_dt) if vtbl_dt else PointerDataType()
            existing = dtm.getDataType(classes_cat, cls)
            if existing is not None:
                # Refresh a stale generic vftable pointer once the real Vtbl exists.
                if vtbl_dt is not None and existing.getNumComponents() > 0:
                    try:
                        existing.replaceAtOffset(0, vptr, 4, "vftable", None)
                    except Exception:  # noqa: BLE001
                        pass
                return existing
            s = _SDT(classes_cat, cls, 0)
            s.add(vptr, 4, "vftable", None)
            pad = max(0, size - 4)
            if pad:
                s.add(ArrayDataType(Undefined1DataType.dataType, pad, 1), pad, "field_0x4", None)
            return dtm.addDataType(s, DataTypeConflictHandler.DEFAULT_HANDLER)

        for cls, info in class_info.items():
            vt = info.get("vtable")
            if vt is None:
                continue
            try:
                vtbl_dt, slots = ensure_vtbl_struct(cls, vt)
                if vtbl_dt is not None:
                    stats["vtbl_structs"] += 1
            except Exception as exc:  # noqa: BLE001
                changes.append(f"  !! vtbl struct {cls} failed: {exc}")
                vtbl_dt, slots = None, []
            try:
                ensure_class_struct(cls, vtbl_dt, info.get("size") or 4)
                stats["class_structs"] += 1
            except Exception as exc:  # noqa: BLE001
                changes.append(f"  !! class struct {cls} failed: {exc}")

            ctor = info.get("ctor")
            if ctor is not None:
                cfn = real_function(ctor)
                if cfn is not None and is_auto_name(cfn.getName()):
                    try:
                        cfn.setParentNamespace(get_or_make_class(cls))
                        cfn.setName("CreateObject", SourceType.USER_DEFINED)
                        stats["ctors_named"] += 1
                    except Exception as exc:  # noqa: BLE001
                        changes.append(f"  !! ctor {cls}@0x{ctor:08x} failed: {exc}")

            base = info.get("base")
            base_vt = descriptor_to_vtable(by_name[base]) if base and base in by_name else None
            for i, tgt in enumerate(slots):
                if tgt is None:
                    continue
                base_t = vtable_target(base_vt, i) if base_vt is not None else None
                if base_t is not None and base_t == tgt:
                    continue  # inherited — owned by a base class
                fn = real_function(tgt)
                if fn is None:
                    continue
                try:
                    pns = fn.getParentNamespace()
                    if pns is None or pns.getName() == "Global":
                        fn.setParentNamespace(get_or_make_class(cls))
                    fn.setCallingConvention("__thiscall")
                    stats["this_typed"] += 1
                except Exception as exc:  # noqa: BLE001
                    changes.append(f"  !! this-type 0x{tgt:08x} {cls} failed: {exc}")

    return {"stats": stats, "changes": changes}


def main() -> int:
    args = parse_args()
    project = ghidra_env.open_project()
    consumer = None
    program = None
    txid = None
    try:
        consumer, program = ghidra_env.open_program(project, writable=bool(args.apply))
        if args.apply:
            txid = program.startTransaction("apply MFC CRuntimeClass data")
        result = run(program, args)
        if args.apply:
            program.endTransaction(txid, True)
            txid = None
            program.save("apply MFC CRuntimeClass data", pyghidra.task_monitor())

        s = result["stats"]
        mode = "APPLIED" if args.apply else "DRY RUN"
        for line in result["changes"][:4000]:
            print(line)
        print(
            f"\n[{mode}] descriptors={s['descriptors']} typed={s['typed']} "
            f"named_desc={s['named_desc']} classes={s['classes']} vtables={s['vtables']} "
            f"overrides_renamed={s['slots_renamed']} skipped_already_named={s['skipped_named']}\n"
            f"          vtbl_structs={s['vtbl_structs']} class_structs={s['class_structs']} "
            f"ctors_named={s['ctors_named']} this_typed={s['this_typed']}"
        )
        if not args.apply:
            print("Re-run with --apply to write these changes to the Ghidra DB.")
        return 0
    finally:
        if txid is not None:
            program.endTransaction(txid, False)
        if program is not None:
            program.release(consumer)
        project.close()


if __name__ == "__main__":
    raise SystemExit(main())
