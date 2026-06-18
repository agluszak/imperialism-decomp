#!/usr/bin/env python3
"""Propagate virtual method identity down live Ghidra RTTI inheritance chains.

This is intentionally Ghidra-native: config/classes/*.yml is not an input.  The
tool reads MFC CRuntimeClass descriptors, their m_pBaseClass chains, and vtable
memory from the live vendored Ghidra project, then renames/signatures derived
override bodies so slot N keeps the same virtual method identity as base slot N.

Dry-run by default.  Pass --apply to write names/signatures to the Ghidra DB.
"""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from typing import Any

from tools.common import ghidra_env

SCHEMA_MAGIC = 0xFFFF
DESC_SIZE = 0x18
IMG_LO, IMG_HI = 0x400000, 0x700000
MAX_SLOTS = 512

AUTO_NAME = re.compile(r"^(FUN_|SUB_|LAB_|thunk_FUN_)")
SIMPLE_METHOD_NAME = re.compile(r"^[A-Za-z_~][A-Za-z0-9_~]*$")


@dataclass(frozen=True)
class Slot:
    index: int
    target: int | None
    current_name: str = ""
    prototype: str = ""


@dataclass(frozen=True)
class ClassRecord:
    name: str
    base: str | None
    vtable: int
    slots: tuple[Slot, ...]


@dataclass(frozen=True)
class MethodIdentity:
    method_name: str
    signature_source: int | None
    prototype: str = ""


@dataclass(frozen=True)
class SurfaceEntry:
    target: int | None
    identity: MethodIdentity | None


@dataclass(frozen=True)
class RenamePlan:
    cls: str
    slot: int
    target: int
    old_qualified: str
    new_qualified: str
    method_name: str
    signature_source: int | None
    prototype: str
    reason: str


@dataclass(frozen=True)
class Conflict:
    target: int
    desired: tuple[str, ...]


def unqualified(name: str) -> str:
    return name.rsplit("::", 1)[-1] if name else ""


def qualified(cls: str, method: str) -> str:
    return f"{cls}::{method}"


def split_args(args_text: str) -> list[str]:
    text = args_text.strip()
    if not text or text == "void":
        return []
    out: list[str] = []
    cur: list[str] = []
    depth = 0
    for ch in text:
        if ch in "(<[":
            depth += 1
        elif ch in ")>]":
            depth = max(0, depth - 1)
        if ch == "," and depth == 0:
            out.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if cur:
        out.append("".join(cur).strip())
    return out


def parse_method_prototype(prototype: str) -> tuple[str, list[tuple[str, str]]] | None:
    """Best-effort parse of simple C++ method prototypes used by root seeds."""
    text = prototype.strip()
    if not text or "(" not in text:
        return None
    head, _, rest = text.partition("(")
    args_text, _, _tail = rest.rpartition(")")
    tokens = head.replace("__thiscall", " ").replace("__cdecl", " ").split()
    if len(tokens) < 2:
        return None
    ret = " ".join(tokens[:-1]).strip()
    args: list[tuple[str, str]] = []
    for index, arg in enumerate(split_args(args_text)):
        pieces = arg.strip().split()
        if not pieces:
            continue
        name = pieces[-1]
        type_text = " ".join(pieces[:-1]).strip()
        if not type_text or "*" in name or "&" in name:
            type_text = arg.strip()
            name = f"param_{index + 1}"
        args.append((name, type_text))
    return ret, args


def usable_method_name(name: str) -> str:
    base = unqualified(name).strip()
    if not base or AUTO_NAME.search(base):
        return ""
    if not SIMPLE_METHOD_NAME.fullmatch(base):
        return ""
    return base


ROOT_SURFACES: dict[str, dict[int, SurfaceEntry]] = {
    "CObject": {
        0: SurfaceEntry(0x00606FBA, MethodIdentity("GetRuntimeClass", 0x00606FBA, "CRuntimeClass* GetRuntimeClass() const")),
        1: SurfaceEntry(0x00415F00, MethodIdentity("`scalar deleting destructor'", 0x00415F00)),
        2: SurfaceEntry(0x00412BD0, MethodIdentity("Serialize", 0x00412BD0, "void Serialize(CArchive& archive)")),
        3: SurfaceEntry(0x00412BF0, MethodIdentity("AssertValid", 0x00412BF0, "void AssertValid() const")),
        4: SurfaceEntry(0x00412C10, MethodIdentity("Dump", 0x00412C10, "void Dump(CDumpContext& dc) const")),
    },
    "TObject": {
        0: SurfaceEntry(0x00485E20, MethodIdentity("GetRuntimeClass", 0x00485E20, "CRuntimeClass* GetRuntimeClass() const")),
        1: SurfaceEntry(0x00484990, MethodIdentity("`scalar deleting destructor'", 0x00484990)),
        2: SurfaceEntry(0x00485E90, MethodIdentity("Serialize", 0x00485E90, "void Serialize(CArchive& archive)")),
        3: SurfaceEntry(0x00412BF0, MethodIdentity("AssertValid", 0x00412BF0, "void AssertValid() const")),
        4: SurfaceEntry(0x00412C10, MethodIdentity("Dump", 0x00412C10, "void Dump(CDumpContext& dc) const")),
        5: SurfaceEntry(0x00485F70, MethodIdentity("WriteTo", 0x00485F70, "void WriteTo(TStream* stream)")),
        6: SurfaceEntry(0x00485F90, MethodIdentity("ReadFrom", 0x00485F90, "void ReadFrom(TStream* stream)")),
        7: SurfaceEntry(0x004798B0, MethodIdentity("Free", 0x004798B0, "void Free()")),
        8: SurfaceEntry(0x004798D0, MethodIdentity("ShallowClone", 0x004798D0, "TObject* ShallowClone()")),
        9: SurfaceEntry(0x00415CE0, MethodIdentity("ShallowFree", 0x00415CE0, "TObject* ShallowFree()")),
    },
}


def build_propagation_plan(
    records: dict[str, ClassRecord],
    *,
    apply_filter: set[str] | None = None,
) -> tuple[list[RenamePlan], dict[str, dict[int, SurfaceEntry]], list[str]]:
    """Return rename plans by propagating slot identities parent-first.

    `records` is deliberately simple so this logic is unit-testable without
    Ghidra.  A derived slot with an existing base slot always inherits that slot's
    method identity.  If the target differs, the derived target is an override and
    gets a rename/signature plan.  Slots beyond the base surface introduce new
    identities from their current live Ghidra method name.
    """
    surfaces: dict[str, dict[int, SurfaceEntry]] = {
        cls: dict(surface) for cls, surface in ROOT_SURFACES.items()
    }
    plans: list[RenamePlan] = []
    warnings: list[str] = []
    visiting: set[str] = set()

    def ensure(cls: str) -> dict[int, SurfaceEntry]:
        if cls in surfaces and cls not in records:
            return surfaces[cls]
        if cls in surfaces and cls in records:
            return surfaces[cls]
        rec = records.get(cls)
        if rec is None:
            warnings.append(f"{cls}: no live class record")
            surfaces[cls] = {}
            return surfaces[cls]
        if cls in visiting:
            warnings.append(f"{cls}: inheritance cycle detected")
            surfaces[cls] = {}
            return surfaces[cls]

        visiting.add(cls)
        parent = ensure(rec.base) if rec.base else {}
        out: dict[int, SurfaceEntry] = {}
        for slot in rec.slots:
            parent_entry = parent.get(slot.index)
            if parent_entry is not None:
                identity = parent_entry.identity
                out[slot.index] = SurfaceEntry(slot.target, identity)
                if (
                    identity is not None
                    and slot.target is not None
                    and parent_entry.target is not None
                    and slot.target != parent_entry.target
                    and "`" not in identity.method_name
                    and (apply_filter is None or rec.name in apply_filter)
                ):
                    new_q = qualified(rec.name, identity.method_name)
                    old_q = slot.current_name
                    plans.append(
                        RenamePlan(
                            cls=rec.name,
                            slot=slot.index,
                            target=slot.target,
                            old_qualified=old_q,
                            new_qualified=new_q,
                            method_name=identity.method_name,
                            signature_source=identity.signature_source,
                            prototype=identity.prototype,
                            reason="override",
                        )
                    )
                continue

            method = usable_method_name(slot.current_name)
            identity = (
                MethodIdentity(method, slot.target, slot.prototype)
                if method and slot.target is not None
                else None
            )
            out[slot.index] = SurfaceEntry(slot.target, identity)
        visiting.remove(cls)
        surfaces[cls] = out
        return out

    for cls in sorted(records):
        ensure(cls)

    root_parent: dict[str, dict[int, SurfaceEntry]] = {
        "TObject": ROOT_SURFACES["CObject"],
    }
    for cls, surface in ROOT_SURFACES.items():
        parent = root_parent.get(cls, {})
        for index, entry in sorted(surface.items()):
            identity = entry.identity
            if identity is None or entry.target is None:
                continue
            if "`" in identity.method_name:
                continue
            parent_entry = parent.get(index)
            if parent_entry is not None and parent_entry.target == entry.target:
                continue
            plans.append(
                RenamePlan(
                    cls=cls,
                    slot=index,
                    target=entry.target,
                    old_qualified="",
                    new_qualified=qualified(cls, identity.method_name),
                    method_name=identity.method_name,
                    signature_source=identity.signature_source,
                    prototype=identity.prototype,
                    reason="root",
                )
            )

    return plans, surfaces, warnings


def find_conflicts(plans: list[RenamePlan]) -> list[Conflict]:
    desired_by_target: dict[int, set[str]] = {}
    for plan in plans:
        desired_by_target.setdefault(plan.target, set()).add(plan.new_qualified)
    conflicts = [
        Conflict(target, tuple(sorted(desired)))
        for target, desired in sorted(desired_by_target.items())
        if len(desired) > 1
    ]
    return conflicts


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Propagate virtual method names down Ghidra RTTI class chains.")
    p.add_argument("--apply", action="store_true", help="Write changes to Ghidra (default: dry-run).")
    p.add_argument("--only", action="append", default=[], help="Restrict application/reporting to a class name; repeatable.")
    p.add_argument("--limit", type=int, default=0, help="Report/apply at most N rename plans after filtering.")
    p.add_argument("--verbose", action="store_true", help="Print skipped warnings and conflicts.")
    return p.parse_args()


def run(program: Any, args: argparse.Namespace) -> dict[str, Any]:
    af = program.getAddressFactory().getDefaultAddressSpace()
    fm = program.getFunctionManager()
    listing = program.getListing()
    mem = program.getMemory()
    refmgr = program.getReferenceManager()
    st = program.getSymbolTable()

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

    def real_function(addr: int):
        target = addr
        for _ in range(8):
            fn = fm.getFunctionContaining(A(target))
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
            ins = listing.getInstructionAt(A(target))
            if ins is not None and ins.getMnemonicString().lower() == "jmp" and len(ins.getFlows()) == 1:
                target = int(ins.getFlows()[0].getOffset())
                continue
            return None
        return fm.getFunctionContaining(A(target))

    scan_cache: dict[int, list[int]] = {}

    def scan_memory_for_dword(target: int) -> list[int]:
        if target in scan_cache:
            return scan_cache[target]
        results: list[int] = []
        for blk in mem.getBlocks():
            if not blk.isInitialized() or blk.isExecute():
                continue
            start = int(blk.getStart().getOffset())
            end = int(blk.getEnd().getOffset())
            for addr_val in range(start, end - 3, 4):
                try:
                    if (mem.getInt(A(addr_val)) & 0xFFFFFFFF) == target:
                        results.append(addr_val)
                except Exception:  # noqa: BLE001
                    pass
        scan_cache[target] = results
        return results

    def descriptor_to_vtable(desc: int) -> int | None:
        for ref in refmgr.getReferencesTo(A(desc)):
            fn = fm.getFunctionContaining(ref.getFromAddress())
            if fn is None:
                continue
            getter = int(fn.getEntryPoint().getOffset())
            for ref2 in refmgr.getReferencesTo(A(getter)):
                fa = int(ref2.getFromAddress().getOffset())
                ins = listing.getInstructionAt(A(fa))
                if ins is not None and ins.getMnemonicString().lower() == "jmp":
                    for ref3 in refmgr.getReferencesTo(A(fa)):
                        fa3 = int(ref3.getFromAddress().getOffset())
                        if listing.getInstructionAt(A(fa3)) is None:
                            return fa3
                    for fa3 in scan_memory_for_dword(fa):
                        if listing.getInstructionAt(A(fa3)) is None:
                            return fa3
                elif ins is None:
                    return fa
        return None

    def base_name_of(desc: int) -> str | None:
        base = rd(desc + 0x10)
        if base == 0 or not in_image(base):
            return None
        return read_cstr(rd(base))

    def function_name_and_proto(target: int) -> tuple[str, str]:
        fn = real_function(target)
        if fn is None:
            return "", ""
        return fn.getName(True), fn.getSignature(True).getPrototypeString()

    def is_rtti_getter_target(target: int | None) -> bool:
        if target is None:
            return False
        fn = real_function(target)
        if fn is None:
            return False
        name = fn.getName()
        return name == "GetRuntimeClass" or "ClassNamePointer" in name

    def extract_slots(vt: int, all_vtables: set[int]) -> tuple[Slot, ...]:
        slots: list[Slot] = []
        for index in range(MAX_SLOTS):
            if index > 0 and (vt + index * 4) in all_vtables:
                break
            try:
                entry = rd(vt + index * 4)
            except Exception:  # noqa: BLE001
                break
            if entry == 0:
                slots.append(Slot(index, None))
                continue
            if not in_image(entry):
                break
            fn = real_function(entry)
            if fn is None:
                break
            target = int(fn.getEntryPoint().getOffset())
            if index > 0 and is_rtti_getter_target(target):
                break
            name, proto = function_name_and_proto(target)
            slots.append(Slot(index, target, name, proto))
        while slots and slots[-1].target is None:
            slots.pop()
        return tuple(slots)

    descs = find_descriptors()
    by_name: dict[str, int] = {}
    for addr, name in sorted(descs.items()):
        by_name.setdefault(name, addr)

    vtables: dict[str, int] = {}
    for name, desc in sorted(by_name.items()):
        vt = descriptor_to_vtable(desc)
        if vt is not None:
            vtables[name] = vt
    all_vtables = set(vtables.values())

    records: dict[str, ClassRecord] = {}
    for name, vt in sorted(vtables.items()):
        desc = by_name[name]
        records[name] = ClassRecord(
            name=name,
            base=base_name_of(desc),
            vtable=vt,
            slots=extract_slots(vt, all_vtables),
        )

    only = set(args.only) if args.only else None
    plans, _surfaces, warnings = build_propagation_plan(records, apply_filter=only)
    conflicts = find_conflicts(plans)
    conflicted_targets = {conflict.target for conflict in conflicts}
    plans = [plan for plan in plans if plan.target not in conflicted_targets]
    if args.limit:
        plans = plans[: args.limit]

    applied = 0
    would_change = 0
    failed: list[str] = []
    changed: list[str] = []

    import jpype

    FunctionUpdateType = jpype.JClass("ghidra.program.model.listing.Function$FunctionUpdateType")
    from ghidra.program.model.data import (
        CategoryPath,
        CharDataType,
        IntegerDataType,
        PointerDataType,
        ShortDataType,
        Undefined4DataType,
        VoidDataType,
    )
    from ghidra.program.model.listing import ParameterImpl, ReturnParameterImpl
    from ghidra.program.model.symbol import SourceType
    from java.util import ArrayList
    dtm = program.getDataTypeManager()

    def get_or_make_class(name: str):
        existing = st.getNamespace(name, None)
        if existing is not None:
            return existing
        return st.createClass(None, name, SourceType.USER_DEFINED)

    def clone_signature(dst_fn, src_fn) -> None:
        params = ArrayList()
        for param in src_fn.getParameters():
            try:
                if param.isAutoParameter():
                    continue
            except Exception:  # noqa: BLE001
                pass
            params.add(ParameterImpl(param.getName(), param.getDataType(), program))
        callconv = src_fn.getCallingConventionName() or "__thiscall"
        dst_fn.updateFunction(
            callconv,
            ReturnParameterImpl(src_fn.getReturnType(), program),
            params,
            FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
            True,
            SourceType.USER_DEFINED,
        )

    def datatype_for_text(type_text: str):
        text = " ".join(type_text.replace("*", " *").replace("&", " &").split())
        if not text:
            return Undefined4DataType.dataType
        if text == "void":
            return VoidDataType.dataType
        pointer_depth = text.count("*") + text.count("&")
        base = text.replace("*", " ").replace("&", " ")
        words = [word for word in base.split() if word not in {"const", "volatile", "register"}]
        base = " ".join(words)
        primitive = {
            "char": CharDataType.dataType,
            "short": ShortDataType.dataType,
            "int": IntegerDataType.dataType,
            "unsigned int": IntegerDataType.dataType,
            "long": IntegerDataType.dataType,
            "unsigned long": IntegerDataType.dataType,
            "undefined4": Undefined4DataType.dataType,
        }.get(base)
        dt = primitive
        if dt is None:
            dt = dtm.getDataType(CategoryPath.ROOT, base)
        if dt is None:
            dt = dtm.getDataType(CategoryPath("/MFC/classes"), base)
        if dt is None:
            dt = dtm.getDataType(CategoryPath("/MFC"), base)
        if dt is None:
            return Undefined4DataType.dataType
        for _ in range(pointer_depth):
            dt = PointerDataType(dt, dtm)
        return dt

    def apply_prototype_signature(dst_fn, prototype: str) -> bool:
        parsed = parse_method_prototype(prototype)
        if parsed is None:
            return False
        ret_text, arg_specs = parsed
        params = ArrayList()
        for name, type_text in arg_specs:
            params.add(ParameterImpl(name, datatype_for_text(type_text), program))
        dst_fn.updateFunction(
            "__thiscall",
            ReturnParameterImpl(datatype_for_text(ret_text), program),
            params,
            FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
            True,
            SourceType.USER_DEFINED,
        )
        return True

    for plan in plans:
        fn = real_function(plan.target)
        if fn is None:
            failed.append(f"0x{plan.target:08x}: no function for {plan.new_qualified}")
            continue
        sig_fn = real_function(plan.signature_source) if plan.signature_source is not None else None
        if args.apply:
            try:
                fn.setParentNamespace(get_or_make_class(plan.cls))
                fn.setName(plan.method_name, SourceType.USER_DEFINED)
                if plan.prototype and apply_prototype_signature(fn, plan.prototype):
                    pass
                elif sig_fn is not None:
                    clone_signature(fn, sig_fn)
            except Exception as exc:  # noqa: BLE001
                failed.append(f"0x{plan.target:08x}: {plan.new_qualified} failed: {exc}")
                continue
            applied += 1
        else:
            would_change += 1
        changed.append(
            f"slot 0x{plan.slot * 4:02x} 0x{plan.target:08x}: "
            f"{plan.old_qualified or '<unnamed>'} -> {plan.new_qualified}"
        )

    return {
        "descriptors": len(descs),
        "classes_with_vtables": len(records),
        "planned": len(plans),
        "would_change": would_change,
        "applied": applied,
        "changed": changed,
        "failed": failed,
        "conflicts": conflicts,
        "warnings": warnings,
        "mode": "APPLIED" if args.apply else "DRY RUN",
    }


def main() -> int:
    import pyghidra

    args = parse_args()
    project = ghidra_env.open_project()
    consumer = None
    program = None
    txid = None
    try:
        consumer, program = ghidra_env.open_program(project, writable=bool(args.apply))
        if args.apply:
            txid = program.startTransaction("propagate virtual method names")
        result = run(program, args)
        if args.apply:
            program.endTransaction(txid, True)
            txid = None
            program.save("propagate virtual method names", pyghidra.task_monitor())

        print(
            f"[{result['mode']}] descriptors={result['descriptors']} "
            f"classes_with_vtables={result['classes_with_vtables']} "
            f"planned={result['planned']} would_change={result['would_change']} "
            f"applied={result['applied']}"
        )
        for line in result["changed"][:5000]:
            print(f"  {line}")
        if result["failed"]:
            print("\nFailures:")
            for line in result["failed"][:200]:
                print(f"  {line}")
        if args.verbose and result["conflicts"]:
            print("\nConflicts:")
            for conflict in result["conflicts"][:200]:
                desired = ", ".join(conflict.desired)
                print(f"  0x{conflict.target:08x}: {desired}")
        if args.verbose and result["warnings"]:
            print("\nWarnings:")
            for warning in result["warnings"][:200]:
                print(f"  {warning}")
        if not args.apply:
            print("Re-run with --apply to write names/signatures to Ghidra.")
        return 1 if result["failed"] else 0
    finally:
        if txid is not None:
            program.endTransaction(txid, False)
        if program is not None:
            program.release(consumer)
        project.close()


if __name__ == "__main__":
    raise SystemExit(main())
