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
  5. builds/replaces ``/MFC/vtables/<Class>Vtbl`` so Ghidra can type vtables,
     while class structures stay canonical at root paths such as ``/<Class>``.
     Canonical MFC library classes reuse the root datatypes from
     ``apply_mfc_datatypes`` instead of growing a second class hierarchy. The
     pass removes stale ``/MFC/classes/<Class>`` duplicates left by older runs.
  6. applies high-confidence non-manual prototypes: per-slot function-pointer
     signatures from the live target function or matching Mac CodeWarrior method
     evidence, CreateObject factory return types, direct vtable-store methods,
     and class-namespace ECX-this functions.
  7. attributes non-virtual __thiscall functions to a class by binary locality
     (a function bracketed by one class's method run, tie-broken by RTTI object
     size), and applies evidence-curated typing the static passes cannot infer:
     typed global pointer arrays (config/recovered_globals.csv) and interior
     class-field pointer types (config/recovered_fields.csv).

Idempotent and re-runnable; it never overwrites a USER_DEFINED name. Dry-run by
default — pass ``--apply`` to open the project writable and ``program.save()``.

Usage:
  uv run python -m tools.ghidra.apply_mfc_rtti [--apply] [--limit N] [--only Name]
"""

from __future__ import annotations

import argparse
import csv
import re
from pathlib import Path

import jpype
import pyghidra

from tools.common import class_manifest, ghidra_env
from tools.common.recovered_field_type import FieldKind, parse_data_field_type, parse_field_type
from tools.common.repo import repo_root_from_file
from tools.ghidra.apply_mfc_datatypes import MFC_MODELS

SCHEMA_MAGIC = 0xFFFF
DESC_SIZE = 0x18
IMG_LO, IMG_HI = 0x400000, 0x700000

# Placeholder/provisional name fragments we must NOT propagate base->derived
# (Hard Rule 6: never spread style/auto names). Real MFC/method names pass.
_PROVISIONAL = re.compile(
    r"(Slot[0-9A-Fa-f]{1,3}\b|_At[0-9A-Fa-f]{6}|VtableSlot|_Target\b|WrapperFor_|"
    r"NoOp|Unknown|Helper_|Maybe|Dummy)"
)
REPO_ROOT = repo_root_from_file(__file__)
MAC_SYMBOLS_PATH = REPO_ROOT / "vendor" / "macos_codewarrior" / "evidence" / "symbols.csv"
# Evidence-curated typing the auto-RTTI passes cannot infer statically (interior
# class-field pointer types and typed global pointer arrays). Static this-argument
# inference was measured to yield almost nothing (virtual dispatch dominates) and
# to be noisy for globals, so these high-confidence facts are recorded by hand from
# concrete evidence and applied deterministically. Both are "|"-delimited.
RECOVERED_GLOBALS_PATH = REPO_ROOT / "config" / "recovered_globals.csv"
RECOVERED_FIELDS_PATH = REPO_ROOT / "config" / "recovered_fields.csv"
# Placeholder "class" namespaces invented by early manual decompilation that are not
# real classes (e.g. functions grouped because their destructor resets the object's
# vptr to a shared base/interface vtable address). Listed here so they are dissolved
# back into Global deterministically. "|"-delimited (namespace|reason).
DISSOLVE_NAMESPACES_PATH = REPO_ROOT / "config" / "dissolve_namespaces.csv"
# Evidence-curated calling-convention overrides. Ghidra mislabels __fastcall/
# __cdecl on a regular basis; this table forces a corrected convention per
# address. "|"-delimited (address|calling_convention|note).
CALLING_CONVENTION_OVERRIDES_PATH = REPO_ROOT / "config" / "calling_convention_overrides.csv"
FUNCTION_CLASS_OVERRIDES_PATH = REPO_ROOT / "config" / "function_class_overrides.csv"
# Per-slot vtable method-name overrides and vtable aliases now live in the per-class
# manifests (config/classes/<Class>.yml: curated.slots / curated.aliases).
# Evidence-curated reclassification of misidentified data (e.g. Ghidra "string" labels
# that are indexed as structs/arrays). "|"-delimited; see recovered_data.csv header.
RECOVERED_DATA_PATH = REPO_ROOT / "config" / "recovered_data.csv"
MFC_LIBRARY_CLASS_NAMES = frozenset(MFC_MODELS)


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

    def clear_code_units_covering(start_addr, end_addr) -> None:
        clear_start = start_addr
        clear_end = end_addr
        data = listing.getDataContaining(start_addr)
        if data is not None:
            if data.getMinAddress().compareTo(clear_start) < 0:
                clear_start = data.getMinAddress()
            if data.getMaxAddress().compareTo(clear_end) > 0:
                clear_end = data.getMaxAddress()
        listing.clearCodeUnits(clear_start, clear_end, False)

    # ------------------------------------------------------------------ #
    # 1. CRuntimeClass datatype
    # ------------------------------------------------------------------ #
    def ensure_runtime_class_dt():
        existing = dtm.getDataType(CategoryPath.ROOT, "CRuntimeClass")
        if existing is not None:
            return existing
        s = StructureDataType(CategoryPath.ROOT, "CRuntimeClass", 0)
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

    def remove_stale_runtime_class_duplicate() -> None:
        duplicate = dtm.getDataType(CategoryPath("/MFC"), "CRuntimeClass")
        if duplicate is None:
            return
        try:
            if dtm.remove(duplicate):
                stats["mfc_class_duplicates_removed"] += 1
            else:
                changes.append("  !! stale /MFC/CRuntimeClass duplicate could not be removed")
        except Exception as exc:  # noqa: BLE001
            changes.append(f"  !! stale /MFC/CRuntimeClass duplicate removal failed: {exc}")

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

    _scan_cache = {}

    def scan_memory_for_dword(target: int) -> list[int]:
        if target in _scan_cache:
            return _scan_cache[target]
        results = []
        block_it = mem.getBlocks()
        for blk in block_it:
            if not blk.isInitialized() or blk.isExecute():
                continue
            start = int(blk.getStart().getOffset())
            end = int(blk.getEnd().getOffset())
            for addr_val in range(start, end - 3, 4):
                try:
                    val = mem.getInt(af.getAddress(addr_val)) & 0xFFFFFFFF
                    if val == target:
                        results.append(addr_val)
                except Exception:
                    pass
        _scan_cache[target] = results
        return results

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
                    # Try references first
                    for r3 in refmgr.getReferencesTo(A(fa)):
                        fa3 = int(r3.getFromAddress().getOffset())
                        if listing.getInstructionAt(A(fa3)) is None:
                            return fa3
                    # Fallback to memory scan if no references exist
                    for fa3 in scan_memory_for_dword(fa):
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
        base = name.split("::")[-1]
        return (
            base.startswith("FUN_")
            or base.startswith("thunk_FUN_")
            or base.startswith("LAB_")
            or base.startswith("SUB_")
            or bool(_PROVISIONAL.search(base))
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
        "vtbl_structs_replaced": 0,
        "class_structs": 0,
        "class_structs_replaced": 0,
        "class_vptr_verified": 0,
        "class_vptr_mismatch": 0,
        "mfc_canonical_class_reused": 0,
        "mfc_class_duplicates_removed": 0,
        "class_duplicates_removed": 0,
        "root_this_structs": 0,
        "root_this_replaced": 0,
        "root_this_preserved": 0,
        "vtable_data_typed": 0,
        "vtable_data_failed": 0,
        "slot_signatures": 0,
        "slot_mac_signatures": 0,
        "ctors_named": 0,
        "factory_typed": 0,
        "vptr_store_methods_typed": 0,
        "namespace_ecx_methods_typed": 0,
        "mac_method_signatures": 0,
        "this_typed": 0,
        "caller_class_assigned": 0,
        "locality_class_assigned": 0,
        "curated_globals_typed": 0,
        "curated_fields_typed": 0,
        "pseudo_classes_dissolved": 0,
        "pseudo_class_members_moved": 0,
        "calling_conventions_fixed": 0,
        "function_class_overridden": 0,
        "curated_data_typed": 0,
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
                clear_code_units_covering(A(desc_addr), end)
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

    if args.apply:
        remove_stale_runtime_class_duplicate()

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
            ByteDataType,
            FunctionDefinitionDataType,
            ParameterDefinitionImpl,
            ShortDataType,
            StructureDataType as _SDT,
            Undefined1DataType,
            Undefined4DataType,
            VoidDataType,
        )
        from ghidra.program.model.listing import ParameterImpl, ReturnParameterImpl
        from java.util import ArrayList

        FunctionUpdateType = jpype.JClass("ghidra.program.model.listing.Function$FunctionUpdateType")
        ParameterDefinitionArray = jpype.JArray(ParameterDefinitionImpl)

        classes_cat = CategoryPath("/MFC/classes")
        vtbl_cat = CategoryPath("/MFC/vtables")
        vfn = dtm.addDataType(
            FunctionDefinitionDataType(CategoryPath("/MFC"), "vfn"),
            DataTypeConflictHandler.DEFAULT_HANDLER,
        )
        vfn_ptr_dt = PointerDataType(vfn)
        vfn_sig_cat = CategoryPath("/MFC/vfn")

        def read_pipe_csv(path):
            if not path.exists():
                return []
            with path.open("r", encoding="utf-8", newline="") as fd:
                return list(csv.DictReader(fd, delimiter="|"))

        mac_methods: dict[tuple[str, str], list[dict[str, str]]] = {}
        # Per-slot method-name overrides and vtable aliases now live in the per-class
        # manifests (config/classes/<Class>.yml: curated.slots / curated.aliases),
        # the single source that replaced vtable_slot_method_overrides.csv and
        # class_vtable_aliases.csv.
        manifests = class_manifest.load_all_manifests(REPO_ROOT)
        slot_method_overrides = class_manifest.slot_method_overrides(manifests)
        vtable_aliases = class_manifest.vtable_aliases(manifests)
        if MAC_SYMBOLS_PATH.exists():
            with MAC_SYMBOLS_PATH.open("r", encoding="utf-8", newline="") as fd:
                for row in csv.DictReader(fd):
                    owner = (row.get("owner") or "").strip()
                    method = (row.get("method") or "").strip()
                    signature = (row.get("signature") or "").strip()
                    confidence = (row.get("confidence") or "").strip()
                    if owner and method and signature and confidence == "high":
                        mac_methods.setdefault((owner, method), []).append(row)

        def replace_or_add_datatype(cat, name: str, datatype):
            existing = dtm.getDataType(cat, name)
            if existing is not None:
                return dtm.replaceDataType(existing, datatype, True), True
            return dtm.addDataType(datatype, DataTypeConflictHandler.REPLACE_HANDLER), False

        def is_generated_root_struct(dt) -> bool:
            try:
                n = dt.getNumComponents()
            except Exception:  # noqa: BLE001
                return False
            if n == 0:
                return True
            for i in range(n):
                comp = dt.getComponent(i)
                name = comp.getFieldName() or ""
                if name and name != "vftable" and not name.startswith("field_0x"):
                    return False
            return True

        def split_args(args_text: str) -> list[str]:
            text = args_text.strip()
            if text.startswith("("):
                text = text[1:]
            suffixes = (" const", " volatile")
            for suffix in suffixes:
                if text.endswith(suffix):
                    text = text[: -len(suffix)].strip()
            if text.endswith(")"):
                text = text[:-1]
            if not text.strip() or text.strip() == "void":
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

        def root_or_mfc_datatype(name: str):
            dt = dtm.getDataType(CategoryPath.ROOT, name)
            if dt is not None:
                return dt
            return dtm.getDataType(classes_cat, name)

        def datatype_for_mac_arg(type_text: str):
            t = " ".join(type_text.replace("&", " &").replace("*", " *").split())
            if not t or t == "void":
                return None
            pointer_depth = t.count("*") + t.count("&")
            base = t.replace("*", " ").replace("&", " ")
            words = [w for w in base.split() if w not in {"const", "volatile", "register"}]
            base = " ".join(words)
            primitive = {
                "char": CharDataType.dataType,
                "signed char": CharDataType.dataType,
                "unsigned char": ByteDataType.dataType,
                "short": ShortDataType.dataType,
                "signed short": ShortDataType.dataType,
                "unsigned short": ShortDataType.dataType,
                "int": IntegerDataType.dataType,
                "signed int": IntegerDataType.dataType,
                "unsigned int": IntegerDataType.dataType,
                "long": IntegerDataType.dataType,
                "signed long": IntegerDataType.dataType,
                "unsigned long": IntegerDataType.dataType,
                "bool": ByteDataType.dataType,
            }.get(base)
            if primitive is not None:
                dt = primitive
            else:
                dt = root_or_mfc_datatype(base)
                if dt is None:
                    if pointer_depth == 0:
                        return None
                    dt = _SDT(CategoryPath.ROOT, base, 0)
                    dt = dtm.addDataType(dt, DataTypeConflictHandler.DEFAULT_HANDLER)
            if pointer_depth:
                for _ in range(pointer_depth):
                    dt = PointerDataType(dt, dtm)
                return dt
            return dt if primitive is not None else None

        def mac_signature_for(cls: str, method: str) -> tuple[list[object], str] | None:
            records = mac_methods.get((cls, method), [])
            if len(records) != 1:
                return None
            signature = records[0].get("signature", "")
            args = split_args(signature)
            dts = []
            for arg in args:
                dt = datatype_for_mac_arg(arg)
                if dt is None:
                    return None
                dts.append(dt)
            return dts, signature

        def parameter_definitions_for(fn, cls: str, method: str) -> tuple[object, bool]:
            mac = mac_signature_for(cls, method)
            explicit = []
            for param in fn.getParameters():
                try:
                    if param.isAutoParameter():
                        continue
                except Exception:  # noqa: BLE001
                    pass
                explicit.append(param)
            if mac is not None and (not explicit or len(explicit) == len(mac[0])):
                params = [
                    ParameterDefinitionImpl(f"param_{i + 1}", dt, None)
                    for i, dt in enumerate(mac[0])
                ]
                return ParameterDefinitionArray(params), True
            params = [
                ParameterDefinitionImpl(param.getName(), param.getDataType(), None)
                for param in explicit
            ]
            return ParameterDefinitionArray(params), False

        def make_function_definition(cls: str, field: str, slot: int, fn):
            name = re.sub(r"[^A-Za-z0-9_]", "_", f"{cls}_{field}_0x{slot * 4:02x}")
            fdt = FunctionDefinitionDataType(vfn_sig_cat, name)
            fdt.setReturnType(fn.getReturnType())
            args, used_mac = parameter_definitions_for(fn, cls, field)
            fdt.setArguments(args)
            fdt = dtm.addDataType(fdt, DataTypeConflictHandler.REPLACE_HANDLER)
            return fdt, used_mac

        def build_class_struct(cat, cls: str, base_name: str | None, vptr, size: int):
            s = _SDT(cat, cls, size, dtm)
            s.replaceAtOffset(0, vptr, 4, "vftable", None)
            base_dt = root_or_mfc_datatype(base_name) if base_name else None
            if base_dt is not None and not is_generated_root_struct(base_dt):
                for i in range(base_dt.getNumComponents()):
                    comp = base_dt.getComponent(i)
                    offset = comp.getOffset()
                    length = comp.getLength()
                    if offset < 4 or length <= 0 or offset + length > size:
                        continue
                    name = comp.getFieldName() or f"base_0x{offset:x}"
                    if name == "vftable":
                        continue
                    s.replaceAtOffset(offset, comp.getDataType(), length, name, comp.getComment())
            return s

        def component0_type_name(dt) -> str:
            try:
                if dt is None or dt.getNumComponents() == 0:
                    return "<missing>"
                return str(dt.getComponent(0).getDataType())
            except Exception as exc:  # noqa: BLE001
                return f"<unavailable: {exc}>"

        def refresh_thiscall_signature(fn):
            params = ArrayList()
            for param in fn.getParameters():
                try:
                    if param.isAutoParameter():
                        continue
                except Exception:  # noqa: BLE001
                    pass
                params.add(ParameterImpl(param.getName(), param.getDataType(), program))
            fn.updateFunction(
                "__thiscall",
                ReturnParameterImpl(fn.getReturnType(), program),
                params,
                FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                True,
                SourceType.USER_DEFINED,
            )

        def refresh_function_signature(fn, callconv: str, return_dt, param_dts: list[object]) -> None:
            params = ArrayList()
            for i, dt in enumerate(param_dts):
                params.add(ParameterImpl(f"param_{i + 1}", dt, program))
            fn.updateFunction(
                callconv,
                ReturnParameterImpl(return_dt, program),
                params,
                FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                True,
                SourceType.USER_DEFINED,
            )

        def apply_mac_signature_if_safe(fn, cls: str, method: str) -> bool:
            mac = mac_signature_for(cls, method)
            if mac is None:
                return False
            explicit_count = 0
            for param in fn.getParameters():
                try:
                    if param.isAutoParameter():
                        continue
                except Exception:  # noqa: BLE001
                    pass
                explicit_count += 1
            if explicit_count and explicit_count != len(mac[0]):
                return False
            refresh_function_signature(fn, "__thiscall", fn.getReturnType(), mac[0])
            return True

        def slot_override_for(cls: str, slot: int) -> dict[str, str] | None:
            override = slot_method_overrides.get((cls, slot))
            if override is not None:
                return override
            canonical = vtable_aliases.get(cls)
            if canonical:
                return slot_method_overrides.get((canonical, slot))
            return None

        def ensure_vtbl_struct(cls: str, vt: int):
            slots = vtable_extent(vt)
            name = f"{cls}Vtbl"
            if not slots:
                return None, slots, False
            s = _SDT(vtbl_cat, name, 0)
            for i, tgt in enumerate(slots):
                fld = f"slot_0x{i*4:02x}"
                field_dt = vfn_ptr_dt
                override = slot_override_for(cls, i)
                if tgt is not None:
                    fn = real_function(tgt)
                    if fn is not None:
                        if override is not None:
                            fld = override["method_name"]
                            if args.apply and is_auto_name(fn.getName()):
                                try:
                                    fn.setParentNamespace(get_or_make_class(cls))
                                    fn.setName(fld, SourceType.USER_DEFINED)
                                except Exception as exc:  # noqa: BLE001
                                    changes.append(
                                        f"  !! slot override rename {cls}#{i} 0x{tgt:08x} failed: {exc}"
                                    )
                            apply_mac_signature_if_safe(fn, cls, override["mac_method"])
                        else:
                            fld = sanitize_field(fn.getName(), i)
                        try:
                            sig_dt, used_mac = make_function_definition(cls, fld, i, fn)
                            field_dt = PointerDataType(sig_dt, dtm)
                            stats["slot_signatures"] += 1
                            if used_mac:
                                stats["slot_mac_signatures"] += 1
                        except Exception as exc:  # noqa: BLE001
                            changes.append(f"  !! slot signature {cls} 0x{i*4:02x} failed: {exc}")
                s.add(field_dt, 4, fld, None)
            vtbl_dt, replaced = replace_or_add_datatype(vtbl_cat, name, s)
            return vtbl_dt, slots, replaced

        def apply_vtable_data(cls: str, vt: int, vtbl_dt, slots: list[int | None]) -> None:
            if vtbl_dt is None or not slots:
                return
            try:
                clear_code_units_covering(A(vt), A(vt + len(slots) * 4 - 1))
                listing.createData(A(vt), vtbl_dt)
                stats["vtable_data_typed"] += 1
            except Exception as exc:  # noqa: BLE001
                stats["vtable_data_failed"] += 1
                changes.append(f"  !! vtable data {cls}@0x{vt:08x} failed: {exc}")


        def remove_stale_class_duplicate(datatype, cls: str) -> None:
            try:
                if dtm.remove(datatype):
                    stats["class_duplicates_removed"] += 1
                    if cls in MFC_LIBRARY_CLASS_NAMES:
                        stats["mfc_class_duplicates_removed"] += 1
                else:
                    changes.append(f"  !! duplicate /MFC/classes/{cls} could not be removed")
            except Exception as exc:  # noqa: BLE001
                changes.append(f"  !! duplicate /MFC/classes/{cls} removal failed: {exc}")

        def remove_stale_class_duplicates() -> None:
            stale: list[tuple[object, str]] = []
            it = dtm.getAllDataTypes()
            while it.hasNext():
                datatype = it.next()
                path = datatype.getPathName()
                if not path.startswith("/MFC/classes/"):
                    continue
                cls = datatype.getName()
                if dtm.getDataType(CategoryPath.ROOT, cls) is not None:
                    stale.append((datatype, cls))
            for datatype, cls in stale:
                remove_stale_class_duplicate(datatype, cls)

        def ensure_class_struct(cls: str, base_name: str | None, vtbl_dt, size: int):
            existing = dtm.getDataType(CategoryPath.ROOT, cls)
            preserved = existing is not None and not is_generated_root_struct(existing)
            if preserved:
                class_dt = existing
                replaced = False
                if cls in MFC_LIBRARY_CLASS_NAMES:
                    stats["mfc_canonical_class_reused"] += 1
            else:
                vptr = PointerDataType(vtbl_dt, dtm) if vtbl_dt else PointerDataType()
                s = build_class_struct(CategoryPath.ROOT, cls, base_name, vptr, size)
                class_dt, replaced = replace_or_add_datatype(CategoryPath.ROOT, cls, s)

            duplicate = dtm.getDataType(classes_cat, cls)
            if duplicate is not None:
                remove_stale_class_duplicate(duplicate, cls)

            vptr_text = component0_type_name(class_dt)
            if preserved and vtbl_dt is not None and hasattr(class_dt, "replaceAtOffset"):
                try:
                    class_dt.replaceAtOffset(
                        0, PointerDataType(vtbl_dt, dtm), 4, "vftable", None
                    )
                    vptr_text = component0_type_name(class_dt)
                except Exception as exc:  # noqa: BLE001
                    changes.append(f"  !! class struct {cls} refresh vftable type failed: {exc}")
            if preserved:
                return class_dt, replaced, preserved, vptr_text, "preserved canonical root type", True
            expected = f"{cls}Vtbl *" if vtbl_dt is not None else "pointer"
            verified = vtbl_dt is None or vptr_text == expected
            return class_dt, replaced, preserved, vptr_text, expected, verified

        def ecx_this_like(fn) -> bool:
            for ins in listing.getInstructions(fn.getBody(), True):
                text = str(ins).upper()
                if "[ECX]" in text or "(ECX)" in text:
                    return True
                if re.search(r"\bECX\s*,", text):
                    return False
            return False

        for cls, info in class_info.items():
            vt = info.get("vtable")
            if vt is None:
                continue
            base = info.get("base")
            try:
                vtbl_dt, slots, vtbl_replaced = ensure_vtbl_struct(cls, vt)
                if vtbl_dt is not None:
                    stats["vtbl_structs"] += 1
                    if vtbl_replaced:
                        stats["vtbl_structs_replaced"] += 1
            except Exception as exc:  # noqa: BLE001
                changes.append(f"  !! vtbl struct {cls} failed: {exc}")
                vtbl_dt, slots = None, []
            apply_vtable_data(cls, vt, vtbl_dt, slots)
            try:
                _class_dt, class_replaced, root_preserved, vptr_text, expected_vptr, verified = ensure_class_struct(
                    cls, base, vtbl_dt, info.get("size") or 4
                )
                stats["class_structs"] += 1
                if class_replaced:
                    stats["class_structs_replaced"] += 1
                if verified:
                    stats["class_vptr_verified"] += 1
                else:
                    stats["class_vptr_mismatch"] += 1
                    changes.append(
                        f"  !! class struct {cls} vftable type is {vptr_text}, expected {expected_vptr}"
                    )
                if args.verbose:
                    changes.append(f"  {cls} class field0: {vptr_text}")
                if root_preserved:
                    stats["root_this_preserved"] += 1
                else:
                    stats["root_this_structs"] += 1
                    if class_replaced:
                        stats["root_this_replaced"] += 1
                if args.verbose:
                    mode = "preserved" if root_preserved else "refreshed"
                    changes.append(f"  {cls} root this type {mode}; field0: {vptr_text}")
            except Exception as exc:  # noqa: BLE001
                changes.append(f"  !! class/root struct {cls} failed: {exc}")

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
                if cfn is not None:
                    try:
                        class_dt = root_or_mfc_datatype(cls)
                        if class_dt is not None:
                            refresh_function_signature(cfn, "__cdecl", PointerDataType(class_dt, dtm), [])
                            stats["factory_typed"] += 1
                    except Exception as exc:  # noqa: BLE001
                        changes.append(f"  !! factory type {cls}@0x{ctor:08x} failed: {exc}")

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
                    refresh_thiscall_signature(fn)
                    method = fn.getName().split("::")[-1]
                    if apply_mac_signature_if_safe(fn, cls, method):
                        stats["mac_method_signatures"] += 1
                    stats["this_typed"] += 1
                except Exception as exc:  # noqa: BLE001
                    changes.append(f"  !! this-type 0x{tgt:08x} {cls} failed: {exc}")

            # Direct references to a class vtable from executable code are usually
            # constructor/destructor vptr stores. Only type them when ECX is used as
            # the incoming object pointer; do not infer names from this evidence.
            for ref in refmgr.getReferencesTo(A(vt)):
                fn = fm.getFunctionContaining(ref.getFromAddress())
                if fn is None:
                    continue
                fn_addr = int(fn.getEntryPoint().getOffset())
                if fn_addr in {t for t in slots if t is not None}:
                    continue
                try:
                    pns = fn.getParentNamespace()
                    if fn.getCallingConventionName() == "__thiscall" and pns is not None and pns.getName() == cls:
                        continue
                    if not ecx_this_like(fn):
                        continue
                    if pns is None or pns.getName() == "Global":
                        fn.setParentNamespace(get_or_make_class(cls))
                    refresh_thiscall_signature(fn)
                    method = fn.getName().split("::")[-1]
                    if apply_mac_signature_if_safe(fn, cls, method):
                        stats["mac_method_signatures"] += 1
                    stats["vptr_store_methods_typed"] += 1
                except Exception as exc:  # noqa: BLE001
                    changes.append(f"  !! vptr-store this-type 0x{fn_addr:08x} {cls} failed: {exc}")

        class_names = set(class_info)
        for fn in fm.getFunctions(True):
            ns = fn.getParentNamespace()
            if ns is None:
                continue
            cls = ns.getName()
            if cls not in class_names or fn.getCallingConventionName() == "__thiscall":
                continue
            if not ecx_this_like(fn):
                continue
            try:
                refresh_thiscall_signature(fn)
                method = fn.getName().split("::")[-1]
                if apply_mac_signature_if_safe(fn, cls, method):
                    stats["mac_method_signatures"] += 1
                stats["namespace_ecx_methods_typed"] += 1
            except Exception as exc:  # noqa: BLE001
                changes.append(
                    f"  !! namespace ecx this-type 0x{int(fn.getEntryPoint().getOffset()):08x} {cls} failed: {exc}"
                )

        # ------------------------------------------------------------------ #
        # Caller-based class assignment: assign Global __thiscall functions
        # to a class when ALL callers belong to the same RTTI class.
        # ------------------------------------------------------------------ #
        # Build thunk -> real entry mapping for xref aggregation
        _thunk_to_real: dict[int, int] = {}
        for tfn in fm.getFunctions(True):
            if tfn.isThunk():
                tf = tfn.getThunkedFunction(True)
                if tf is not None:
                    _thunk_to_real[int(tfn.getEntryPoint().getOffset())] = int(tf.getEntryPoint().getOffset())
            else:
                ins0 = listing.getInstructionAt(tfn.getEntryPoint())
                if ins0 is not None and ins0.getMnemonicString().lower() == "jmp" and len(ins0.getFlows()) == 1:
                    _thunk_to_real[int(tfn.getEntryPoint().getOffset())] = int(ins0.getFlows()[0].getOffset())
        _real_to_thunks: dict[int, list[int]] = {}
        for tk, rv in _thunk_to_real.items():
            _real_to_thunks.setdefault(rv, []).append(tk)

        for fn in fm.getFunctions(True):
            ns = fn.getParentNamespace()
            if ns is None or ns.getName() != "Global":
                continue
            if fn.getCallingConventionName() != "__thiscall" or fn.isThunk():
                continue
            entry = int(fn.getEntryPoint().getOffset())
            call_targets = [entry] + _real_to_thunks.get(entry, [])
            caller_classes: set[str] = set()
            for tgt in call_targets:
                for ref in refmgr.getReferencesTo(A(tgt)):
                    if not ref.getReferenceType().isCall() and not ref.getReferenceType().isJump():
                        continue
                    cfn = fm.getFunctionContaining(ref.getFromAddress())
                    if cfn is None:
                        continue
                    cns = cfn.getParentNamespace()
                    if cns is not None and cns.getName() != "Global" and cns.getName() in class_names:
                        caller_classes.add(cns.getName())
            if len(caller_classes) == 1:
                cls = next(iter(caller_classes))
                try:
                    if args.apply:
                        fn.setParentNamespace(get_or_make_class(cls))
                        refresh_thiscall_signature(fn)
                    stats["caller_class_assigned"] += 1
                    if args.verbose or not args.apply:
                        changes.append(f"  caller-assign 0x{entry:08x} {fn.getName()} -> {cls}")
                except Exception as exc:  # noqa: BLE001
                    changes.append(f"  !! caller-assign 0x{entry:08x} {fn.getName()} -> {cls} failed: {exc}")

        # ------------------------------------------------------------------ #
        # Locality-based class assignment: MSVC emits all methods of a class's
        # translation unit contiguously, so a non-virtual (Global) __thiscall
        # function bracketed between two recovered-class functions is almost
        # always a method of one of those classes. When both neighbours are the
        # same class the assignment is unambiguous; when they differ we break the
        # tie with the recovered RTTI object size (m_nObjectSize): a function that
        # dereferences `this + 0xNNN` cannot belong to a class whose object is
        # smaller than 0xNNN. This relies only on RTTI-recovered facts (object
        # size + already-owned neighbours), never on Ghidra's provisional naming.
        # ------------------------------------------------------------------ #
        recovered_size: dict[str, int] = {
            cls: int(info.get("size") or 0)
            for cls, info in class_info.items()
            if int(info.get("size") or 0) > 0
        }

        ordered_funcs = [fn for fn in fm.getFunctions(True) if not fn.isThunk()]
        ordered_funcs.sort(key=lambda f: int(f.getEntryPoint().getOffset()))

        def recovered_class_of(fn) -> str | None:
            pns = fn.getParentNamespace()
            if pns is None:
                return None
            name = pns.getName()
            return name if name in recovered_size else None

        # entry -> owning recovered class, updated as we assign so runs propagate.
        owner_of: dict[int, str | None] = {}
        for fn in ordered_funcs:
            owner_of[int(fn.getEntryPoint().getOffset())] = recovered_class_of(fn)

        _decomp_holder: dict[str, object] = {}

        def get_decompiler():
            if "ifc" not in _decomp_holder:
                from ghidra.app.decompiler import DecompileOptions, DecompInterface

                ifc = DecompInterface()
                ifc.setOptions(DecompileOptions())
                ifc.setSimplificationStyle("decompile")
                ifc.openProgram(program)
                _decomp_holder["ifc"] = ifc
            return _decomp_holder["ifc"]

        from ghidra.util.task import TaskMonitor as _TaskMonitor

        _this_off_re_cache: dict[str, object] = {}

        def max_this_offset(fn) -> int | None:
            """Largest constant offset added to the `this` pointer in the decompiled
            body, e.g. 0x1dc for ``*(short *)((int)this + i * 2 + 0x1dc)``."""
            try:
                res = get_decompiler().decompileFunction(fn, 45, _TaskMonitor.DUMMY)
                if not res.decompileCompleted():
                    return None
                c_text = res.getDecompiledFunction().getC()
            except Exception:  # noqa: BLE001
                return None
            pname = "this"
            for param in fn.getParameters():
                try:
                    if param.isAutoParameter():
                        pname = param.getName()
                        break
                except Exception:  # noqa: BLE001
                    pass
            pat = _this_off_re_cache.get(pname)
            if pat is None:
                pat = re.compile(re.escape(pname) + r"[^;\n]*?\+\s*(0x[0-9a-fA-F]+)")
                _this_off_re_cache[pname] = pat
            max_off = 0
            for m in pat.finditer(c_text):
                val = int(m.group(1), 16)
                if val < 0x40000:
                    max_off = max(max_off, val)
            return max_off

        for idx, fn in enumerate(ordered_funcs):
            if idx == 0 or idx == len(ordered_funcs) - 1:
                continue
            ns = fn.getParentNamespace()
            if ns is None or ns.getName() != "Global":
                continue
            if fn.getCallingConventionName() != "__thiscall":
                continue
            entry = int(fn.getEntryPoint().getOffset())
            prev_cls = owner_of.get(int(ordered_funcs[idx - 1].getEntryPoint().getOffset()))
            next_cls = owner_of.get(int(ordered_funcs[idx + 1].getEntryPoint().getOffset()))
            # Require the function to be bracketed by recovered classes: strong
            # evidence it sits inside a compiled class-method region.
            if prev_cls is None or next_cls is None:
                continue
            if prev_cls == next_cls:
                cls = prev_cls
            else:
                off = max_this_offset(fn)
                if off is None:
                    continue
                fits = [c for c in (prev_cls, next_cls) if recovered_size.get(c, 0) >= off]
                if len(fits) != 1:
                    continue
                cls = fits[0]
            try:
                if args.apply:
                    fn.setParentNamespace(get_or_make_class(cls))
                    refresh_thiscall_signature(fn)
                owner_of[entry] = cls
                stats["locality_class_assigned"] += 1
                if args.verbose or not args.apply:
                    changes.append(
                        f"  locality-assign 0x{entry:08x} {fn.getName()} -> {cls} "
                        f"(prev={prev_cls} next={next_cls})"
                    )
            except Exception as exc:  # noqa: BLE001
                changes.append(f"  !! locality-assign 0x{entry:08x} -> {cls} failed: {exc}")

        # ------------------------------------------------------------------ #
        # Curated typing: apply evidence-recorded global pointer-array types and
        # interior class-field pointer types that static inference cannot recover
        # reliably (see RECOVERED_*_PATH docstring). These are authoritative, so
        # they overwrite whatever Ghidra had there.
        # ------------------------------------------------------------------ #
        from ghidra.program.model.data import (
            ArrayDataType as _ArrayDT,
            DWordDataType as _DWordDT,
            WordDataType as _WordDT,
            StructureDataType as _DataStructDT,
        )
        from ghidra.program.model.symbol import SourceType as _SymSource

        def root_class_dt(name: str):
            return dtm.getDataType(CategoryPath.ROOT, name)

        def ensure_root_class_dt_for_curated(cls: str, object_size: int | None = None):
            """Return a root struct for pointer typing. RTTI may not have built one
            (e.g. Config is not DYNCREATE) even when the class namespace exists."""
            existing = root_class_dt(cls)
            if existing is not None and existing.getLength() > 1:
                return existing
            ns = st.getNamespace(cls, None)
            if ns is None and object_size is None:
                return existing
            size = object_size or (existing.getLength() if existing is not None else 4)
            if size < 4:
                size = 4
            vptr = PointerDataType()
            s = build_class_struct(CategoryPath.ROOT, cls, None, vptr, size)
            dt, _replaced = replace_or_add_datatype(CategoryPath.ROOT, cls, s)
            if args.verbose:
                changes.append(f"  curated ensure struct {cls} (size=0x{size:x}) for pointer typing")
            return dt

        for row in read_pipe_csv(RECOVERED_GLOBALS_PATH):
            name = (row.get("name") or "").strip()
            addr_s = (row.get("address") or "").strip()
            elem = (row.get("element_type") or "").strip()
            count_s = (row.get("count") or "1").strip()
            size_s = (row.get("object_size") or "").strip()
            if not addr_s or not elem:
                continue
            try:
                addr = int(addr_s, 16)
                count = max(1, int(count_s))
                object_size = int(size_s, 16) if size_s else None
            except ValueError:
                changes.append(f"  !! curated global {name}: bad address/count/size")
                continue
            elem_dt = ensure_root_class_dt_for_curated(elem, object_size)
            if elem_dt is None:
                changes.append(f"  !! curated global {name}@{addr_s}: type {elem} not found")
                continue
            ptr_dt = PointerDataType(elem_dt, dtm)
            data_dt = ptr_dt if count == 1 else _ArrayDT(ptr_dt, count, 4)
            try:
                clear_code_units_covering(A(addr), A(addr + data_dt.getLength() - 1))
                listing.createData(A(addr), data_dt)
                rename = (row.get("rename") or "").strip()
                label = rename or name
                if label:
                    sym_addr = A(addr)
                    syms = list(st.getSymbols(sym_addr))
                    if syms:
                        if syms[0].getName() != label:
                            syms[0].setName(label, _SymSource.USER_DEFINED)
                    else:
                        st.createLabel(sym_addr, label, _SymSource.USER_DEFINED)
                stats["curated_globals_typed"] += 1
                if args.verbose:
                    changes.append(f"  curated global {name}@0x{addr:08x} = {elem} *[{count}]")
            except Exception as exc:  # noqa: BLE001
                changes.append(f"  !! curated global {name}@0x{addr:08x} failed: {exc}")

        def curated_field_datatype(ftype: str):
            """Map recovered_fields field_type to (datatype, byte_length)."""
            spec = parse_field_type(ftype)
            if spec is None:
                return None
            if spec.kind == FieldKind.POINTER_ARRAY:
                if spec.base.lower() in ("int", "dword", "uint"):
                    elem = PointerDataType(_DWordDT(), dtm)
                elif spec.base.lower() == "void":
                    elem = PointerDataType(VoidDataType.dataType, dtm)
                else:
                    inner = root_class_dt(spec.base)
                    if inner is None:
                        return None
                    elem = PointerDataType(inner, dtm)
                arr = _ArrayDT(elem, spec.count, 4)
                return arr, arr.getLength()
            if spec.kind == FieldKind.VALUE_ARRAY:
                base = spec.base.lower()
                if base == "short":
                    elem = _WordDT()
                elif base in ("int", "dword", "uint"):
                    elem = _DWordDT()
                else:
                    inner = root_class_dt(spec.base)
                    if inner is None:
                        return None
                    elem = inner
                arr = _ArrayDT(elem, spec.count, elem.getLength())
                return arr, arr.getLength()
            if spec.kind == FieldKind.POINTER:
                if spec.base.lower() in ("int", "dword", "uint"):
                    inner = _DWordDT()
                else:
                    inner = root_class_dt(spec.base)
                    if inner is None:
                        return None
                return PointerDataType(inner, dtm), 4
            if spec.base.lower() in ("int", "dword", "uint"):
                return _DWordDT(), 4
            if spec.base.lower() == "short":
                return _WordDT(), 2
            inner = root_class_dt(spec.base)
            if inner is None:
                return None
            return inner, inner.getLength()

        curated_field_rows = read_pipe_csv(RECOVERED_FIELDS_PATH)
        curated_field_rows.sort(
            key=lambda row: (
                (row.get("class") or "").strip(),
                int((row.get("offset") or "0").strip(), 16)
                if (row.get("offset") or "").strip()
                else 0,
            )
        )
        fields_by_class: dict[str, list[dict[str, str]]] = {}
        for row in curated_field_rows:
            cls = (row.get("class") or "").strip()
            if cls:
                fields_by_class.setdefault(cls, []).append(row)

        for cls, class_rows in fields_by_class.items():
            for idx, row in enumerate(class_rows):
                off_s = (row.get("offset") or "").strip()
                ftype = (row.get("field_type") or "").strip()
                if not off_s or not ftype:
                    continue
                try:
                    off = int(off_s, 16)
                except ValueError:
                    changes.append(f"  !! curated field {cls}: bad offset {off_s}")
                    continue
                fname = (row.get("field_name") or "").strip() or f"field_0x{off:x}"
                note = (row.get("note") or "").strip() or None
                struct = root_class_dt(cls)
                if struct is None or not hasattr(struct, "replaceAtOffset"):
                    changes.append(f"  !! curated field {cls}+0x{off:x}: struct not found")
                    continue
                field_dt_spec = curated_field_datatype(ftype)
                if field_dt_spec is None:
                    changes.append(f"  !! curated field {cls}+0x{off:x}: type {ftype} not found")
                    continue
                field_dt, field_len = field_dt_spec
                if idx + 1 < len(class_rows):
                    next_off_s = (class_rows[idx + 1].get("offset") or "").strip()
                    try:
                        next_off = int(next_off_s, 16)
                        if next_off > off:
                            clipped = next_off - off
                            if clipped < field_len:
                                if args.verbose:
                                    changes.append(
                                        f"  curated field {cls}+0x{off:x}: clip "
                                        f"0x{field_len:x} -> 0x{clipped:x} before +0x{next_off:x}"
                                    )
                                field_len = clipped
                    except ValueError:
                        pass
                if off + field_len > struct.getLength():
                    changes.append(
                        f"  !! curated field {cls}+0x{off:x}: beyond object size 0x{struct.getLength():x}"
                    )
                    continue
                try:
                    struct.replaceAtOffset(off, field_dt, field_len, fname, note)
                    stats["curated_fields_typed"] += 1
                    if args.verbose:
                        changes.append(f"  curated field {cls}+0x{off:x} = {ftype} ({fname})")
                except Exception as exc:  # noqa: BLE001
                    changes.append(f"  !! curated field {cls}+0x{off:x} failed: {exc}")

        # Dissolve placeholder pseudo-class namespaces (not real classes) back into
        # Global: move every member symbol out, drop any leftover root datatype of
        # the same name, then delete the now-empty namespace.
        from ghidra.util.task import TaskMonitor as _TM

        global_ns = program.getGlobalNamespace()
        for row in read_pipe_csv(DISSOLVE_NAMESPACES_PATH):
            nsname = (row.get("namespace") or "").strip()
            if not nsname:
                continue
            ns = st.getNamespace(nsname, None)
            if ns is None:
                continue
            moved = 0
            for sym in list(st.getSymbols(ns)):
                try:
                    sym.setNamespace(global_ns)
                    moved += 1
                except Exception as exc:  # noqa: BLE001
                    changes.append(f"  !! dissolve {nsname}: move {sym.getName()} failed: {exc}")
            leftover = dtm.getDataType(CategoryPath.ROOT, nsname)
            if leftover is not None:
                try:
                    dtm.remove(leftover, _TM.DUMMY)
                except Exception as exc:  # noqa: BLE001
                    changes.append(f"  !! dissolve {nsname}: remove datatype failed: {exc}")
            try:
                ns_sym = ns.getSymbol()
                if ns_sym is not None:
                    ns_sym.delete()
                stats["pseudo_classes_dissolved"] += 1
                stats["pseudo_class_members_moved"] += moved
                if args.verbose:
                    changes.append(f"  dissolved pseudo-class {nsname} ({moved} members -> Global)")
            except Exception as exc:  # noqa: BLE001
                changes.append(f"  !! dissolve {nsname}: delete namespace failed: {exc}")

        # Reclassify misidentified data labels (strings/DAT_ mistaken for tables).
        from ghidra.program.model.data import (
            ArrayDataType as _DataArrayDT,
            DWordDataType as _DWordDT,
            StructureDataType as _DataStructDT,
        )

        def parse_data_field_spec(spec: str):
            """Parse '0x28:dword[6]:summaryTags' or '0x40:dword' into (offset, datatype, length, name)."""
            spec = spec.strip()
            if not spec:
                return None
            parts = spec.split(":")
            if len(parts) < 2:
                return None
            off = int(parts[0], 16)
            if len(parts) == 2:
                type_part = parts[1]
                fname = None
            else:
                fname = parts[-1].strip() or None
                type_part = ":".join(parts[1:-1])
            type_spec = parse_data_field_type(type_part)
            if type_spec is None:
                return None
            if type_spec.kind == FieldKind.VALUE_ARRAY:
                elem = _DWordDT()
                fdt = _DataArrayDT(elem, type_spec.count, elem.getLength())
                return off, fdt, type_spec.byte_length, fname
            if type_spec.kind == FieldKind.SCALAR and type_spec.base.lower() in (
                "dword",
                "uint",
                "int",
            ):
                return off, _DWordDT(), 4, fname
            return None

        for row in read_pipe_csv(RECOVERED_DATA_PATH):
            addr_s = (row.get("address") or "").strip()
            struct_name = (row.get("struct_name") or "").strip()
            size_s = (row.get("size") or "").strip()
            fields_s = (row.get("fields") or "").strip()
            rename = (row.get("rename") or "").strip()
            if not addr_s or not struct_name or not size_s:
                continue
            try:
                addr = int(addr_s, 16)
                total_size = int(size_s, 16)
            except ValueError:
                changes.append(f"  !! curated data {struct_name}: bad address/size")
                continue
            try:
                sdt = _DataStructDT(CategoryPath.ROOT, struct_name, total_size, dtm)
                for part in (p for p in fields_s.split(";") if p.strip()):
                    parsed = parse_data_field_spec(part)
                    if parsed is None:
                        changes.append(f"  !! curated data {struct_name}: bad field {part}")
                        continue
                    off, fdt, flen, fname = parsed
                    if off + flen > total_size:
                        changes.append(
                            f"  !! curated data {struct_name}+0x{off:x}: beyond size 0x{total_size:x}"
                        )
                        continue
                    default_name = part.split(":")[1].split("[")[0]
                    sdt.replaceAtOffset(off, fdt, flen, fname or default_name, None)
                replace_or_add_datatype(CategoryPath.ROOT, struct_name, sdt)
                clear_code_units_covering(A(addr), A(addr + total_size - 1))
                listing.createData(A(addr), sdt)
                if rename:
                    syms = list(st.getSymbols(A(addr)))
                    if syms:
                        syms[0].setName(rename, SourceType.USER_DEFINED)
                stats["curated_data_typed"] += 1
                if args.verbose:
                    changes.append(f"  curated data 0x{addr:08x} = {struct_name}")
            except Exception as exc:  # noqa: BLE001
                changes.append(f"  !! curated data {struct_name}@0x{addr:08x} failed: {exc}")

        # Apply evidence-curated calling-convention overrides (Ghidra mislabels
        # __fastcall/__cdecl regularly; these are verified by `just scan-cdecl-thiscall`).
        for row in read_pipe_csv(CALLING_CONVENTION_OVERRIDES_PATH):
            addr_s = (row.get("address") or "").strip()
            target_cc = (row.get("calling_convention") or "").strip()
            if not addr_s or not target_cc:
                continue
            try:
                addr = int(addr_s, 16)
            except ValueError:
                changes.append(f"  !! cc-override {addr_s}: bad address")
                continue
            fn = fm.getFunctionAt(A(addr))
            if fn is None:
                if args.verbose:
                    changes.append(f"  !! cc-override 0x{addr:08x}: no function")
                continue
            if fn.getCallingConventionName() == target_cc:
                continue
            try:
                params = ArrayList()
                for param in fn.getParameters():
                    try:
                        if param.isAutoParameter():
                            continue
                    except Exception:  # noqa: BLE001
                        pass
                    params.add(ParameterImpl(param.getName(), param.getDataType(), program))
                fn.updateFunction(
                    target_cc,
                    ReturnParameterImpl(fn.getReturnType(), program),
                    params,
                    FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                    True,
                    SourceType.USER_DEFINED,
                )
                stats["calling_conventions_fixed"] += 1
                if args.verbose:
                    changes.append(f"  cc-override 0x{addr:08x} -> {target_cc}")
            except Exception as exc:  # noqa: BLE001
                changes.append(f"  !! cc-override 0x{addr:08x} failed: {exc}")

        for row in read_pipe_csv(FUNCTION_CLASS_OVERRIDES_PATH):
            addr_s = (row.get("address") or "").strip()
            cls = (row.get("class_name") or "").strip()
            method = (row.get("method_name") or "").strip() or None
            if not addr_s or not cls:
                continue
            try:
                addr = int(addr_s, 16)
            except ValueError:
                changes.append(f"  !! class-override {addr_s}: bad address")
                continue
            fn = fm.getFunctionAt(A(addr))
            if fn is None:
                if args.verbose:
                    changes.append(f"  !! class-override 0x{addr:08x}: no function")
                continue
            cls_dt = root_class_dt(cls)
            if cls_dt is None:
                cls_dt = ensure_root_class_dt_for_curated(cls, None)
            if cls_dt is None:
                changes.append(f"  !! class-override 0x{addr:08x}: type {cls} not found")
                continue
            try:
                this_dt = PointerDataType(cls_dt, dtm)
                if method and fn.getName() != method:
                    fn.setName(method, SourceType.USER_DEFINED)
                fn.setParentNamespace(get_or_make_class(cls))
                params = ArrayList()
                for param in fn.getParameters():
                    try:
                        if param.isAutoParameter():
                            params.add(ParameterImpl("this", this_dt, program))
                            continue
                    except Exception:  # noqa: BLE001
                        pass
                    params.add(ParameterImpl(param.getName(), param.getDataType(), program))
                fn.updateFunction(
                    "__thiscall",
                    ReturnParameterImpl(fn.getReturnType(), program),
                    params,
                    FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                    True,
                    SourceType.USER_DEFINED,
                )
                stats["function_class_overridden"] += 1
                if args.verbose:
                    label = f"{cls}::{method}" if method else cls
                    changes.append(f"  class-override 0x{addr:08x} -> {label}")
            except Exception as exc:  # noqa: BLE001
                changes.append(f"  !! class-override 0x{addr:08x} failed: {exc}")

        remove_stale_class_duplicates()

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
            f"ctors_named={s['ctors_named']} this_typed={s['this_typed']}\n"
            f"          vtbl_replaced={s['vtbl_structs_replaced']} "
            f"class_replaced={s['class_structs_replaced']} "
            f"class_vptr_verified={s['class_vptr_verified']} "
            f"class_vptr_mismatch={s['class_vptr_mismatch']} "
            f"mfc_canonical_reused={s['mfc_canonical_class_reused']} "
            f"mfc_duplicates_removed={s['mfc_class_duplicates_removed']} "
            f"class_duplicates_removed={s['class_duplicates_removed']}\n"
            f"          root_this_structs={s['root_this_structs']} "
            f"root_this_replaced={s['root_this_replaced']} "
            f"root_this_preserved={s['root_this_preserved']}\n"
            f"          vtable_data_typed={s['vtable_data_typed']} "
            f"vtable_data_failed={s['vtable_data_failed']} "
            f"slot_signatures={s['slot_signatures']} "
            f"slot_mac_signatures={s['slot_mac_signatures']}\n"
            f"          factory_typed={s['factory_typed']} "
            f"vptr_store_methods_typed={s['vptr_store_methods_typed']} "
            f"namespace_ecx_methods_typed={s['namespace_ecx_methods_typed']} "
            f"mac_method_signatures={s['mac_method_signatures']}\n"
            f"          caller_class_assigned={s['caller_class_assigned']} "
            f"locality_class_assigned={s['locality_class_assigned']}\n"
            f"          curated_globals_typed={s['curated_globals_typed']} "
            f"curated_fields_typed={s['curated_fields_typed']}\n"
            f"          pseudo_classes_dissolved={s['pseudo_classes_dissolved']} "
            f"pseudo_class_members_moved={s['pseudo_class_members_moved']}\n"
            f"          calling_conventions_fixed={s['calling_conventions_fixed']}\n"
            f"          function_class_overridden={s['function_class_overridden']}\n"
            f"          curated_data_typed={s['curated_data_typed']}"
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
