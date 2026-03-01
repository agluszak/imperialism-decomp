#!/usr/bin/env python3
"""
Reconstruct class inheritance hierarchy from constructor/destructor vtable sequences.

When a constructor or destructor writes multiple vtable pointers to offset 0 of
``this``/``param_1``, the sequence reveals the class hierarchy.  In a constructor
the writes go base→derived (last write = own class); in a destructor they go
derived→base (first write = own class).

Algorithm:
  1. Build vtable_addr → class_name and vtable_sym → class_name maps
  2. Collect all class-namespaced functions grouped by class
  3. Decompile each function and extract ordered vtable writes at offset 0
     - Pcode path (default): uses Ghidra's Pcode SSA to find STORE ops
       whose destination traces to param0 and whose value resolves to a vtable
     - Regex path (--no-use-pcode): regex on decompiled C text
  4. Detect constructor vs destructor order and emit parent→child edges
  5. Optionally detect cross-class constructor call chains
  6. Filter: both endpoints must be known class names
  7. Aggregate, rank, and print ASCII tree

Output CSV columns (raw edges):
  base_class, derived_class, evidence_kind, confidence, function_name,
  function_addr, evidence_detail

Usage:
  uv run impk reconstruct_class_hierarchy --out-csv tmp_decomp/class_hierarchy_edges.csv
  uv run impk reconstruct_class_hierarchy --no-use-pcode --out-csv tmp_decomp/class_hierarchy_edges_regex.csv
"""

from __future__ import annotations

import argparse
import csv
import re
from collections import Counter, defaultdict
from pathlib import Path

from imperialism_re.commands.infer_class_from_indirect_refs import _VTBL_PATTERN
from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.ghidra_session import open_program


# Vtable write patterns — two forms depending on whether the decompiler typed `this`.
#
# Form A (untyped / raw pointer):
#   *(type *)param_1 = 0xNNNNNNNN
#   *(type *)this   = &g_vtblTFoo
#   *in_ECX = &g_vtblTFoo
#
# Form B (typed struct access):
#   pThis->pVtable = &g_vtblTFoo
#   this->pVtable = (void *)&g_vtblTFoo
_VTBL_WRITE_RAW = re.compile(
    r"\*\s*(?:\([^)]*\)\s*)?(?:param_1|this|in_ECX)\s*=\s*"
    r"(?:(0x[0-9a-fA-F]+)"  # group 1: hex constant
    r"|(?:&|\([^)]*\))?(?:&)?(g_vtbl\w+))"  # group 2: symbol name
)

_VTBL_WRITE_TYPED = re.compile(
    r"(?:pThis|this|param_1)\s*->\s*(?:pVtable|vtable)\s*=\s*"
    r"(?:(0x[0-9a-fA-F]+)"  # group 1: hex constant
    r"|(?:&|\([^)]*\))?(?:&)?(g_vtbl\w+))"  # group 2: symbol name
)

# Cross-class constructor call: ConstructYBaseState(this/param_1, ...)
_CTOR_CALL = re.compile(
    r"(Construct\w+BaseState|Create\w+Instance)\s*\(\s*(?:this|param_1|pThis)\s*(?:,|\))"
)


def decompile_text(ifc, func) -> str:
    res = ifc.decompileFunction(func, 20, None)
    if not res or not res.decompileCompleted():
        return ""
    dc = res.getDecompiledFunction()
    if dc is None:
        return ""
    return str(dc.getC())


def _resolve_vtbl_class(
    m: re.Match,
    vtable_addr_to_class: dict[int, str],
    class_names: set[str],
) -> str | None:
    """Resolve a _VTBL_WRITE match to a class name, or None."""
    hex_val = m.group(1)
    sym_name = m.group(2)
    if hex_val:
        try:
            addr = int(hex_val, 16)
        except ValueError:
            return None
        return vtable_addr_to_class.get(addr)
    if sym_name:
        vm = _VTBL_PATTERN.match(sym_name)
        if vm:
            cls = vm.group(1)
            if cls in class_names:
                return cls
    return None


# ---------------------------------------------------------------------------
# Pcode SSA helpers
# ---------------------------------------------------------------------------

# Opcodes that transparently pass through a value (for tracing to param0)
_PASSTHROUGH_OPCODES: set[int] | None = None


def _get_passthrough_opcodes(PcodeOp) -> set[int]:
    """Lazily build the set of pass-through opcodes (needs PcodeOp class)."""
    global _PASSTHROUGH_OPCODES
    if _PASSTHROUGH_OPCODES is None:
        _PASSTHROUGH_OPCODES = {
            PcodeOp.COPY,
            PcodeOp.CAST,
            PcodeOp.MULTIEQUAL,
            PcodeOp.INDIRECT,
        }
    return _PASSTHROUGH_OPCODES


def _trace_to_param0(vn, param0_varnodes: set, PcodeOp, max_depth: int = 8) -> bool:
    """Walk backward through SSA def-chain to check if *vn* originates from param0.

    Follows COPY, CAST, INT_ADD(x,0), MULTIEQUAL (phi), INDIRECT ops.
    Uses explicit stack + visited set (not recursion).
    """
    passthrough = _get_passthrough_opcodes(PcodeOp)
    stack = [(vn, 0)]
    visited: set[int] = set()
    while stack:
        cur, depth = stack.pop()
        if cur is None or depth > max_depth:
            continue
        uid = id(cur)
        if uid in visited:
            continue
        visited.add(uid)

        # Direct match to a param0 varnode
        if cur in param0_varnodes:
            return True

        defn = cur.getDef()
        if defn is None:
            continue
        op = defn.getOpcode()

        if op in passthrough:
            # All inputs are candidates (MULTIEQUAL has multiple)
            for i in range(defn.getNumInputs()):
                stack.append((defn.getInput(i), depth + 1))
        elif op == PcodeOp.INT_ADD:
            # INT_ADD(x, 0) — offset-zero addition is identity for our purpose
            in0 = defn.getInput(0)
            in1 = defn.getInput(1)
            if in1 is not None and in1.isConstant() and in1.getOffset() == 0:
                stack.append((in0, depth + 1))
            elif in0 is not None and in0.isConstant() and in0.getOffset() == 0:
                stack.append((in1, depth + 1))
        elif op == PcodeOp.PTRSUB:
            # PTRSUB(base, 0) — struct access at offset 0
            in1 = defn.getInput(1)
            if in1 is not None and in1.isConstant() and in1.getOffset() == 0:
                stack.append((defn.getInput(0), depth + 1))

    return False


def _resolve_stored_vtable(
    value_vn,
    vtable_addr_to_class: dict[int, str],
    class_names: set[str],
    program,
    PcodeOp,
    max_depth: int = 6,
) -> str | None:
    """Resolve a value Varnode to a vtable class name.

    Walks backward through COPY/CAST/PTRSUB/INT_ADD chains looking for:
    - Constant/address Varnodes → look up in vtable_addr_to_class
    - HighVariable.getSymbol() matching g_vtbl* → resolve via _VTBL_PATTERN
    """
    stack = [(value_vn, 0)]
    visited: set[int] = set()
    while stack:
        cur, depth = stack.pop()
        if cur is None or depth > max_depth:
            continue
        uid = id(cur)
        if uid in visited:
            continue
        visited.add(uid)

        # Check constant/address directly
        if cur.isConstant() or cur.isAddress():
            addr_val = cur.getOffset() & 0xFFFFFFFF
            cls = vtable_addr_to_class.get(addr_val)
            if cls:
                return cls

        # Check HighVariable symbol name
        try:
            high = cur.getHigh()
            if high is not None:
                sym = high.getSymbol()
                if sym is not None:
                    sym_name = sym.getName()
                    if sym_name and sym_name.startswith("g_vtbl"):
                        vm = _VTBL_PATTERN.match(sym_name)
                        if vm:
                            cls = vm.group(1)
                            if cls in class_names:
                                return cls
        except Exception:
            pass

        defn = cur.getDef()
        if defn is None:
            continue
        op = defn.getOpcode()

        if op in (PcodeOp.COPY, PcodeOp.CAST):
            stack.append((defn.getInput(0), depth + 1))
        elif op == PcodeOp.PTRSUB:
            # PTRSUB can encode &struct.field — check both inputs
            stack.append((defn.getInput(0), depth + 1))
            stack.append((defn.getInput(1), depth + 1))
        elif op == PcodeOp.INT_ADD:
            in0 = defn.getInput(0)
            in1 = defn.getInput(1)
            # Follow the non-constant operand; also check the constant
            if in1 is not None and in1.isConstant():
                stack.append((in0, depth + 1))
                # The constant itself might be a vtable address
                addr_val = in1.getOffset() & 0xFFFFFFFF
                cls = vtable_addr_to_class.get(addr_val)
                if cls:
                    return cls
            elif in0 is not None and in0.isConstant():
                stack.append((in1, depth + 1))
                addr_val = in0.getOffset() & 0xFFFFFFFF
                cls = vtable_addr_to_class.get(addr_val)
                if cls:
                    return cls
            else:
                stack.append((in0, depth + 1))
                stack.append((in1, depth + 1))
        elif op == PcodeOp.MULTIEQUAL:
            for i in range(defn.getNumInputs()):
                stack.append((defn.getInput(i), depth + 1))

    return None


def _extract_vtbl_writes_pcode(
    ifc,
    func,
    vtable_addr_to_class: dict[int, str],
    class_names: set[str],
    fn_name_to_class: dict[str, str],
    program,
) -> tuple[list[str], list[tuple[str, str]]] | None:
    """Extract vtable write sequence and call edges using Pcode SSA.

    Returns (vtbl_seq, call_edges) or None if decompilation fails.
    vtbl_seq: ordered list of class names from vtable STOREs to param0.
    call_edges: list of (callee_class, callee_fn_name) pairs.
    """
    from ghidra.program.model.pcode import PcodeOp

    res = ifc.decompileFunction(func, 20, None)
    if not res or not res.decompileCompleted():
        return None
    high_fn = res.getHighFunction()
    if high_fn is None:
        return None

    # Build param0 varnode set.
    # LocalSymbolMap.getParam(0) returns HighSymbol; we need its HighVariable
    # to access getRepresentative()/getInstances().
    param0_varnodes: set = set()
    lsm = high_fn.getLocalSymbolMap()

    def _collect_varnodes_from_hv(hv) -> None:
        """Add representative + all SSA instances from a HighVariable."""
        if hv is None:
            return
        try:
            rep = hv.getRepresentative()
            if rep is not None:
                param0_varnodes.add(rep)
        except Exception:
            pass
        try:
            for inst in hv.getInstances():
                param0_varnodes.add(inst)
        except Exception:
            pass

    # Method 1: getParam(0) → getHighVariable()
    try:
        param0_sym = lsm.getParam(0)
        if param0_sym is not None:
            try:
                hv = param0_sym.getHighVariable()
                _collect_varnodes_from_hv(hv)
            except AttributeError:
                # In some Ghidra versions, getParam may return HighParam
                # (which IS a HighVariable) directly
                _collect_varnodes_from_hv(param0_sym)
    except Exception:
        pass

    # Method 2: scan all symbols for parameter at category index 0
    if not param0_varnodes:
        try:
            sym_iter = lsm.getSymbols()
            while sym_iter.hasNext():
                sym = sym_iter.next()
                try:
                    if not sym.isParameter():
                        continue
                    if sym.getCategoryIndex() != 0:
                        continue
                except Exception:
                    continue
                try:
                    hv = sym.getHighVariable()
                except AttributeError:
                    hv = sym
                _collect_varnodes_from_hv(hv)
                break
        except Exception:
            pass

    # Method 3: Find param0 via Function.getParameters() storage location
    if not param0_varnodes:
        try:
            params = func.getParameters()
            if params and len(params) > 0:
                p0 = params[0]
                p0_reg = p0.getRegister()
                if p0_reg is not None:
                    reg_offset = p0_reg.getOffset()
                    reg_size = p0_reg.getMinimumByteSize()
                    for op in high_fn.getPcodeOps():
                        opc = op.getOpcode()
                        if opc == PcodeOp.COPY or opc == PcodeOp.INDIRECT:
                            inp = op.getInput(0)
                            if inp is not None and inp.isRegister():
                                if inp.getOffset() == reg_offset and inp.getSize() == reg_size:
                                    out = op.getOutput()
                                    if out is not None:
                                        param0_varnodes.add(out)
                                        param0_varnodes.add(inp)
        except Exception:
            pass

    # Method 4: Match by HighVariable name (catches decompiler-named vars
    # when parameter storage detection fails)
    if not param0_varnodes:
        param0_names = {"param_1", "this", "pThis", "in_ECX"}
        try:
            sym_iter = lsm.getSymbols()
            while sym_iter.hasNext():
                sym = sym_iter.next()
                try:
                    name = sym.getName()
                    if name not in param0_names:
                        continue
                except Exception:
                    continue
                try:
                    hv = sym.getHighVariable()
                except AttributeError:
                    hv = sym
                _collect_varnodes_from_hv(hv)
                if param0_varnodes:
                    break
        except Exception:
            pass

    if not param0_varnodes:
        return None

    # Collect STORE and CALL ops
    store_ops = []
    call_ops = []
    for op in high_fn.getPcodeOps():
        opc = op.getOpcode()
        if opc == PcodeOp.STORE:
            store_ops.append(op)
        elif opc == PcodeOp.CALL:
            call_ops.append(op)

    # Sort stores by (instruction address, intra-instruction order) for correct
    # execution sequencing.  getOrder() alone is intra-address; we need the
    # machine instruction address to get cross-block ordering right.
    store_ops.sort(
        key=lambda o: (o.getSeqnum().getTarget().getOffset(), o.getSeqnum().getOrder())
    )

    # --- Extract ordered vtable writes ---
    vtbl_seq: list[str] = []
    for op in store_ops:
        # STORE: input[0]=space, input[1]=dest addr, input[2]=value
        dest_vn = op.getInput(1)
        value_vn = op.getInput(2)
        if dest_vn is None or value_vn is None:
            continue
        # Check if destination traces back to param0
        if not _trace_to_param0(dest_vn, param0_varnodes, PcodeOp):
            continue
        # Resolve value to a vtable class
        cls = _resolve_stored_vtable(
            value_vn, vtable_addr_to_class, class_names, program, PcodeOp
        )
        if cls and (not vtbl_seq or vtbl_seq[-1] != cls):
            vtbl_seq.append(cls)

    # --- Extract cross-class constructor calls ---
    call_edges: list[tuple[str, str]] = []
    fm = program.getFunctionManager()
    for op in call_ops:
        # CALL: input[0]=callee addr, input[1..]=arguments
        callee_addr_vn = op.getInput(0)
        if callee_addr_vn is None:
            continue
        # Check if first argument (input[1]) traces to param0
        if op.getNumInputs() < 2:
            continue
        arg0_vn = op.getInput(1)
        if arg0_vn is None:
            continue
        if not _trace_to_param0(arg0_vn, param0_varnodes, PcodeOp):
            continue
        # Resolve callee function
        try:
            callee_addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(
                callee_addr_vn.getOffset()
            )
            callee_fn = fm.getFunctionAt(callee_addr)
        except Exception:
            continue
        if callee_fn is None:
            continue
        callee_name = callee_fn.getName()
        # Only accept constructor/destructor-like callees as inheritance evidence
        callee_lower = callee_name.lower()
        if not ("construct" in callee_lower or "create" in callee_lower or "destruct" in callee_lower):
            continue
        callee_cls = fn_name_to_class.get(callee_name)
        if callee_cls:
            call_edges.append((callee_cls, callee_name))

    return (vtbl_seq, call_edges)


def _compare_vtable_slots(
    program,
    vtable_addr_to_class: dict[int, str],
    class_names: set[str],
) -> list[dict]:
    """Compare vtable slot contents to detect structural inheritance.

    For each pair of vtable addresses, read function pointers at consecutive
    4-byte slots.  If vtable A's slots are an exact prefix of vtable B's
    (minimum 3 slots), then A's class is a base of B's class.

    Slot reading stops at the next known symbol address to avoid overshooting
    into adjacent data.  A transitive reduction keeps only direct parent→child
    edges.
    """
    mem = program.getMemory()
    fm = program.getFunctionManager()
    af = program.getAddressFactory().getDefaultAddressSpace()

    # Build a sorted list of all known symbol addresses for boundary detection
    all_sym_addrs: set[int] = set(vtable_addr_to_class.keys())
    # Also collect other global symbols that could mark vtable boundaries
    st = program.getSymbolTable()
    sym_it = st.getAllSymbols(False)
    while sym_it.hasNext():
        sym = sym_it.next()
        a = sym.getAddress()
        if not a.isExternalAddress():
            try:
                all_sym_addrs.add(int(str(a), 16))
            except Exception:
                pass

    # Step 1: Read all vtable slot sequences
    vtable_slots: dict[str, list[tuple[int, list[int]]]] = {}
    for addr_int, cls in vtable_addr_to_class.items():
        # Find the next symbol after this vtable to bound the read
        max_slots = 120
        for sym_addr in all_sym_addrs:
            if sym_addr > addr_int:
                boundary_slots = (sym_addr - addr_int) // 4
                if boundary_slots < max_slots:
                    max_slots = boundary_slots

        slots: list[int] = []
        for i in range(max_slots):
            try:
                a = af.getAddress(f"0x{(addr_int + i * 4) & 0xFFFFFFFF:08x}")
                val = mem.getInt(a) & 0xFFFFFFFF
            except Exception:
                break
            if val == 0:
                break  # NULL terminates the vtable
            try:
                fn_addr = af.getAddress(f"0x{val:08x}")
                fn = fm.getFunctionAt(fn_addr)
            except Exception:
                fn = None
            if fn is None:
                break  # Non-function-pointer terminates
            slots.append(val)
        if len(slots) >= 3:
            vtable_slots.setdefault(cls, []).append((addr_int, slots))

    # Step 2: Compare pairs — check exact prefix match
    raw_pairs: list[tuple[str, str, int, int, int, int]] = []
    # (base_cls, derived_cls, base_addr, derived_addr, prefix_len, derived_len)
    class_list = sorted(vtable_slots.keys())
    for i, cls_a in enumerate(class_list):
        for cls_b in class_list[i + 1 :]:
            if cls_a == cls_b:
                continue
            for addr_a, slots_a in vtable_slots[cls_a]:
                for addr_b, slots_b in vtable_slots[cls_b]:
                    if len(slots_a) == len(slots_b):
                        continue
                    if len(slots_a) < len(slots_b):
                        shorter, longer = slots_a, slots_b
                        shorter_cls, longer_cls = cls_a, cls_b
                        shorter_addr, longer_addr = addr_a, addr_b
                    else:
                        shorter, longer = slots_b, slots_a
                        shorter_cls, longer_cls = cls_b, cls_a
                        shorter_addr, longer_addr = addr_b, addr_a
                    prefix_len = len(shorter)
                    if prefix_len < 3:
                        continue
                    # Require exact prefix match
                    if shorter != longer[:prefix_len]:
                        continue
                    raw_pairs.append((
                        shorter_cls, longer_cls,
                        shorter_addr, longer_addr,
                        prefix_len, len(longer),
                    ))

    # Step 3: Transitive reduction — only keep direct parent→child edges
    # For each derived class, keep only the base with the longest prefix
    # (i.e., the most immediate parent).
    best_base: dict[str, tuple[str, int, int, int, int]] = {}
    for base_cls, derived_cls, base_addr, derived_addr, plen, dlen in raw_pairs:
        key = derived_cls
        existing = best_base.get(key)
        if existing is None or plen > existing[1]:
            best_base[key] = (base_cls, plen, base_addr, derived_addr, dlen)

    edges: list[dict] = []
    for derived_cls, (base_cls, plen, base_addr, derived_addr, dlen) in best_base.items():
        edges.append({
            "base_class": base_cls,
            "derived_class": derived_cls,
            "evidence_kind": "vtable_slot_prefix",
            "confidence": "high",
            "function_name": "",
            "function_addr": "",
            "evidence_detail": (
                f"vtbl_0x{base_addr:08x}({plen}slots)"
                f"⊂vtbl_0x{derived_addr:08x}({dlen}slots)"
            ),
        })
    return edges


def _extract_vtbl_writes_regex(
    ifc,
    func,
    vtable_addr_to_class: dict[int, str],
    class_names: set[str],
    fn_name_to_class: dict[str, str],
) -> tuple[list[str], list[tuple[str, str]]] | None:
    """Extract vtable write sequence and call edges using regex on decompiled C.

    Returns (vtbl_seq, call_edges) or None if decompilation fails.
    """
    c_code = decompile_text(ifc, func)
    if not c_code:
        return None

    # --- Extract ordered vtable writes (both raw and typed) ---
    vtbl_seq: list[str] = []
    all_matches = list(_VTBL_WRITE_RAW.finditer(c_code))
    all_matches.extend(_VTBL_WRITE_TYPED.finditer(c_code))
    all_matches.sort(key=lambda m: m.start())
    for m in all_matches:
        resolved = _resolve_vtbl_class(m, vtable_addr_to_class, class_names)
        if resolved and (not vtbl_seq or vtbl_seq[-1] != resolved):
            vtbl_seq.append(resolved)

    # --- Cross-class constructor calls ---
    call_edges: list[tuple[str, str]] = []
    for cm in _CTOR_CALL.finditer(c_code):
        callee_name = cm.group(1)
        callee_cls = fn_name_to_class.get(callee_name)
        if callee_cls:
            call_edges.append((callee_cls, callee_name))

    return (vtbl_seq, call_edges)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Reconstruct class inheritance hierarchy from "
        "constructor/destructor vtable write sequences.",
    )
    ap.add_argument("--out-csv", required=True, help="Raw edges output CSV path")
    ap.add_argument("--max-classes", type=int, default=0, help="Limit classes (0=all)")
    ap.add_argument(
        "--use-pcode",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Use Pcode SSA analysis instead of regex (default: True)",
    )
    ap.add_argument(
        "--vtable-compare",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Compare vtable slot contents for structural hierarchy (default: False)",
    )
    ap.add_argument(
        "--project-root",
        default=default_project_root(),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    root = resolve_project_root(args.project_root)
    out_csv = Path(args.out_csv)
    if not out_csv.is_absolute():
        out_csv = root / out_csv
    out_csv.parent.mkdir(parents=True, exist_ok=True)

    with open_program(root) as program:
        from ghidra.app.decompiler import DecompInterface

        fm = program.getFunctionManager()
        st = program.getSymbolTable()
        global_ns = program.getGlobalNamespace()

        # ------------------------------------------------------------------
        # Step 1: Build vtable mappings
        # ------------------------------------------------------------------
        class_names: set[str] = set()
        it_cls = st.getClassNamespaces()
        while it_cls.hasNext():
            class_names.add(it_cls.next().getName())

        # vtable_addr → class_name  (from g_vtbl* symbols)
        vtable_addr_to_class: dict[int, str] = {}
        sym_it = st.getAllSymbols(False)
        while sym_it.hasNext():
            sym = sym_it.next()
            name = sym.getName()
            if not name or not name.startswith("g_vtbl"):
                continue
            rest = name[6:]
            for cls in sorted(class_names, key=len, reverse=True):
                if rest.startswith(cls):
                    addr = sym.getAddress()
                    if not addr.isExternalAddress():
                        vtable_addr_to_class[int(str(addr), 16)] = cls
                    break

        print(f"[init] known classes: {len(class_names)}")
        print(f"[init] vtable_addr_to_class entries: {len(vtable_addr_to_class)}")

        # ------------------------------------------------------------------
        # Step 2: Collect class-namespaced functions + Global helpers
        # ------------------------------------------------------------------
        class_methods: dict[str, list] = {}
        fn_name_to_class: dict[str, str] = {}

        # Pattern to extract class name from Global helper names like
        # DestructTWindowViewAndUnlinkGlobalLists, ConstructTTextLineBaseState
        _HELPER_NAME = re.compile(
            r"(?:Destruct|Construct|Create)(T[A-Z]\w+?)"
            r"(?:And|Base|Core|View|Instance|Maybe|State|Free|_Impl)"
        )
        # Sorted by length descending for longest-match
        sorted_classes = sorted(class_names, key=len, reverse=True)

        global_helpers_added = 0
        fit = fm.getFunctions(True)
        while fit.hasNext():
            fn = fit.next()
            ns = fn.getParentNamespace()
            if ns is not None and ns != global_ns:
                ns_name = ns.getName()
                if ns_name in class_names:
                    class_methods.setdefault(ns_name, []).append(fn)
                    fn_name_to_class[fn.getName()] = ns_name
                continue

            # Global function — check if it's a ctor/dtor helper
            # These often use __cdecl (param_1 = this) rather than __thiscall
            fn_name = fn.getName()

            # Try to extract class from name
            hm = _HELPER_NAME.search(fn_name)
            if not hm:
                continue
            candidate = hm.group(1)
            # Find the longest known class that is a prefix of candidate
            matched_cls = None
            for cls in sorted_classes:
                if candidate.startswith(cls):
                    matched_cls = cls
                    break
            if matched_cls:
                class_methods.setdefault(matched_cls, []).append(fn)
                fn_name_to_class[fn_name] = matched_cls
                global_helpers_added += 1

        print(f"[init] classes with methods: {len(class_methods)}")
        ns_count = sum(len(v) for v in class_methods.values()) - global_helpers_added
        print(f"[init] class-namespaced functions: {ns_count}")
        print(f"[init] global helper functions added: {global_helpers_added}")

        # ------------------------------------------------------------------
        # Step 2b: Call-graph pre-pass for constructor chain detection
        # ------------------------------------------------------------------
        # Fast non-decompilation pass: for each class method, record which
        # other class methods it calls. This enables transitive ctor chain
        # propagation after the main loop.
        fn_addr_to_class: dict[int, str] = {}
        for cls_name, methods in class_methods.items():
            for fn in methods:
                addr_int = fn.getEntryPoint().getOffset() & 0xFFFFFFFF
                fn_addr_to_class[addr_int] = cls_name

        callgraph_edges: list[tuple[str, str, str, str]] = []
        # (caller_cls, callee_cls, caller_fn_name, callee_fn_name)
        for cls_name, methods in class_methods.items():
            for fn in methods:
                fn_name = fn.getName()
                try:
                    callees = fn.getCalledFunctions(None)
                except Exception:
                    continue
                try:
                    it = callees.iterator()
                    while it.hasNext():
                        callee = it.next()
                        callee_addr = callee.getEntryPoint().getOffset() & 0xFFFFFFFF
                        callee_cls = fn_addr_to_class.get(callee_addr)
                        if callee_cls and callee_cls != cls_name:
                            callgraph_edges.append(
                                (cls_name, callee_cls, fn_name, callee.getName())
                            )
                except Exception:
                    continue

        print(f"[init] cross-class call-graph edges: {len(callgraph_edges)}")

        # ------------------------------------------------------------------
        # Step 2c: Vtable slot comparison (structural hierarchy)
        # ------------------------------------------------------------------
        raw_edges: list[dict] = []

        if args.vtable_compare:
            vtable_slot_edges = _compare_vtable_slots(
                program, vtable_addr_to_class, class_names
            )
            raw_edges.extend(vtable_slot_edges)
            print(f"[init] vtable slot prefix edges: {len(vtable_slot_edges)}")

        # ------------------------------------------------------------------
        # Step 3-6: Decompile and extract hierarchy edges
        # ------------------------------------------------------------------
        ifc = DecompInterface()
        ifc.openProgram(program)

        extraction_mode = "pcode" if args.use_pcode else "regex"
        print(f"\n[scan] extraction mode: {extraction_mode}")
        classes_processed = 0
        methods_decompiled = 0
        pcode_fallbacks = 0

        for cls_name, methods in sorted(class_methods.items()):
            if args.max_classes and classes_processed >= args.max_classes:
                break
            classes_processed += 1

            for method_fn in methods:
                fn_name = method_fn.getName()
                addr_int = method_fn.getEntryPoint().getOffset() & 0xFFFFFFFF
                fn_addr_str = f"0x{addr_int:08x}"

                # --- Extract vtable writes and call edges ---
                if args.use_pcode:
                    result = _extract_vtbl_writes_pcode(
                        ifc,
                        method_fn,
                        vtable_addr_to_class,
                        class_names,
                        fn_name_to_class,
                        program,
                    )
                    # Fall back to regex if Pcode can't find param0
                    if result is None:
                        result = _extract_vtbl_writes_regex(
                            ifc,
                            method_fn,
                            vtable_addr_to_class,
                            class_names,
                            fn_name_to_class,
                        )
                        if result is not None:
                            pcode_fallbacks += 1
                else:
                    result = _extract_vtbl_writes_regex(
                        ifc,
                        method_fn,
                        vtable_addr_to_class,
                        class_names,
                        fn_name_to_class,
                    )

                if result is None:
                    continue
                methods_decompiled += 1
                vtbl_seq, call_edges = result

                # --- Direction detection and edge emission (shared) ---
                if len(vtbl_seq) >= 2:
                    fn_lower = fn_name.lower()
                    is_dtor_name = "destruct" in fn_lower
                    is_ctor_name = "construct" in fn_lower or "create" in fn_lower

                    if vtbl_seq[-1] == cls_name:
                        direction = "ctor"
                        chain = vtbl_seq
                    elif vtbl_seq[0] == cls_name:
                        direction = "dtor"
                        chain = list(reversed(vtbl_seq))
                    elif is_dtor_name and not is_ctor_name:
                        direction = "dtor_inferred"
                        chain = list(reversed(vtbl_seq))
                    elif is_ctor_name and not is_dtor_name:
                        direction = "ctor_inferred"
                        chain = vtbl_seq
                    else:
                        chain = None

                    if chain is not None:
                        evidence_kind = f"decomp_vtbl_seq_{direction}"
                        if direction in ("ctor", "dtor"):
                            confidence = "high"
                        elif cls_name in vtbl_seq:
                            confidence = "medium"
                        else:
                            confidence = "low"

                        for i in range(len(chain) - 1):
                            base = chain[i]
                            derived = chain[i + 1]
                            if (
                                base in class_names
                                and derived in class_names
                                and base != derived
                            ):
                                raw_edges.append({
                                    "base_class": base,
                                    "derived_class": derived,
                                    "evidence_kind": evidence_kind,
                                    "confidence": confidence,
                                    "function_name": fn_name,
                                    "function_addr": fn_addr_str,
                                    "evidence_detail": f"chain={'→'.join(chain)}",
                                })

                # --- Cross-class constructor calls ---
                for callee_cls, callee_name in call_edges:
                    if (
                        callee_cls != cls_name
                        and callee_cls in class_names
                    ):
                        raw_edges.append({
                            "base_class": callee_cls,
                            "derived_class": cls_name,
                            "evidence_kind": "ctor_call",
                            "confidence": "low",
                            "function_name": fn_name,
                            "function_addr": fn_addr_str,
                            "evidence_detail": f"calls_{callee_name}_in_{callee_cls}",
                        })

            if classes_processed % 50 == 0:
                print(
                    f"  [progress] classes: {classes_processed}/{len(class_methods)}, "
                    f"methods: {methods_decompiled}, edges: {len(raw_edges)}"
                )

        ifc.dispose()

        print(f"\n[scan] classes processed: {classes_processed}")
        print(f"[scan] methods decompiled: {methods_decompiled}")
        if args.use_pcode:
            print(f"[scan] pcode→regex fallbacks: {pcode_fallbacks}")
        print(f"[scan] raw edges (before promotion/transitive): {len(raw_edges)}")

        # ------------------------------------------------------------------
        # Step 6a: Promote ctor_call confidence
        # ------------------------------------------------------------------
        ctor_groups: dict[tuple[str, str], list[dict]] = defaultdict(list)
        for e in raw_edges:
            if e["evidence_kind"] == "ctor_call":
                ctor_groups[(e["base_class"], e["derived_class"])].append(e)

        promoted_count = 0
        for (base, derived), edges in ctor_groups.items():
            distinct_fns = len(set(e["function_addr"] for e in edges))
            has_ctor_name = any(
                "Construct" in e["function_name"] or "Create" in e["function_name"]
                for e in edges
            )
            if distinct_fns >= 3 or (has_ctor_name and distinct_fns >= 2):
                for e in edges:
                    e["confidence"] = "medium"
                promoted_count += len(edges)

        if promoted_count:
            print(f"[scan] ctor_call edges promoted to medium: {promoted_count}")

        # ------------------------------------------------------------------
        # Step 6b: Transitive constructor chain propagation
        # ------------------------------------------------------------------
        # If B→A and C→B are ctor_call edges, add C→A as ctor_call_transitive.
        ctor_call_set: set[tuple[str, str]] = set()
        for e in raw_edges:
            if e["evidence_kind"] == "ctor_call":
                ctor_call_set.add((e["base_class"], e["derived_class"]))

        transitive_edges: list[dict] = []
        for base_a, derived_b in list(ctor_call_set):
            # derived_b calls base_a's ctor → derived_b inherits from base_a
            # Now find who calls derived_b's ctor
            for base_b, derived_c in list(ctor_call_set):
                if base_b == derived_b and derived_c != base_a:
                    # derived_c → derived_b → base_a, so derived_c also inherits from base_a
                    pair = (base_a, derived_c)
                    if pair not in ctor_call_set and base_a in class_names and derived_c in class_names:
                        transitive_edges.append({
                            "base_class": base_a,
                            "derived_class": derived_c,
                            "evidence_kind": "ctor_call_transitive",
                            "confidence": "low",
                            "function_name": "",
                            "function_addr": "",
                            "evidence_detail": f"transitive_via_{derived_b}",
                        })

        raw_edges.extend(transitive_edges)
        if transitive_edges:
            print(f"[scan] transitive ctor_call edges added: {len(transitive_edges)}")
        print(f"[scan] total raw edges: {len(raw_edges)}")

    # ------------------------------------------------------------------
    # Step 7: Aggregate and rank
    # ------------------------------------------------------------------

    # Write raw edges CSV
    raw_fields = [
        "base_class",
        "derived_class",
        "evidence_kind",
        "confidence",
        "function_name",
        "function_addr",
        "evidence_detail",
    ]
    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=raw_fields)
        w.writeheader()
        w.writerows(raw_edges)

    # Build ranked summary
    edge_key = lambda e: (e["base_class"], e["derived_class"])
    edge_groups: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for e in raw_edges:
        edge_groups[edge_key(e)].append(e)

    ranked_rows: list[dict] = []
    for (base, derived), evidences in sorted(edge_groups.items()):
        conf_counts = Counter(e["confidence"] for e in evidences)
        kinds = sorted(set(e["evidence_kind"] for e in evidences))
        # Collect sample functions (unique, up to 8)
        seen_fns: set[str] = set()
        samples: list[str] = []
        for e in evidences:
            key = f"{e['function_addr']}:{e['function_name']}"
            if key not in seen_fns:
                seen_fns.add(key)
                samples.append(key)
            if len(samples) >= 8:
                break

        ranked_rows.append({
            "base_class": base,
            "derived_class": derived,
            "total_support": len(evidences),
            "high_support": conf_counts.get("high", 0),
            "medium_support": conf_counts.get("medium", 0),
            "low_support": conf_counts.get("low", 0),
            "evidence_kinds": ",".join(kinds),
            "sample_functions": ";".join(samples),
        })

    ranked_rows.sort(key=lambda r: -r["total_support"])

    # Write ranked CSV
    ranked_csv = out_csv.with_name(out_csv.stem + "_ranked.csv")
    ranked_fields = [
        "base_class",
        "derived_class",
        "total_support",
        "high_support",
        "medium_support",
        "low_support",
        "evidence_kinds",
        "sample_functions",
    ]
    with ranked_csv.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=ranked_fields)
        w.writeheader()
        w.writerows(ranked_rows)

    # ------------------------------------------------------------------
    # Step 8: Build tree and print
    # ------------------------------------------------------------------

    # Only use edges with high or medium support for the tree
    children: dict[str, list[str]] = defaultdict(list)
    all_derived: set[str] = set()
    all_bases: set[str] = set()

    for row in ranked_rows:
        if row["high_support"] + row["medium_support"] > 0:
            base = row["base_class"]
            derived = row["derived_class"]
            children[base].append(derived)
            all_derived.add(derived)
            all_bases.add(base)

    # Detect circular edges
    circular = []
    for base, kids in children.items():
        for kid in kids:
            if base in children.get(kid, []):
                circular.append((base, kid))
    if circular:
        print(f"\n[WARNING] circular edges detected: {circular}")

    # Roots: appear as base but not as derived
    roots = sorted(all_bases - all_derived)

    # Also include isolated pairs where derived appears nowhere else
    # (these are leaf-only hierarchies)

    def _print_tree(node: str, prefix: str, is_last: bool, visited: set[str]) -> None:
        connector = "└── " if is_last else "├── "
        print(f"{prefix}{connector}{node}")
        if node in visited:
            print(f"{prefix}{'    ' if is_last else '│   '}(cycle)")
            return
        visited = visited | {node}
        kids = sorted(children.get(node, []))
        for i, kid in enumerate(kids):
            ext = "    " if is_last else "│   "
            _print_tree(kid, prefix + ext, i == len(kids) - 1, visited)

    if roots:
        print(f"\n[tree] {len(roots)} root(s), {len(ranked_rows)} edges (ranked)")
        for i, root_cls in enumerate(roots):
            if i > 0:
                print()
            print(root_cls)
            kids = sorted(children.get(root_cls, []))
            for j, kid in enumerate(kids):
                _print_tree(kid, "", j == len(kids) - 1, {root_cls})
    else:
        print("\n[tree] no hierarchy roots found")

    # Stats summary
    classes_with_parents = len(all_derived)
    max_depth = 0

    def _depth(node: str, visited: set[str]) -> int:
        if node in visited or node not in children:
            return 0
        visited = visited | {node}
        return 1 + max((_depth(k, visited) for k in children[node]), default=0)

    for r in roots:
        d = _depth(r, set())
        if d > max_depth:
            max_depth = d

    print(f"\n[stats] ranked edges: {len(ranked_rows)}")
    print(f"[stats] high+medium edges: {sum(1 for r in ranked_rows if r['high_support'] + r['medium_support'] > 0)}")
    print(f"[stats] classes with identified parents: {classes_with_parents}")
    print(f"[stats] max tree depth: {max_depth}")
    print(f"[stats] tree roots: {len(roots)}")

    print(f"\n[saved] raw edges: {out_csv}")
    print(f"[saved] ranked summary: {ranked_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
