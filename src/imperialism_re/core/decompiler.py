"""Shared decompiler factory and Pcode SSA helpers.

Provides reusable ``DecompInterface`` configuration, function-level
decompilation wrappers, and param0 varnode collection / tracing utilities
extracted from ``reconstruct_class_hierarchy``.

Usage::

    from imperialism_re.core.decompiler import (
        create_configured_decompiler,
        decompile_function,
        decompile_function_text,
        collect_param0_varnodes,
        trace_to_param0,
    )

    with open_program(root) as program:
        ifc = create_configured_decompiler(program)
        try:
            text = decompile_function_text(ifc, func)
        finally:
            ifc.dispose()
"""

from __future__ import annotations


# ---------------------------------------------------------------------------
# Decompiler factory
# ---------------------------------------------------------------------------

def create_configured_decompiler(
    program,
    *,
    timeout: int = 20,
    eliminate_unreachable: bool = True,
    respect_read_only: bool = True,
    toggle_jump_loads: bool = True,
):
    """Create a ``DecompInterface`` with quality-tuned ``DecompileOptions``.

    The caller is responsible for calling ``.dispose()`` when done.
    """
    from ghidra.app.decompiler import DecompInterface, DecompileOptions

    ifc = DecompInterface()

    opts = DecompileOptions()
    opts.grabFromProgram(program)
    opts.setEliminateUnreachable(eliminate_unreachable)
    opts.setRespectReadOnly(respect_read_only)

    ifc.setOptions(opts)
    ifc.toggleJumpLoads(toggle_jump_loads)
    ifc.openProgram(program)
    return ifc


# ---------------------------------------------------------------------------
# Function-level decompilation helpers
# ---------------------------------------------------------------------------

def decompile_function(ifc, func, timeout: int = 20):
    """Decompile *func* and return ``DecompileResults`` or ``None``."""
    res = ifc.decompileFunction(func, timeout, None)
    if not res or not res.decompileCompleted():
        return None
    return res


def decompile_function_text(ifc, func, timeout: int = 20) -> str:
    """Return the decompiled C text for *func*, or ``""`` on failure."""
    res = decompile_function(ifc, func, timeout)
    if res is None:
        return ""
    dc = res.getDecompiledFunction()
    if dc is None:
        return ""
    return str(dc.getC())


# ---------------------------------------------------------------------------
# Pcode SSA: passthrough opcode set
# ---------------------------------------------------------------------------

_PASSTHROUGH_OPCODES: set[int] | None = None


def _get_passthrough_opcodes(PcodeOp) -> set[int]:
    """Lazily build the set of pass-through opcodes (needs ``PcodeOp`` class)."""
    global _PASSTHROUGH_OPCODES
    if _PASSTHROUGH_OPCODES is None:
        _PASSTHROUGH_OPCODES = {
            PcodeOp.COPY,
            PcodeOp.CAST,
            PcodeOp.MULTIEQUAL,
            PcodeOp.INDIRECT,
        }
    return _PASSTHROUGH_OPCODES


# ---------------------------------------------------------------------------
# param0 varnode collection
# ---------------------------------------------------------------------------

def _collect_varnodes_from_hv(hv, dest: set) -> None:
    """Add representative + all SSA instances from a ``HighVariable``."""
    if hv is None:
        return
    try:
        rep = hv.getRepresentative()
        if rep is not None:
            dest.add(rep)
    except Exception:
        pass
    try:
        for inst in hv.getInstances():
            dest.add(inst)
    except Exception:
        pass


def collect_param0_varnodes(high_fn, func, PcodeOp) -> set:
    """Collect all Varnodes that represent param0 / ``this``.

    Uses four detection methods (in priority order):
      1. ``lsm.getParam(0)`` → ``getHighVariable()``
      2. Scan all symbols for parameter at category index 0
      3. Match register storage location from ``func.getParameters()``
      4. Match by HighVariable name (``param_1``, ``this``, etc.)

    Returns a set of Varnode objects (may be empty).
    """
    param0_varnodes: set = set()
    lsm = high_fn.getLocalSymbolMap()

    # Method 1: getParam(0) → getHighVariable()
    try:
        param0_sym = lsm.getParam(0)
        if param0_sym is not None:
            try:
                hv = param0_sym.getHighVariable()
                _collect_varnodes_from_hv(hv, param0_varnodes)
            except AttributeError:
                _collect_varnodes_from_hv(param0_sym, param0_varnodes)
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
                _collect_varnodes_from_hv(hv, param0_varnodes)
                break
        except Exception:
            pass

    # Method 3: find param0 via Function.getParameters() storage location
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

    # Method 4: match by HighVariable name
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
                _collect_varnodes_from_hv(hv, param0_varnodes)
                if param0_varnodes:
                    break
        except Exception:
            pass

    return param0_varnodes


# ---------------------------------------------------------------------------
# param0 tracing
# ---------------------------------------------------------------------------

def trace_to_param0(
    vn,
    param0_varnodes: set,
    PcodeOp,
    max_depth: int = 8,
) -> bool:
    """Walk backward through SSA def-chain to check if *vn* originates from param0.

    Follows COPY, CAST, INT_ADD(x,0), PTRSUB(base,0), MULTIEQUAL, INDIRECT.
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

        if cur in param0_varnodes:
            return True

        defn = cur.getDef()
        if defn is None:
            continue
        op = defn.getOpcode()

        if op in passthrough:
            for i in range(defn.getNumInputs()):
                stack.append((defn.getInput(i), depth + 1))
        elif op == PcodeOp.INT_ADD:
            in0 = defn.getInput(0)
            in1 = defn.getInput(1)
            if in1 is not None and in1.isConstant() and in1.getOffset() == 0:
                stack.append((in0, depth + 1))
            elif in0 is not None and in0.isConstant() and in0.getOffset() == 0:
                stack.append((in1, depth + 1))
        elif op == PcodeOp.PTRSUB:
            in1 = defn.getInput(1)
            if in1 is not None and in1.isConstant() and in1.getOffset() == 0:
                stack.append((defn.getInput(0), depth + 1))

    return False
