from __future__ import annotations

import hashlib

from imperialism_re.core.decompiler import (
    _get_passthrough_opcodes,
    collect_param0_varnodes,
    create_configured_decompiler,
    decompile_function,
    trace_to_param0,
)


def format_addr(value: int) -> str:
    return f"0x{(value & 0xFFFFFFFF):08x}"


def function_class_name(fn) -> str:
    ns = fn.getParentNamespace()
    if ns is None:
        return ""
    name = str(ns.getName())
    if name.lower() == "global":
        return ""
    return name


def _read_scalar_operand_values(ins) -> list[int]:
    out: list[int] = []
    try:
        num_ops = int(ins.getNumOperands())
    except Exception:
        return out
    for op_idx in range(num_ops):
        try:
            objs = ins.getOpObjects(op_idx)
        except Exception:
            continue
        for obj in objs:
            if not hasattr(obj, "getUnsignedValue"):
                continue
            try:
                val = int(obj.getUnsignedValue()) & 0xFFFFFFFF
            except Exception:
                continue
            out.append(val)
    return out


_STRING_TYPE_KEYWORDS = ("string", "char", "terminated", "unicode")


def _extract_string_from_data(data) -> str | None:
    if data is None:
        return None
    try:
        dt_name = str(data.getDataType()).lower()
    except Exception:
        dt_name = ""
    if not any(k in dt_name for k in _STRING_TYPE_KEYWORDS):
        return None
    try:
        val = data.getValue()
    except Exception:
        val = None
    if val is None:
        return None
    if isinstance(val, bytes):
        try:
            txt = val.decode("utf-8", errors="ignore")
        except Exception:
            return None
    else:
        txt = str(val)
    txt = txt.strip()
    if not txt:
        return None
    return txt


def _looks_like_pointer(value: int, mem, af) -> bool:
    if value <= 0:
        return False
    try:
        addr = af.getAddress(f"{value:08x}")
    except Exception:
        return False
    try:
        return bool(mem.contains(addr))
    except Exception:
        return False


def _resolve_call_target_addr(vn, PcodeOp, max_depth: int = 6) -> int | None:
    stack: list[tuple[object, int]] = [(vn, 0)]
    visited: set[int] = set()
    passthrough = _get_passthrough_opcodes(PcodeOp)
    while stack:
        cur, depth = stack.pop()
        if cur is None or depth > max_depth:
            continue
        uid = id(cur)
        if uid in visited:
            continue
        visited.add(uid)

        try:
            if cur.isAddress() or cur.isConstant():
                return int(cur.getOffset()) & 0xFFFFFFFF
        except Exception:
            pass

        try:
            defn = cur.getDef()
        except Exception:
            defn = None
        if defn is None:
            continue
        try:
            opc = int(defn.getOpcode())
        except Exception:
            continue
        if opc in passthrough:
            for i in range(defn.getNumInputs()):
                stack.append((defn.getInput(i), depth + 1))
            continue
        if opc == PcodeOp.INT_ADD:
            in0 = defn.getInput(0)
            in1 = defn.getInput(1)
            if in1 is not None:
                try:
                    if in1.isConstant():
                        stack.append((in0, depth + 1))
                        continue
                except Exception:
                    pass
            if in0 is not None:
                try:
                    if in0.isConstant():
                        stack.append((in1, depth + 1))
                        continue
                except Exception:
                    pass
    return None


def _emit_rows_for_function(
    program,
    fn,
    ifc,
    min_constant: int,
    max_constant: int,
) -> list[dict[str, str]]:
    from ghidra.program.model.pcode import PcodeOp

    fm = program.getFunctionManager()
    af = program.getAddressFactory().getDefaultAddressSpace()
    mem = program.getMemory()
    listing = program.getListing()

    addr = int(fn.getEntryPoint().getOffset()) & 0xFFFFFFFF
    name = str(fn.getName())
    class_name = function_class_name(fn)

    fingerprints: dict[str, set[str]] = {
        "string_hash": set(),
        "constant": set(),
        "callee": set(),
        "this_offset": set(),
    }

    ins_it = listing.getInstructions(fn.getBody(), True)
    while ins_it.hasNext():
        ins = ins_it.next()

        for ref in ins.getReferencesFrom():
            to = ref.getToAddress()
            if to is None:
                continue
            data = listing.getDataAt(to)
            if data is None:
                data = listing.getDefinedDataContaining(to)
            txt = _extract_string_from_data(data)
            if not txt:
                continue
            h = hashlib.sha1(txt.encode("utf-8", errors="ignore")).hexdigest()[:8]
            fingerprints["string_hash"].add(h)

        for val in _read_scalar_operand_values(ins):
            if val < min_constant or val > max_constant:
                continue
            if _looks_like_pointer(val, mem, af):
                continue
            fingerprints["constant"].add(str(val))

    res = decompile_function(ifc, fn, timeout=30)
    if res is not None:
        high_fn = res.getHighFunction()
        if high_fn is not None:
            param0 = collect_param0_varnodes(high_fn, fn, PcodeOp)
            op_it = high_fn.getPcodeOps()
            while op_it.hasNext():
                op = op_it.next()
                opc = int(op.getOpcode())

                if opc == PcodeOp.CALL and op.getNumInputs() > 0:
                    target = _resolve_call_target_addr(op.getInput(0), PcodeOp)
                    if target is not None:
                        try:
                            callee = fm.getFunctionAt(af.getAddress(f"{target:08x}"))
                        except Exception:
                            callee = None
                        if callee is not None:
                            fingerprints["callee"].add(str(callee.getName()))

                if opc not in (PcodeOp.PTRSUB, PcodeOp.INT_ADD):
                    continue
                if op.getNumInputs() < 2:
                    continue

                in0 = op.getInput(0)
                in1 = op.getInput(1)
                if in0 is None or in1 is None:
                    continue

                try:
                    in1_const = bool(in1.isConstant())
                except Exception:
                    in1_const = False
                try:
                    in0_const = bool(in0.isConstant())
                except Exception:
                    in0_const = False

                if in1_const and trace_to_param0(in0, param0, PcodeOp):
                    off = int(in1.getOffset()) & 0xFFFFFFFF
                    if off <= 0x10000:
                        fingerprints["this_offset"].add(str(off))
                elif opc == PcodeOp.INT_ADD and in0_const and trace_to_param0(in1, param0, PcodeOp):
                    off = int(in0.getOffset()) & 0xFFFFFFFF
                    if off <= 0x10000:
                        fingerprints["this_offset"].add(str(off))

    rows: list[dict[str, str]] = []
    for fp_type in ("string_hash", "constant", "callee", "this_offset"):
        for fp_value in sorted(fingerprints[fp_type]):
            rows.append(
                {
                    "func_addr": format_addr(addr),
                    "func_name": name,
                    "class_name": class_name,
                    "fingerprint_type": fp_type,
                    "fingerprint_value": fp_value,
                }
            )
    return rows


def collect_fingerprint_rows(
    program,
    functions: list[object],
    *,
    min_constant: int,
    max_constant: int,
    progress_label: str,
) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    if not functions:
        return rows
    ifc = create_configured_decompiler(program)
    try:
        for idx, fn in enumerate(functions, start=1):
            rows.extend(
                _emit_rows_for_function(
                    program,
                    fn,
                    ifc,
                    min_constant=min_constant,
                    max_constant=max_constant,
                )
            )
            if idx % 500 == 0 or idx == len(functions):
                print(f"[{progress_label}] {idx}/{len(functions)}")
    finally:
        ifc.dispose()
    return rows

