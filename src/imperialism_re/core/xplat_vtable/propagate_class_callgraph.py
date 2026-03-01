from __future__ import annotations

import difflib
from collections import defaultdict
from pathlib import Path

from imperialism_re.core.csvio import load_csv_rows, write_csv_rows
from imperialism_re.core.decompiler import (
    collect_param0_varnodes,
    create_configured_decompiler,
    decompile_function,
    trace_to_param0,
)
from imperialism_re.core.ghidra_session import open_program
from imperialism_re.core.wave_shared import is_unresolved_name


def _parse_addr(text: str) -> int | None:
    token = (text or "").strip()
    if not token:
        return None
    try:
        return int(token, 0)
    except ValueError:
        try:
            return int(token, 16)
        except ValueError:
            return None


def _normalize_method_name(name: str) -> str:
    v = (name or "").strip()
    if "::" in v:
        v = v.rsplit("::", 1)[1]
    if "(" in v:
        v = v.split("(", 1)[0]
    return v.strip()


def _looks_thiscall(fn) -> bool:
    try:
        cc = str(fn.getCallingConventionName() or "").lower()
    except Exception:
        cc = ""
    if "thiscall" in cc:
        return True
    try:
        sig = str(fn.getSignature() or "").lower()
    except Exception:
        sig = ""
    return "__thiscall" in sig


def run(
    project_root: Path,
    *,
    vtable_matches_csv: Path,
    macos_fingerprints_csv: Path,
    out_csv: Path,
    min_name_similarity: float,
    max_classes: int,
) -> dict[str, int]:
    vtable_rows = load_csv_rows(vtable_matches_csv)
    class_vfuncs: dict[str, list[tuple[int, str]]] = defaultdict(list)
    for row in vtable_rows:
        cls = (row.get("mac_class") or "").strip()
        addr = _parse_addr(row.get("win_func_addr") or "")
        method = (row.get("mac_method_name") or "").strip()
        if not cls or addr is None:
            continue
        class_vfuncs[cls].append((addr, method))

    mac_rows = load_csv_rows(macos_fingerprints_csv)
    class_methods: dict[str, set[str]] = defaultdict(set)
    for row in mac_rows:
        cls = (row.get("class_name") or "").strip()
        fn_name = (row.get("func_name") or "").strip()
        if not cls or not fn_name:
            continue
        class_methods[cls].add(_normalize_method_name(fn_name))

    classes = sorted(class_vfuncs.keys())
    if max_classes > 0:
        classes = classes[:max_classes]

    with open_program(project_root) as program:
        from ghidra.program.model.pcode import PcodeOp

        fm = program.getFunctionManager()
        af = program.getAddressFactory().getDefaultAddressSpace()
        ifc = create_configured_decompiler(program)
        try:
            proposals: dict[int, dict[str, str]] = {}
            for idx, cls in enumerate(classes, start=1):
                method_pool = sorted(class_methods.get(cls, set()))
                if not method_pool:
                    continue
                for addr, parent_method in class_vfuncs.get(cls, []):
                    fn = fm.getFunctionAt(af.getAddress(f"{addr:08x}"))
                    if fn is None:
                        continue
                    res = decompile_function(ifc, fn, timeout=30)
                    if res is None:
                        continue
                    high_fn = res.getHighFunction()
                    if high_fn is None:
                        continue
                    param0 = collect_param0_varnodes(high_fn, fn, PcodeOp)
                    op_it = high_fn.getPcodeOps()
                    while op_it.hasNext():
                        op = op_it.next()
                        if int(op.getOpcode()) != PcodeOp.CALL:
                            continue
                        if op.getNumInputs() <= 1:
                            continue

                        this_passed = False
                        for i in range(1, op.getNumInputs()):
                            if trace_to_param0(op.getInput(i), param0, PcodeOp):
                                this_passed = True
                                break
                        if not this_passed:
                            continue

                        target = op.getInput(0)
                        target_addr = None
                        try:
                            if target is not None and (target.isAddress() or target.isConstant()):
                                target_addr = int(target.getOffset()) & 0xFFFFFFFF
                        except Exception:
                            target_addr = None
                        if target_addr is None:
                            continue
                        callee = fm.getFunctionAt(af.getAddress(f"{target_addr:08x}"))
                        if callee is None:
                            continue
                        callee_name = str(callee.getName())
                        if not is_unresolved_name(callee_name):
                            continue
                        if not _looks_thiscall(callee):
                            continue

                        probe_name = callee_name.replace("thunk_", "").replace("FUN_", "")
                        best_name = ""
                        best_ratio = 0.0
                        for candidate in method_pool:
                            ratio = difflib.SequenceMatcher(None, probe_name, candidate).ratio()
                            if ratio > best_ratio:
                                best_ratio = ratio
                                best_name = candidate
                        if best_ratio < min_name_similarity or not best_name:
                            continue

                        cur = proposals.get(target_addr)
                        evidence = (
                            f"thiscall_from=0x{addr:08x}:{_normalize_method_name(parent_method)};"
                            f"sim={best_ratio:.3f}"
                        )
                        proposal = {
                            "address": f"0x{target_addr:08x}",
                            "name": callee_name,
                            "class_name": cls,
                            "proposed_name": best_name,
                            "confidence": f"{best_ratio:.3f}",
                            "evidence": evidence,
                        }
                        if cur is None or float(proposal["confidence"]) > float(cur["confidence"]):
                            proposals[target_addr] = proposal

                if idx % 20 == 0 or idx == len(classes):
                    print(f"[propagate_class_by_callgraph] classes={idx}/{len(classes)}")
        finally:
            ifc.dispose()

    out_rows = [proposals[k] for k in sorted(proposals.keys())]
    write_csv_rows(
        out_csv,
        out_rows,
        ["address", "name", "class_name", "proposed_name", "confidence", "evidence"],
    )
    print(f"[propagate_class_by_callgraph] rows={len(out_rows)} -> {out_csv}")
    return {"rows": len(out_rows), "class_count": len(classes)}

