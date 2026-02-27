#!/usr/bin/env python3
"""
Reusable class-attachment/signature wave toolset.

Implements six high-yield lanes:
  1) thiscall + typed pThis ownership sweep
  2) unique caller-class ownership sweep
  3) multi-hop thunk-chain ownership sweep
  4) inferred vtable-table backfill sweep
  5) UI message-handler ownership sweep
  6) class-lane signature-clone propagation

Usage examples:
  .venv/bin/python new_scripts/class_attachment_wave_tools.py thiscall-pthis
  .venv/bin/python new_scripts/class_attachment_wave_tools.py caller-owner --apply
  .venv/bin/python new_scripts/class_attachment_wave_tools.py thunk-chain --apply --max-depth 3
  .venv/bin/python new_scripts/class_attachment_wave_tools.py inferred-vtbl --apply
  .venv/bin/python new_scripts/class_attachment_wave_tools.py ui-msg --apply
  .venv/bin/python new_scripts/class_attachment_wave_tools.py sig-clone --apply
  .venv/bin/python new_scripts/class_attachment_wave_tools.py all --apply
"""

from __future__ import annotations

import argparse
import re
import time
from collections import defaultdict
from pathlib import Path

import pyghidra

GHIDRA_DIR = Path(
    "/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC"
)
PROJECT_NAME = "imperialism-decomp"
PROGRAM_PATH = "/Imperialism.exe"
UI_NS_RE = re.compile(r"(View|Dialog|Window|Control|Frame|Doc|Toolbar|Panel|Map)", re.IGNORECASE)
UI_FN_RE = re.compile(
    r"(OnMsg|OnCommand|OnNotify|WndProc|DialogProc|Handle.*(Msg|Command|Notify)|WM_|ID_)",
    re.IGNORECASE,
)


def open_project_with_lock_cleanup(root: Path):
    try:
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)
    except Exception:
        for lock_file in (root / f"{PROJECT_NAME}.lock", root / f"{PROJECT_NAME}.lock~"):
            if lock_file.exists():
                lock_file.unlink()
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)


def addr_u32(addr) -> int:
    return int(addr.getOffset() & 0xFFFFFFFF)


def addr_hex(v: int) -> str:
    return f"0x{v:08x}"


def is_global_ns(ns, global_ns) -> bool:
    return ns is None or ns == global_ns or ns.getName() == "Global"


def get_functions(program):
    fm = program.getFunctionManager()
    out = []
    it = fm.getFunctions(True)
    while it.hasNext():
        out.append(it.next())
    return out


def get_class_map(program):
    st = program.getSymbolTable()
    out = {}
    it = st.getClassNamespaces()
    while it.hasNext():
        ns = it.next()
        out[ns.getName()] = ns
    return out


def get_function_by_u32(program, ep_u32: int):
    af = program.getAddressFactory().getDefaultAddressSpace()
    fm = program.getFunctionManager()
    return fm.getFunctionAt(af.getAddress(addr_hex(ep_u32)))


def get_instructions(listing, body):
    out = []
    it = listing.getInstructions(body, True)
    while it.hasNext():
        out.append(it.next())
    return out


def resolve_first_internal_target(fm, ins):
    refs = ins.getReferencesFrom()
    for ref in refs:
        callee = fm.getFunctionAt(ref.getToAddress())
        if callee is None:
            continue
        ep_txt = str(callee.getEntryPoint())
        if ep_txt.startswith("EXTERNAL:"):
            continue
        return callee
    return None


def detect_simple_forward_target(program, func):
    listing = program.getListing()
    fm = program.getFunctionManager()
    insns = get_instructions(listing, func.getBody())
    if len(insns) == 1 and str(insns[0].getMnemonicString()).upper() == "JMP":
        tgt = resolve_first_internal_target(fm, insns[0])
        return tgt, "JMP"
    if (
        len(insns) == 2
        and str(insns[0].getMnemonicString()).upper() == "CALL"
        and str(insns[1].getMnemonicString()).upper() == "RET"
    ):
        tgt = resolve_first_internal_target(fm, insns[0])
        return tgt, "CALL_RET"
    return None, None


def get_calling_class_counts(program, target_func):
    rm = program.getReferenceManager()
    listing = program.getListing()
    fm = program.getFunctionManager()
    class_counts: dict[str, int] = defaultdict(int)
    total_calls = 0

    refs = rm.getReferencesTo(target_func.getEntryPoint())
    while refs.hasNext():
        ref = refs.next()
        from_addr = ref.getFromAddress()
        ins = listing.getInstructionAt(from_addr)
        if ins is None:
            continue
        if str(ins.getMnemonicString()).upper() != "CALL":
            continue
        caller = fm.getFunctionContaining(from_addr)
        if caller is None:
            continue
        ns = caller.getParentNamespace()
        if ns is None:
            continue
        total_calls += 1
        class_counts[ns.getName()] += 1
    return class_counts, total_calls


def extract_first_param_class_name(func, class_map: dict[str, object]) -> str | None:
    params = list(func.getParameters())
    if not params:
        return None
    p0 = params[0]
    p0_name = p0.getName() or ""
    dt = p0.getDataType()

    # Prefer explicit pThis naming when available.
    if p0_name.lower() not in ("pthis", "this"):
        # Keep permissive fallback for thiscall with typed first param.
        if func.getCallingConventionName() != "__thiscall":
            return None

    # Pointer type in Ghidra has getDataType().
    base_name = None
    if hasattr(dt, "getDataType"):
        try:
            base = dt.getDataType()
            if base is not None:
                base_name = base.getName()
        except Exception:
            base_name = None
    if not base_name:
        dt_name = dt.getName()
        base_name = dt_name.replace("*", "").strip()

    if not base_name or not base_name.startswith("T"):
        return None
    if base_name not in class_map:
        return None
    return base_name


def clone_callee_signature_to(program, src_func, callee_func):
    from ghidra.program.model.listing import Function, ParameterImpl
    from ghidra.program.model.symbol import SourceType

    cc = callee_func.getCallingConventionName()
    if cc:
        src_func.setCallingConvention(cc)
    src_func.setReturnType(callee_func.getReturnType(), SourceType.USER_DEFINED)

    params = []
    callee_params = callee_func.getParameters()
    for i in range(len(callee_params)):
        p = callee_params[i]
        nm = p.getName() or f"param_{i+1}"
        params.append(ParameterImpl(nm, p.getDataType(), program, SourceType.USER_DEFINED))

    src_func.replaceParameters(
        Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
        True,
        SourceType.USER_DEFINED,
        params,
    )


def apply_namespace_moves(program, rows, tx_name: str, save_name: str):
    """
    rows: list[(func_obj, class_ns_obj)]
    """
    tx = program.startTransaction(tx_name)
    ok = 0
    skip = 0
    fail = 0
    try:
        for func, class_ns in rows:
            try:
                if func.getParentNamespace() == class_ns:
                    skip += 1
                    continue
                func.setParentNamespace(class_ns)
                ok += 1
            except Exception as ex:
                fail += 1
                print(f"[fail] {func.getEntryPoint()} {func.getName()} -> {class_ns.getName()} err={ex}")
    finally:
        program.endTransaction(tx, True)

    if ok > 0:
        program.save(save_name, None)
    return ok, skip, fail


def stage_thiscall_pthis(program, args):
    class_map = get_class_map(program)
    global_ns = program.getGlobalNamespace()

    candidates = []
    skip_conflict = 0
    for f in get_functions(program):
        if not is_global_ns(f.getParentNamespace(), global_ns):
            continue
        if f.getCallingConventionName() != "__thiscall":
            continue
        cls_name = extract_first_param_class_name(f, class_map)
        if not cls_name:
            continue
        class_counts, total_calls = get_calling_class_counts(program, f)
        caller_classes = {k for k in class_counts.keys() if k in class_map}
        if caller_classes and (caller_classes - {cls_name}):
            skip_conflict += 1
            continue
        candidates.append((f, class_map[cls_name], cls_name, total_calls))

    print(
        f"[thiscall-pthis] candidates={len(candidates)} "
        f"skip_conflict={skip_conflict}"
    )
    for f, _ns, cname, calls in candidates[: args.max_print]:
        print(f"  {f.getEntryPoint()} {f.getName()} -> {cname} callers={calls}")
    if len(candidates) > args.max_print:
        print(f"  ... ({len(candidates) - args.max_print} more)")

    if not args.apply:
        return
    rows = [(f, ns) for f, ns, _c, _calls in candidates]
    ok, skip, fail = apply_namespace_moves(
        program,
        rows,
        "Attach class by thiscall+pThis ownership",
        "attach class by thiscall+pThis ownership",
    )
    print(f"[thiscall-pthis:done] ok={ok} skip={skip} fail={fail}")


def stage_caller_owner(program, args):
    class_map = get_class_map(program)
    global_ns = program.getGlobalNamespace()
    deny_re = re.compile(args.name_deny_regex) if args.name_deny_regex else None

    candidates = []
    for f in get_functions(program):
        if not is_global_ns(f.getParentNamespace(), global_ns):
            continue
        if deny_re and deny_re.search(f.getName()):
            continue
        class_counts, total_calls = get_calling_class_counts(program, f)
        class_counts = {k: v for k, v in class_counts.items() if k in class_map}
        class_call_total = sum(class_counts.values())
        if class_call_total < args.min_class_calls:
            continue
        dom_class, dom_count = max(class_counts.items(), key=lambda kv: kv[1])
        dom_ratio = dom_count / float(class_call_total)
        if dom_ratio < args.min_owner_ratio:
            continue
        candidates.append((f, class_map[dom_class], dom_class, dom_count, class_call_total, dom_ratio))

    print(
        f"[caller-owner] candidates={len(candidates)} "
        f"min_calls={args.min_class_calls} min_ratio={args.min_owner_ratio:.2f}"
    )
    for f, _ns, cname, dom, total, ratio in candidates[: args.max_print]:
        print(f"  {f.getEntryPoint()} {f.getName()} -> {cname} dom={dom}/{total} ratio={ratio:.2f}")
    if len(candidates) > args.max_print:
        print(f"  ... ({len(candidates) - args.max_print} more)")

    if not args.apply:
        return
    rows = [(f, ns) for f, ns, _c, _dom, _total, _ratio in candidates]
    ok, skip, fail = apply_namespace_moves(
        program,
        rows,
        "Attach class by caller ownership",
        "attach class by caller ownership",
    )
    print(f"[caller-owner:done] ok={ok} skip={skip} fail={fail}")


def stage_thunk_chain(program, args):
    class_map = get_class_map(program)
    global_ns = program.getGlobalNamespace()

    func_by_ep = {}
    for f in get_functions(program):
        func_by_ep[addr_u32(f.getEntryPoint())] = f

    forward_map = {}
    for f in func_by_ep.values():
        tgt, shape = detect_simple_forward_target(program, f)
        if tgt is None:
            continue
        forward_map[addr_u32(f.getEntryPoint())] = (addr_u32(tgt.getEntryPoint()), shape)

    owners: dict[int, set[str]] = defaultdict(set)
    sample: dict[int, tuple[str, int, int]] = {}

    for src_ep, src in func_by_ep.items():
        src_ns = src.getParentNamespace()
        if is_global_ns(src_ns, global_ns):
            continue
        src_class = src_ns.getName()
        if src_class not in class_map:
            continue

        cur = src_ep
        visited = {cur}
        chain_depth = 0
        terminal = None
        while chain_depth < args.max_depth:
            nxt = forward_map.get(cur)
            if not nxt:
                break
            to_ep, _shape = nxt
            terminal = to_ep
            if to_ep in visited:
                break
            visited.add(to_ep)
            cur = to_ep
            chain_depth += 1

        if terminal is None or chain_depth < args.min_hops:
            continue
        tgt = func_by_ep.get(terminal)
        if tgt is None:
            tgt = get_function_by_u32(program, terminal)
        if tgt is None:
            continue
        if not is_global_ns(tgt.getParentNamespace(), global_ns):
            continue

        owners[terminal].add(src_class)
        if terminal not in sample:
            sample[terminal] = (src_class, src_ep, chain_depth)

    unique = []
    ambiguous = 0
    for ep, cls_set in owners.items():
        if len(cls_set) != 1:
            ambiguous += 1
            continue
        cls_name = next(iter(cls_set))
        tgt = func_by_ep.get(ep) or get_function_by_u32(program, ep)
        if tgt is None:
            continue
        src_class, src_ep, depth = sample.get(ep, (cls_name, 0, 0))
        unique.append((tgt, class_map[cls_name], cls_name, src_ep, depth))

    print(
        f"[thunk-chain] forwarders={len(forward_map)} owned_targets={len(owners)} "
        f"unique={len(unique)} ambiguous={ambiguous}"
    )
    for tgt, _ns, cname, src_ep, depth in unique[: args.max_print]:
        print(
            f"  {tgt.getEntryPoint()} {tgt.getName()} -> {cname} "
            f"via={addr_hex(src_ep)} hops={depth}"
        )
    if len(unique) > args.max_print:
        print(f"  ... ({len(unique) - args.max_print} more)")

    if not args.apply:
        return
    rows = [(tgt, ns) for tgt, ns, _c, _src, _d in unique]
    ok, skip, fail = apply_namespace_moves(
        program,
        rows,
        "Attach class by multi-hop thunk ownership",
        "attach class by multi-hop thunk ownership",
    )
    print(f"[thunk-chain:done] ok={ok} skip={skip} fail={fail}")


def stage_inferred_vtbl(program, args):
    class_map = get_class_map(program)
    st = program.getSymbolTable()
    mem = program.getMemory()
    fm = program.getFunctionManager()
    global_ns = program.getGlobalNamespace()
    af = program.getAddressFactory().getDefaultAddressSpace()

    # Candidate starts from DAT_* labels only (conservative and bounded).
    starts = []
    sit = st.getAllSymbols(True)
    while sit.hasNext():
        sym = sit.next()
        n = sym.getName()
        if not n.startswith("DAT_"):
            continue
        if n.startswith("g_vtbl"):
            continue
        starts.append(addr_u32(sym.getAddress()))

    owners: dict[int, set[str]] = defaultdict(set)
    sample: dict[int, tuple[int, str, int, int, int]] = {}
    tables_seen = 0

    for s in starts:
        funcs = []
        holes = 0
        for i in range(args.max_slots):
            slot = s + i * 4
            try:
                ptr = mem.getInt(af.getAddress(addr_hex(slot))) & 0xFFFFFFFF
            except Exception:
                holes += 1
                if holes > args.max_hole_run:
                    break
                continue
            tgt = fm.getFunctionAt(af.getAddress(addr_hex(ptr)))
            if tgt is None or addr_u32(tgt.getEntryPoint()) != ptr:
                holes += 1
                if holes > args.max_hole_run:
                    break
                continue
            holes = 0
            funcs.append(tgt)

        if len(funcs) < args.min_slots:
            continue
        tables_seen += 1
        class_counts = defaultdict(int)
        globals_in_table = []
        for f in funcs:
            ns = f.getParentNamespace()
            if is_global_ns(ns, global_ns):
                globals_in_table.append(f)
                continue
            ns_name = ns.getName()
            if ns_name in class_map:
                class_counts[ns_name] += 1
        if not class_counts:
            continue
        dom_class, dom_count = max(class_counts.items(), key=lambda kv: kv[1])
        total_class_hits = sum(class_counts.values())
        dom_ratio = dom_count / float(total_class_hits)
        if dom_count < args.min_class_hits or dom_ratio < args.min_dom_ratio:
            continue
        for g in globals_in_table:
            ep = addr_u32(g.getEntryPoint())
            owners[ep].add(dom_class)
            if ep not in sample:
                sample[ep] = (s, dom_class, dom_count, total_class_hits, len(funcs))

    unique = []
    ambiguous = 0
    for ep, cls_set in owners.items():
        if len(cls_set) != 1:
            ambiguous += 1
            continue
        cls = next(iter(cls_set))
        f = get_function_by_u32(program, ep)
        if f is None:
            continue
        if not is_global_ns(f.getParentNamespace(), global_ns):
            continue
        s, _c, dom, hits, slots = sample.get(ep, (0, cls, 0, 0, 0))
        unique.append((f, class_map[cls], cls, s, dom, hits, slots))

    print(
        f"[inferred-vtbl] start_symbols={len(starts)} tables_seen={tables_seen} "
        f"owned_targets={len(owners)} unique={len(unique)} ambiguous={ambiguous}"
    )
    for f, _ns, cls, s, dom, hits, slots in unique[: args.max_print]:
        print(
            f"  {f.getEntryPoint()} {f.getName()} -> {cls} "
            f"table={addr_hex(s)} dom={dom}/{hits} slots={slots}"
        )
    if len(unique) > args.max_print:
        print(f"  ... ({len(unique) - args.max_print} more)")

    if not args.apply:
        return
    rows = [(f, ns) for f, ns, _c, _s, _dom, _hits, _slots in unique]
    ok, skip, fail = apply_namespace_moves(
        program,
        rows,
        "Attach class by inferred vtable tables",
        "attach class by inferred vtable tables",
    )
    print(f"[inferred-vtbl:done] ok={ok} skip={skip} fail={fail}")


def stage_ui_msg(program, args):
    class_map = get_class_map(program)
    global_ns = program.getGlobalNamespace()
    deny_re = re.compile(args.name_deny_regex) if args.name_deny_regex else None

    candidates = []
    for f in get_functions(program):
        if not is_global_ns(f.getParentNamespace(), global_ns):
            continue
        nm = f.getName()
        if deny_re and deny_re.search(nm):
            continue
        if not UI_FN_RE.search(nm):
            continue
        class_counts, _total_calls = get_calling_class_counts(program, f)
        class_counts = {
            k: v for k, v in class_counts.items() if (k in class_map and UI_NS_RE.search(k))
        }
        class_call_total = sum(class_counts.values())
        if class_call_total < args.min_class_calls:
            continue
        dom_class, dom_count = max(class_counts.items(), key=lambda kv: kv[1])
        dom_ratio = dom_count / float(class_call_total)
        if dom_ratio < args.min_owner_ratio:
            continue
        candidates.append((f, class_map[dom_class], dom_class, dom_count, class_call_total, dom_ratio))

    print(
        f"[ui-msg] candidates={len(candidates)} "
        f"min_calls={args.min_class_calls} min_ratio={args.min_owner_ratio:.2f}"
    )
    for f, _ns, cname, dom, total, ratio in candidates[: args.max_print]:
        print(f"  {f.getEntryPoint()} {f.getName()} -> {cname} dom={dom}/{total} ratio={ratio:.2f}")
    if len(candidates) > args.max_print:
        print(f"  ... ({len(candidates) - args.max_print} more)")

    if not args.apply:
        return
    rows = [(f, ns) for f, ns, _c, _dom, _total, _ratio in candidates]
    ok, skip, fail = apply_namespace_moves(
        program,
        rows,
        "Attach UI msg handlers by dispatch ownership",
        "attach UI msg handlers by dispatch ownership",
    )
    print(f"[ui-msg:done] ok={ok} skip={skip} fail={fail}")


def stage_sig_clone(program, args):
    class_map = get_class_map(program)
    global_ns = program.getGlobalNamespace()

    candidates = []
    for f in get_functions(program):
        if not is_global_ns(f.getParentNamespace(), global_ns):
            continue
        callee, shape = detect_simple_forward_target(program, f)
        if callee is None:
            continue
        callee_ns = callee.getParentNamespace()
        if is_global_ns(callee_ns, global_ns):
            continue
        callee_class = callee_ns.getName()
        if callee_class not in class_map:
            continue
        src_sig = str(f.getSignature())
        callee_sig = str(callee.getSignature())
        if callee_sig.startswith("undefined "):
            continue
        if (not args.force_defined) and (not src_sig.startswith("undefined ")):
            continue
        candidates.append((f, callee, class_map[callee_class], callee_class, shape))

    print(f"[sig-clone] candidates={len(candidates)}")
    for f, callee, _ns, cls, shape in candidates[: args.max_print]:
        print(
            f"  {f.getEntryPoint()} {shape} {f.getName()} -> "
            f"{cls}::{callee.getName()}"
        )
    if len(candidates) > args.max_print:
        print(f"  ... ({len(candidates) - args.max_print} more)")

    if not args.apply:
        return

    tx = program.startTransaction("Class-lane signature clone propagation")
    sig_ok = 0
    sig_skip = 0
    sig_fail = 0
    ns_ok = 0
    ns_skip = 0
    ns_fail = 0
    try:
        for src, callee, class_ns, _cls, _shape in candidates:
            try:
                old_sig = str(src.getSignature())
                clone_callee_signature_to(program, src, callee)
                if str(src.getSignature()) == old_sig:
                    sig_skip += 1
                else:
                    sig_ok += 1
            except Exception as ex:
                sig_fail += 1
                print(f"[sig-fail] {src.getEntryPoint()} {src.getName()} err={ex}")
                continue

            if args.attach_namespace:
                try:
                    if src.getParentNamespace() == class_ns:
                        ns_skip += 1
                    else:
                        src.setParentNamespace(class_ns)
                        ns_ok += 1
                except Exception as ex:
                    ns_fail += 1
                    print(f"[ns-fail] {src.getEntryPoint()} {src.getName()} -> {class_ns.getName()} err={ex}")
    finally:
        program.endTransaction(tx, True)

    if sig_ok > 0 or ns_ok > 0:
        program.save("class-lane signature clone propagation", None)
    print(
        f"[sig-clone:done] sig_ok={sig_ok} sig_skip={sig_skip} sig_fail={sig_fail} "
        f"ns_ok={ns_ok} ns_skip={ns_skip} ns_fail={ns_fail}"
    )


def add_common_args(sp):
    sp.add_argument("--apply", action="store_true", help="Write changes")
    sp.add_argument("--max-print", type=int, default=120)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    ap.add_argument(
        "--sleep-after-apply",
        type=float,
        default=0.5,
        help="Sleep seconds after each apply stage (lock-safety pacing)",
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    s1 = sub.add_parser("thiscall-pthis", help="1) thiscall + typed pThis ownership sweep")
    add_common_args(s1)

    s2 = sub.add_parser("caller-owner", help="2) unique caller-class ownership sweep")
    add_common_args(s2)
    s2.add_argument("--min-class-calls", type=int, default=3)
    s2.add_argument("--min-owner-ratio", type=float, default=0.90)
    s2.add_argument("--name-deny-regex", default=r"^(thunk_|WrapperFor_|FUN_)")

    s3 = sub.add_parser("thunk-chain", help="3) multi-hop thunk-chain ownership sweep")
    add_common_args(s3)
    s3.add_argument("--max-depth", type=int, default=3)
    s3.add_argument("--min-hops", type=int, default=2)

    s4 = sub.add_parser("inferred-vtbl", help="4) inferred vtable-table backfill sweep")
    add_common_args(s4)
    s4.add_argument("--min-slots", type=int, default=8)
    s4.add_argument("--max-slots", type=int, default=120)
    s4.add_argument("--max-hole-run", type=int, default=4)
    s4.add_argument("--min-class-hits", type=int, default=6)
    s4.add_argument("--min-dom-ratio", type=float, default=0.80)

    s5 = sub.add_parser("ui-msg", help="5) UI message-handler ownership sweep")
    add_common_args(s5)
    s5.add_argument("--min-class-calls", type=int, default=2)
    s5.add_argument("--min-owner-ratio", type=float, default=0.80)
    s5.add_argument("--name-deny-regex", default=r"^(thunk_|WrapperFor_|FUN_)")

    s6 = sub.add_parser("sig-clone", help="6) class-lane signature-clone propagation")
    add_common_args(s6)
    s6.add_argument("--force-defined", action="store_true", help="Also process already-defined source signatures")
    s6.add_argument("--attach-namespace", action="store_true", default=True)
    s6.add_argument("--no-attach-namespace", dest="attach_namespace", action="store_false")

    sall = sub.add_parser("all", help="Run stages 1..6 sequentially")
    add_common_args(sall)
    sall.add_argument("--min-class-calls", type=int, default=3)
    sall.add_argument("--min-owner-ratio", type=float, default=0.90)
    sall.add_argument("--name-deny-regex", default=r"^(thunk_|WrapperFor_|FUN_)")
    sall.add_argument("--max-depth", type=int, default=3)
    sall.add_argument("--min-hops", type=int, default=2)
    sall.add_argument("--min-slots", type=int, default=8)
    sall.add_argument("--max-slots", type=int, default=120)
    sall.add_argument("--max-hole-run", type=int, default=4)
    sall.add_argument("--min-class-hits", type=int, default=6)
    sall.add_argument("--min-dom-ratio", type=float, default=0.80)
    sall.add_argument("--ui-min-class-calls", type=int, default=2)
    sall.add_argument("--ui-min-owner-ratio", type=float, default=0.80)
    sall.add_argument("--force-defined", action="store_true")
    sall.add_argument("--attach-namespace", action="store_true", default=True)
    sall.add_argument("--no-attach-namespace", dest="attach_namespace", action="store_false")

    args = ap.parse_args()
    root = Path(args.project_root).resolve()

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        if args.cmd == "thiscall-pthis":
            stage_thiscall_pthis(program, args)
            return 0
        if args.cmd == "caller-owner":
            stage_caller_owner(program, args)
            return 0
        if args.cmd == "thunk-chain":
            stage_thunk_chain(program, args)
            return 0
        if args.cmd == "inferred-vtbl":
            stage_inferred_vtbl(program, args)
            return 0
        if args.cmd == "ui-msg":
            stage_ui_msg(program, args)
            return 0
        if args.cmd == "sig-clone":
            stage_sig_clone(program, args)
            return 0

        if args.cmd == "all":
            # Stage 1
            stage_thiscall_pthis(program, args)
            if args.apply:
                time.sleep(args.sleep_after_apply)

            # Stage 2
            stage_caller_owner(program, args)
            if args.apply:
                time.sleep(args.sleep_after_apply)

            # Stage 3
            stage_thunk_chain(program, args)
            if args.apply:
                time.sleep(args.sleep_after_apply)

            # Stage 4
            stage_inferred_vtbl(program, args)
            if args.apply:
                time.sleep(args.sleep_after_apply)

            # Stage 5: adapt UI thresholds from all-subcommand args.
            ui_args = argparse.Namespace(**vars(args))
            ui_args.min_class_calls = args.ui_min_class_calls
            ui_args.min_owner_ratio = args.ui_min_owner_ratio
            stage_ui_msg(program, ui_args)
            if args.apply:
                time.sleep(args.sleep_after_apply)

            # Stage 6
            stage_sig_clone(program, args)
            return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
