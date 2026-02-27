#!/usr/bin/env python3
"""
Attach likely class methods by caller-class ownership (no thiscall requirement).

Flow:
1) Scan global functions and compute direct CALL ownership by class namespaces.
2) Keep candidates where dominant class ratio and class-call count pass thresholds.
3) Optionally resolve wrapper/forwarder chains (JMP or CALL;RET) to terminal impl.
4) Attach terminal impl to dominant class namespace.

Safety gates:
- Global target only (unless --allow-non-global)
- Name deny regex to avoid CRT/WinAPI/FID noise
- Minimum class calls and dominant ratio thresholds

Usage:
  .venv/bin/python new_scripts/attach_impls_by_caller_ownership.py
  .venv/bin/python new_scripts/attach_impls_by_caller_ownership.py --apply
"""

from __future__ import annotations

import argparse
import re
from collections import defaultdict
from pathlib import Path

import pyghidra

GHIDRA_DIR = Path(
    "/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC"
)
PROJECT_NAME = "imperialism-decomp"
PROGRAM_PATH = "/Imperialism.exe"
DEFAULT_DENY = (
    r"^(thunk_|WrapperFor_|FUN_|Dtor_|Ctor_|FID_conflict|`|"
    r"operator|Afx|_mem|_str|_mb|memset|memcpy|memcmp|strlen|strcpy|strcat|strcmp|"
    r"GetProcAddress|LoadLibrary|CreateWindow|DestroyWindow|SendMessage|PostMessage|"
    r"TranslateMessage|DispatchMessage|PeekMessage|DefWindowProc|BeginPaint|EndPaint|"
    r"SetWindow|GetWindow|ShowWindow|MoveWindow|EnableWindow|UpdateWindow|"
    r"SetTimer|KillTimer|MessageBox|wsprintf|sprintf|printf|fopen|fclose|fread|fwrite|"
    r"fseek|ftell|malloc|free|realloc|new|delete)$"
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


def parse_int(text: str) -> int:
    t = text.strip().lower()
    if t.startswith("0x"):
        return int(t, 16)
    return int(t, 10)


def is_global_ns(ns, global_ns) -> bool:
    return ns is None or ns == global_ns or ns.getName() == "Global"


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


def simple_forward_target(program, func):
    listing = program.getListing()
    fm = program.getFunctionManager()
    insns = get_instructions(listing, func.getBody())
    if len(insns) == 1 and str(insns[0].getMnemonicString()).upper() == "JMP":
        return resolve_first_internal_target(fm, insns[0]), "JMP"
    if (
        len(insns) == 2
        and str(insns[0].getMnemonicString()).upper() == "CALL"
        and str(insns[1].getMnemonicString()).upper() == "RET"
    ):
        return resolve_first_internal_target(fm, insns[0]), "CALL_RET"
    return None, None


def get_functions(program):
    fm = program.getFunctionManager()
    out = []
    it = fm.getFunctions(True)
    while it.hasNext():
        out.append(it.next())
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true", help="Write namespace changes")
    ap.add_argument("--min-class-calls", type=int, default=2)
    ap.add_argument("--min-owner-ratio", type=float, default=0.75)
    ap.add_argument("--max-depth", type=int, default=4, help="Forwarder-chain max depth")
    ap.add_argument("--allow-non-global", action="store_true")
    ap.add_argument("--attach-source-too", action="store_true", help="Also attach source wrapper/function")
    ap.add_argument("--name-deny-regex", default=DEFAULT_DENY)
    ap.add_argument("--owner-class-regex", default="", help="Optional regex to keep dominant owner classes")
    ap.add_argument("--start", default="", help="Optional function entry start filter (hex/dec)")
    ap.add_argument("--end", default="", help="Optional function entry end filter (hex/dec), exclusive")
    ap.add_argument("--max-print", type=int, default=120)
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    deny_re = re.compile(args.name_deny_regex) if args.name_deny_regex else None
    owner_re = re.compile(args.owner_class_regex) if args.owner_class_regex else None
    start = parse_int(args.start) if args.start else None
    end = parse_int(args.end) if args.end else None
    root = Path(args.project_root).resolve()

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        fm = program.getFunctionManager()
        rm = program.getReferenceManager()
        listing = program.getListing()
        st = program.getSymbolTable()
        global_ns = program.getGlobalNamespace()

        class_map = {}
        it_cls = st.getClassNamespaces()
        while it_cls.hasNext():
            ns = it_cls.next()
            class_map[ns.getName()] = ns

        funcs = get_functions(program)
        by_ep = {addr_u32(f.getEntryPoint()): f for f in funcs}

        candidates = []
        for f in funcs:
            f_addr = addr_u32(f.getEntryPoint())
            if start is not None and f_addr < start:
                continue
            if end is not None and f_addr >= end:
                continue
            if not is_global_ns(f.getParentNamespace(), global_ns):
                continue
            if deny_re and deny_re.search(f.getName()):
                continue

            class_counts = defaultdict(int)
            refs = rm.getReferencesTo(f.getEntryPoint())
            while refs.hasNext():
                ref = refs.next()
                from_addr = ref.getFromAddress()
                ins = listing.getInstructionAt(from_addr)
                if ins is None or str(ins.getMnemonicString()).upper() != "CALL":
                    continue
                caller = fm.getFunctionContaining(from_addr)
                if caller is None:
                    continue
                ns = caller.getParentNamespace()
                if ns is None:
                    continue
                nsn = ns.getName()
                if nsn in class_map:
                    class_counts[nsn] += 1

            class_total = sum(class_counts.values())
            if class_total < args.min_class_calls:
                continue
            dom_class, dom_calls = max(class_counts.items(), key=lambda kv: kv[1])
            if owner_re and not owner_re.search(dom_class):
                continue
            dom_ratio = dom_calls / float(class_total)
            if dom_ratio < args.min_owner_ratio:
                continue

            cur = f
            hops = 0
            seen = {addr_u32(f.getEntryPoint())}
            while hops < args.max_depth:
                nxt, _shape = simple_forward_target(program, cur)
                if nxt is None:
                    break
                ep = addr_u32(nxt.getEntryPoint())
                if ep in seen:
                    break
                seen.add(ep)
                cur = nxt
                hops += 1

            tgt = cur
            if deny_re and deny_re.search(tgt.getName()):
                continue
            if (not args.allow_non_global) and (not is_global_ns(tgt.getParentNamespace(), global_ns)):
                continue

            candidates.append(
                {
                    "source": f,
                    "target": tgt,
                    "dom_class": dom_class,
                    "dom_calls": dom_calls,
                    "class_total": class_total,
                    "ratio": dom_ratio,
                    "hops": hops,
                }
            )

        # Dedup by target address, keep strongest ownership score.
        dedup = {}
        for c in candidates:
            key = addr_u32(c["target"].getEntryPoint())
            old = dedup.get(key)
            if old is None:
                dedup[key] = c
                continue
            old_score = (old["ratio"], old["dom_calls"], old["class_total"])
            new_score = (c["ratio"], c["dom_calls"], c["class_total"])
            if new_score > old_score:
                dedup[key] = c
        plans = [dedup[k] for k in sorted(dedup.keys())]

        print(
            f"[candidates] raw={len(candidates)} dedup_targets={len(plans)} "
            f"min_calls={args.min_class_calls} min_ratio={args.min_owner_ratio:.2f}"
        )
        for c in plans[: args.max_print]:
            src = c["source"]
            tgt = c["target"]
            print(
                f"  {src.getEntryPoint()} {src.getName()} -> "
                f"{tgt.getEntryPoint()} {tgt.getName()} -> {c['dom_class']} "
                f"dom={c['dom_calls']}/{c['class_total']} ratio={c['ratio']:.2f} hops={c['hops']}"
            )
        if len(plans) > args.max_print:
            print(f"  ... ({len(plans) - args.max_print} more)")

        if not args.apply:
            print("[dry-run] pass --apply to write changes")
            return 0

        tx = program.startTransaction("Attach impls by caller ownership")
        ok = skip = fail = 0
        src_ok = src_skip = src_fail = 0
        try:
            for c in plans:
                tgt = c["target"]
                cls_ns = class_map[c["dom_class"]]
                try:
                    if tgt.getParentNamespace() == cls_ns:
                        skip += 1
                    else:
                        tgt.setParentNamespace(cls_ns)
                        ok += 1
                except Exception as ex:
                    fail += 1
                    print(f"[fail] {tgt.getEntryPoint()} {tgt.getName()} -> {c['dom_class']} err={ex}")
                    continue

                if not args.attach_source_too:
                    continue
                src = c["source"]
                try:
                    if src.getParentNamespace() == cls_ns:
                        src_skip += 1
                    else:
                        src.setParentNamespace(cls_ns)
                        src_ok += 1
                except Exception as ex:
                    src_fail += 1
                    print(f"[src-fail] {src.getEntryPoint()} {src.getName()} -> {c['dom_class']} err={ex}")
        finally:
            program.endTransaction(tx, True)

        if ok > 0 or src_ok > 0:
            program.save("attach impls by caller ownership", None)
        print(
            f"[done] target_ok={ok} target_skip={skip} target_fail={fail} "
            f"source_ok={src_ok} source_skip={src_skip} source_fail={src_fail}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
