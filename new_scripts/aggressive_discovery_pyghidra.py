#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
import time

import pyghidra


def open_project_resilient(project_root: Path, project_name: str):
    try:
        return pyghidra.open_project(str(project_root), project_name, create=False)
    except BaseException:
        from ghidra.framework.model import ProjectLocator
        from ghidra.pyghidra import PyGhidraProjectManager

        pm = PyGhidraProjectManager()
        loc = ProjectLocator(str(project_root), project_name)
        for restore, flag in ((False, False), (False, True), (True, False), (True, True)):
            try:
                log(f"[open] fallback openProject restore={restore} flag={flag}")
                return pm.openProject(loc, restore, flag)
            except BaseException:
                continue
        raise


def u8(mem, addr):
    return mem.getByte(addr) & 0xFF


def log(msg: str):
    print(msg, flush=True)


def mine_class_strings(program, min_len: int, max_hits: int):
    terms = ["window", "wnd", "dialog", "frame", "view", "toolbar", "tooltip", "class", "mainframe"]
    rx = re.compile("|".join([re.escape(t) for t in terms]), re.IGNORECASE)
    mem = program.getMemory()
    fm = program.getFunctionManager()

    hits = []
    blocks = list(mem.getBlocks())
    log(f"[class-strings] scanning {len(blocks)} blocks")
    for i, block in enumerate(blocks, 1):
        if not block.isInitialized() or block.isExecute():
            continue
        log(f"[class-strings] block {i}/{len(blocks)} {block.getName()} start={block.getStart()} end={block.getEnd()}")
        a = block.getStart()
        end = block.getEnd()
        cur = []
        cur_start = None
        while a <= end:
            b = u8(mem, a)
            if 0x20 <= b <= 0x7E:
                if cur_start is None:
                    cur_start = a
                cur.append(chr(b))
            else:
                if cur_start is not None and len(cur) >= min_len:
                    s = "".join(cur)
                    if rx.search(s):
                        refs = program.getReferenceManager().getReferencesTo(cur_start)
                        callers = []
                        seen = set()
                        rc = 0
                        for r in refs:
                            rc += 1
                            f = fm.getFunctionContaining(r.getFromAddress())
                            if f is None:
                                continue
                            key = f"{f.getName()}@{f.getEntryPoint()}"
                            if key in seen:
                                continue
                            seen.add(key)
                            callers.append(key)
                            if len(callers) >= 4:
                                break
                        hits.append(
                            {
                                "address": f"0x{cur_start}",
                                "text": s,
                                "ref_count": rc,
                                "callers": callers,
                            }
                        )
                cur = []
                cur_start = None
            a = a.add(1)

    hits.sort(key=lambda x: (x["ref_count"], len(x["text"])), reverse=True)
    log(f"[class-strings] done; raw_hits={len(hits)}")
    return hits[:max_hits]


def mine_vtable_candidates(program, min_run: int, max_rows: int):
    mem = program.getMemory()
    fm = program.getFunctionManager()
    rows = []

    def is_exec_func_ptr(v):
        try:
            ta = program.getAddressFactory().getDefaultAddressSpace().getAddress(hex(v))
        except Exception:
            return None
        if ta is None:
            return None
        b = mem.getBlock(ta)
        if b is None or not b.isExecute():
            return None
        return fm.getFunctionContaining(ta)

    blocks = list(mem.getBlocks())
    log(f"[vtables] scanning {len(blocks)} blocks")
    for i, block in enumerate(blocks, 1):
        if not block.isInitialized() or block.isExecute():
            continue
        log(f"[vtables] block {i}/{len(blocks)} {block.getName()} start={block.getStart()} end={block.getEnd()}")
        a = block.getStart()
        end = block.getEnd()
        run_start = None
        run_funcs = []
        while a <= end.subtract(3):
            try:
                v = program.getMemory().getInt(a) & 0xFFFFFFFF
            except Exception:
                v = None
            f = is_exec_func_ptr(v) if v is not None else None
            if f is not None:
                if run_start is None:
                    run_start = a
                    run_funcs = []
                run_funcs.append(f)
            else:
                if run_start is not None and len(run_funcs) >= min_run:
                    names = []
                    seen = set()
                    for fn in run_funcs[:8]:
                        nm = f"{fn.getName()}@{fn.getEntryPoint()}"
                        if nm in seen:
                            continue
                        seen.add(nm)
                        names.append(nm)
                    rows.append(
                        {
                            "address": f"0x{run_start}",
                            "run_len": len(run_funcs),
                            "block": block.getName(),
                            "sample_functions": names,
                        }
                    )
                run_start = None
                run_funcs = []
            a = a.add(4)
        if run_start is not None and len(run_funcs) >= min_run:
            names = []
            seen = set()
            for fn in run_funcs[:8]:
                nm = f"{fn.getName()}@{fn.getEntryPoint()}"
                if nm in seen:
                    continue
                seen.add(nm)
                names.append(nm)
            rows.append(
                {
                    "address": f"0x{run_start}",
                    "run_len": len(run_funcs),
                    "block": block.getName(),
                    "sample_functions": names,
                }
            )

    rows.sort(key=lambda x: x["run_len"], reverse=True)
    log(f"[vtables] done; raw_candidates={len(rows)}")
    return rows[:max_rows]


def mine_virtual_call_clusters(program, max_funcs: int):
    listing = program.getListing()
    fm = program.getFunctionManager()
    off_rx = re.compile(r"CALL\s+dword ptr \[[A-Z]{2,3}\s*\+\s*0x([0-9a-fA-F]+)\]")
    plain_rx = re.compile(r"CALL\s+dword ptr \[[A-Z]{2,3}\]")

    func_rows = []
    off_counts = {}
    log("[vcalls] scanning all functions for indirect CALL patterns")
    it = fm.getFunctions(True)
    scanned = 0
    while it.hasNext():
        f = it.next()
        scanned += 1
        if scanned % 2000 == 0:
            log(f"[vcalls] scanned_functions={scanned}")
        offs = []
        ins_it = listing.getInstructions(f.getBody(), True)
        while ins_it.hasNext():
            ins = ins_it.next()
            if ins.getMnemonicString().upper() != "CALL":
                continue
            t = str(ins)
            m = off_rx.match(t)
            if m:
                off = int(m.group(1), 16)
                offs.append(off)
                off_counts[off] = off_counts.get(off, 0) + 1
            elif plain_rx.match(t):
                offs.append(0)
                off_counts[0] = off_counts.get(0, 0) + 1
        if len(offs) >= 2:
            uniq = sorted(set(offs))
            func_rows.append(
                {
                    "address": f"0x{f.getEntryPoint()}",
                    "function": f.getName(),
                    "vcall_count": len(offs),
                    "offsets": [f"0x{x:x}" for x in uniq[:24]],
                }
            )
    func_rows.sort(key=lambda x: x["vcall_count"], reverse=True)
    log(f"[vcalls] done; functions_with_vcalls={len(func_rows)} unique_offsets={len(off_counts)}")
    offs = sorted(off_counts.items(), key=lambda kv: kv[1], reverse=True)
    top_offs = [{"offset": f"0x{k:x}", "count": v} for k, v in offs[:120]]
    return func_rows[:max_funcs], top_offs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ghidra-install", required=True, type=Path)
    ap.add_argument("--project-root", required=True, type=Path)
    ap.add_argument("--project-name", default="imperialism-decomp")
    ap.add_argument("--program", default="/Imperialism.exe")
    ap.add_argument("--min-string-len", type=int, default=8)
    ap.add_argument("--max-string-hits", type=int, default=200)
    ap.add_argument("--min-vtable-run", type=int, default=5)
    ap.add_argument("--max-vtable-hits", type=int, default=200)
    ap.add_argument("--max-vcall-funcs", type=int, default=120)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()

    t0 = time.time()
    log("[start] launching pyghidra")
    pyghidra.start(install_dir=args.ghidra_install)
    log("[start] opening project")
    project = open_project_resilient(args.project_root, args.project_name)
    try:
        log("[start] opening program context")
        with pyghidra.program_context(project, args.program) as program:
            log("[phase] class-string mining")
            class_hits = mine_class_strings(program, args.min_string_len, args.max_string_hits)
            log("[phase] vtable candidate mining")
            vt_hits = mine_vtable_candidates(program, args.min_vtable_run, args.max_vtable_hits)
            log("[phase] virtual-call clustering")
            vfuncs, voffs = mine_virtual_call_clusters(program, args.max_vcall_funcs)
            out = {
                "class_string_hits": class_hits,
                "vtable_candidates": vt_hits,
                "virtual_call_functions": vfuncs,
                "virtual_call_offsets": voffs,
            }
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(json.dumps(out, indent=2))
            log(f"[done] wrote {args.out}")
            log(f"[done] class_string_hits={len(class_hits)}")
            log(f"[done] vtable_candidates={len(vt_hits)}")
            log(f"[done] virtual_call_functions={len(vfuncs)}")
            log(f"[done] virtual_call_offsets={len(voffs)}")
            log(f"[done] elapsed_sec={time.time() - t0:.2f}")
    finally:
        project.close()


if __name__ == "__main__":
    main()
