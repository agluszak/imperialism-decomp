#!/usr/bin/env python3
"""
Attach likely create/ctor/dtor neighbors to class namespaces using getter anchors.

Anchor pattern:
  GetT*ClassNamePointer

For each getter, evaluate neighboring functions:
  - previous: create candidate
  - next: ctor candidate
  - next+1: dtor candidate

Only applies attachments when role-specific evidence passes threshold.

Usage:
  .venv/bin/python new_scripts/attach_class_neighbors_from_getters.py
  .venv/bin/python new_scripts/attach_class_neighbors_from_getters.py --apply
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

GETTER_RE = re.compile(r"^Get(T[A-Za-z0-9_]+)ClassNamePointer$")
VTBL_MOV_RE = re.compile(r"^MOV dword ptr \[[A-Z]{2,3}\],0x00[0-9A-Fa-f]{6}$")


def open_project_with_lock_cleanup(root: Path):
    try:
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)
    except Exception:
        for lock_file in (root / f"{PROJECT_NAME}.lock", root / f"{PROJECT_NAME}.lock~"):
            if lock_file.exists():
                lock_file.unlink()
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)


def ep_int(func) -> int:
    return int(str(func.getEntryPoint()), 16)


def first_n_instruction_strings(listing, func, n: int = 12) -> list[str]:
    out: list[str] = []
    it = listing.getInstructions(func.getBody(), True)
    while it.hasNext() and len(out) < n:
        out.append(str(it.next()))
    return out


def called_function_names(listing, fm, func) -> list[str]:
    out: list[str] = []
    it = listing.getInstructions(func.getBody(), True)
    while it.hasNext():
        ins = it.next()
        if str(ins.getMnemonicString()).upper() != "CALL":
            continue
        refs = ins.getReferencesFrom()
        for ref in refs:
            callee = fm.getFunctionAt(ref.getToAddress())
            if callee is not None:
                out.append(callee.getName())
    return out


def decomp_text(ifc, func) -> str:
    try:
        res = ifc.decompileFunction(func, 30, None)
        if not res.decompileCompleted():
            return ""
        return res.getDecompiledFunction().getC()
    except Exception:
        return ""


def score_create(func, call_names: list[str]) -> tuple[int, list[str]]:
    score = 0
    why: list[str] = []
    if any("AllocateWithFallbackHandler" in n for n in call_names):
        score += 3
        why.append("alloc_call")
    if func.getName().startswith(("Create", "Allocate")):
        score += 1
        why.append("name_create_or_alloc")
    if func.getBody().getNumAddresses() <= 260:
        score += 1
        why.append("size_le_260")
    return score, why


def score_ctor(type_name: str, func, first_ins: list[str], ctext: str) -> tuple[int, list[str]]:
    score = 0
    why: list[str] = []
    if any(VTBL_MOV_RE.match(ins) for ins in first_ins):
        score += 3
        why.append("vtbl_mov")
    if f"g_vtbl{type_name}" in ctext:
        score += 3
        why.append("decomp_g_vtbl")
    elif "*param_1 = &PTR_" in ctext or "*this = &PTR_" in ctext:
        score += 2
        why.append("decomp_ptr_install")
    if func.getName().startswith("Construct"):
        score += 1
        why.append("name_construct")
    if func.getBody().getNumAddresses() <= 350:
        score += 1
        why.append("size_le_350")
    return score, why


def score_dtor(func, call_names: list[str], ctext: str) -> tuple[int, list[str]]:
    score = 0
    why: list[str] = []
    if any("FreeHeapBufferIfNotNull" in n or "free" in n.lower() for n in call_names):
        score += 3
        why.append("free_call")
    if func.getName().startswith(("Destruct", "Destroy", "Delete")):
        score += 2
        why.append("name_dtor")
    if "FreeHeapBufferIfNotNull" in ctext and "& 1" in ctext:
        score += 2
        why.append("decomp_free_if_owned")
    if func.getBody().getNumAddresses() <= 350:
        score += 1
        why.append("size_le_350")
    return score, why


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true", help="Write namespace attachments")
    ap.add_argument("--min-create-score", type=int, default=4)
    ap.add_argument("--min-ctor-score", type=int, default=4)
    ap.add_argument("--min-dtor-score", type=int, default=4)
    ap.add_argument("--max-print", type=int, default=200)
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    root = Path(args.project_root).resolve()
    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        from ghidra.app.decompiler import DecompInterface

        fm = program.getFunctionManager()
        st = program.getSymbolTable()
        global_ns = program.getGlobalNamespace()
        listing = program.getListing()

        funcs = []
        it = fm.getFunctions(True)
        while it.hasNext():
            funcs.append(it.next())
        funcs.sort(key=ep_int)
        by_ep = {ep_int(f): i for i, f in enumerate(funcs)}

        class_map = {}
        it_cls = st.getClassNamespaces()
        while it_cls.hasNext():
            ns = it_cls.next()
            class_map[ns.getName()] = ns

        ifc = DecompInterface()
        ifc.openProgram(program)

        candidate_by_func: dict[int, list[dict]] = defaultdict(list)
        stats = {
            "getters_seen": 0,
            "getters_with_class_ns": 0,
            "create_hits": 0,
            "ctor_hits": 0,
            "dtor_hits": 0,
        }

        for getter in funcs:
            m = GETTER_RE.match(getter.getName())
            if not m:
                continue
            stats["getters_seen"] += 1
            tname = m.group(1)
            class_ns = class_map.get(tname)
            if class_ns is None:
                continue
            stats["getters_with_class_ns"] += 1

            idx = by_ep[ep_int(getter)]
            prev_f = funcs[idx - 1] if idx > 0 else None
            ctor_f = funcs[idx + 1] if idx + 1 < len(funcs) else None
            dtor_f = funcs[idx + 2] if idx + 2 < len(funcs) else None

            if prev_f is not None and prev_f.getParentNamespace() == global_ns:
                call_names = called_function_names(listing, fm, prev_f)
                score, why = score_create(prev_f, call_names)
                if score >= args.min_create_score:
                    stats["create_hits"] += 1
                    candidate_by_func[ep_int(prev_f)].append(
                        {
                            "func": prev_f,
                            "class_name": tname,
                            "class_ns": class_ns,
                            "role": "create",
                            "score": score,
                            "why": ",".join(why),
                            "getter": getter.getName(),
                        }
                    )

            if ctor_f is not None and ctor_f.getParentNamespace() == global_ns:
                first_ins = first_n_instruction_strings(listing, ctor_f, 12)
                ctext = decomp_text(ifc, ctor_f)
                score, why = score_ctor(tname, ctor_f, first_ins, ctext)
                if score >= args.min_ctor_score:
                    stats["ctor_hits"] += 1
                    candidate_by_func[ep_int(ctor_f)].append(
                        {
                            "func": ctor_f,
                            "class_name": tname,
                            "class_ns": class_ns,
                            "role": "ctor",
                            "score": score,
                            "why": ",".join(why),
                            "getter": getter.getName(),
                        }
                    )

            if dtor_f is not None and dtor_f.getParentNamespace() == global_ns:
                call_names = called_function_names(listing, fm, dtor_f)
                ctext = decomp_text(ifc, dtor_f)
                score, why = score_dtor(dtor_f, call_names, ctext)
                if score >= args.min_dtor_score:
                    stats["dtor_hits"] += 1
                    candidate_by_func[ep_int(dtor_f)].append(
                        {
                            "func": dtor_f,
                            "class_name": tname,
                            "class_ns": class_ns,
                            "role": "dtor",
                            "score": score,
                            "why": ",".join(why),
                            "getter": getter.getName(),
                        }
                    )

        accepted = []
        ambiguous = 0
        for _faddr, cands in sorted(candidate_by_func.items()):
            cands.sort(key=lambda c: c["score"], reverse=True)
            if len(cands) > 1 and cands[0]["score"] == cands[1]["score"]:
                ambiguous += 1
                continue
            accepted.append(cands[0])

        print(
            "[summary] "
            f"getters_seen={stats['getters_seen']} "
            f"getters_with_class_ns={stats['getters_with_class_ns']} "
            f"create_hits={stats['create_hits']} "
            f"ctor_hits={stats['ctor_hits']} "
            f"dtor_hits={stats['dtor_hits']} "
            f"accepted={len(accepted)} ambiguous={ambiguous}"
        )
        for c in accepted[: args.max_print]:
            f = c["func"]
            print(
                f"{f.getEntryPoint()} {f.getName()} role={c['role']} "
                f"class={c['class_name']} score={c['score']} why={c['why']} "
                f"getter={c['getter']}"
            )
        if len(accepted) > args.max_print:
            print(f"... ({len(accepted) - args.max_print} more)")

        if not args.apply:
            print("[dry-run] pass --apply to attach accepted candidates")
            return 0

        tx = program.startTransaction("Attach class neighbors from getters")
        ok = 0
        skip = 0
        fail = 0
        try:
            for c in accepted:
                f = c["func"]
                cls_ns = c["class_ns"]
                if f.getParentNamespace() == cls_ns:
                    skip += 1
                    continue
                try:
                    f.setParentNamespace(cls_ns)
                    ok += 1
                except Exception as ex:
                    fail += 1
                    print(f"[fail] {f.getEntryPoint()} {f.getName()} err={ex}")
        finally:
            program.endTransaction(tx, True)

        program.save("attach class neighbors from getters", None)
        print(f"[done] ok={ok} skip={skip} fail={fail}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
