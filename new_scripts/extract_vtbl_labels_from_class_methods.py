#!/usr/bin/env python3
"""
Infer missing canonical g_vtblT* labels from class-method decomp evidence.

Heuristic:
1) Focus on T* class namespaces that currently lack canonical g_vtblT<Class>.
2) Decompile methods in that class and collect vtable-store style literals.
3) Score candidate addresses using constructor-like naming and repeated evidence.
4) Apply only non-conflicting labels when confidence gates pass.

Usage:
  .venv/bin/python new_scripts/extract_vtbl_labels_from_class_methods.py
  .venv/bin/python new_scripts/extract_vtbl_labels_from_class_methods.py --apply
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

VTBL_STORE_RE = re.compile(
    r"(?:\*this|\*param_1|\*\([^)]+\))\s*=\s*&PTR_LAB_00([0-9a-fA-F]{6})"
)
VTBL_ANY_RE = re.compile(r"&PTR_LAB_00([0-9a-fA-F]{6})")
CTORISH_RE = re.compile(r"construct|create|init|setup", re.IGNORECASE)


def open_project_with_lock_cleanup(root: Path):
    try:
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)
    except Exception:
        for lock_file in (root / f"{PROJECT_NAME}.lock", root / f"{PROJECT_NAME}.lock~"):
            if lock_file.exists():
                lock_file.unlink()
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true", help="Write labels")
    ap.add_argument(
        "--allow-shared-vtbl",
        action="store_true",
        help="Allow multiple canonical g_vtblT* aliases at the same vtable address",
    )
    ap.add_argument(
        "--max-methods-per-class",
        type=int,
        default=24,
        help="Maximum methods decompiled per class",
    )
    ap.add_argument(
        "--min-score",
        type=int,
        default=4,
        help="Minimum score required for apply candidates",
    )
    ap.add_argument(
        "--min-hit-count",
        type=int,
        default=2,
        help="Minimum literal-hit count for selected vtable candidate",
    )
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
        from ghidra.program.model.symbol import SourceType

        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()
        st = program.getSymbolTable()
        global_ns = program.getGlobalNamespace()

        # Existing canonical labels: g_vtblT*
        existing_canonical_names = set()
        sit = st.getAllSymbols(True)
        while sit.hasNext():
            n = sit.next().getName()
            if n.startswith("g_vtblT"):
                existing_canonical_names.add(n)

        # Build method lists by class namespace.
        class_namespaces = {}
        it_cls = st.getClassNamespaces()
        while it_cls.hasNext():
            ns = it_cls.next()
            class_namespaces[ns.getName()] = ns

        methods_by_class: dict[str, list[object]] = defaultdict(list)
        fit = fm.getFunctions(True)
        while fit.hasNext():
            f = fit.next()
            pns = f.getParentNamespace()
            if pns is None or pns == global_ns:
                continue
            cname = pns.getName()
            if cname.startswith("T"):
                methods_by_class[cname].append(f)

        ifc = DecompInterface()
        ifc.openProgram(program)

        candidates = []
        scanned_classes = 0
        for cname, cls_ns in sorted(class_namespaces.items()):
            if not cname.startswith("T"):
                continue

            label = f"g_vtbl{cname}"
            if label in existing_canonical_names:
                continue

            methods = methods_by_class.get(cname, [])
            if not methods:
                continue

            scanned_classes += 1
            methods_sorted = sorted(
                methods,
                key=lambda f: (
                    0 if CTORISH_RE.search(f.getName()) else 1,
                    str(f.getEntryPoint()),
                ),
            )[: args.max_methods_per_class]

            score_by_vtbl: dict[int, int] = defaultdict(int)
            hits_by_vtbl: dict[int, int] = defaultdict(int)
            evidence_rows: list[str] = []

            for f in methods_sorted:
                res = ifc.decompileFunction(f, 25, None)
                if not res.decompileCompleted():
                    continue
                code = str(res.getDecompiledFunction().getC())

                strong_hits = VTBL_STORE_RE.findall(code)
                weak_hits = VTBL_ANY_RE.findall(code)

                boost = 2 if CTORISH_RE.search(f.getName()) else 0
                if cname.lower() in f.getName().lower():
                    boost += 1

                if strong_hits:
                    for h in strong_hits:
                        va = int("00" + h, 16)
                        hits_by_vtbl[va] += 1
                        score_by_vtbl[va] += 2 + boost
                        evidence_rows.append(
                            f"{f.getName()}@{f.getEntryPoint()} strong 0x{va:08x}"
                        )
                elif weak_hits:
                    # Weak evidence only if this function looks ctor-like.
                    if boost > 0:
                        for h in weak_hits:
                            va = int("00" + h, 16)
                            hits_by_vtbl[va] += 1
                            score_by_vtbl[va] += 1 + boost
                            evidence_rows.append(
                                f"{f.getName()}@{f.getEntryPoint()} weak 0x{va:08x}"
                            )

            if not score_by_vtbl:
                continue

            ranked = sorted(
                score_by_vtbl.items(),
                key=lambda kv: (kv[1], hits_by_vtbl.get(kv[0], 0)),
                reverse=True,
            )
            best_va, best_score = ranked[0]
            best_hits = hits_by_vtbl.get(best_va, 0)
            second_score = ranked[1][1] if len(ranked) > 1 else -1

            # Conservative confidence gate.
            if best_score < args.min_score or best_hits < args.min_hit_count:
                continue
            if second_score >= best_score:
                continue

            addr = af.getAddress(f"0x{best_va:08x}")
            syms = list(st.getSymbols(addr))
            conflict = any(
                s.getName().startswith("g_vtblT") and s.getName() != label for s in syms
            )
            if conflict and args.allow_shared_vtbl:
                conflict = False
            if conflict:
                continue

            candidates.append(
                {
                    "class": cname,
                    "label": label,
                    "vtbl_addr": f"0x{best_va:08x}",
                    "score": best_score,
                    "hits": best_hits,
                    "runner_up_score": second_score,
                    "evidence_count": len(evidence_rows),
                }
            )

        print(
            f"[summary] scanned_classes={scanned_classes} "
            f"candidates={len(candidates)} min_score={args.min_score} min_hits={args.min_hit_count}"
        )
        for c in candidates[:240]:
            print(
                f"{c['class']},{c['vtbl_addr']},{c['label']},"
                f"score={c['score']},hits={c['hits']},runner_up={c['runner_up_score']}"
            )
        if len(candidates) > 240:
            print(f"... ({len(candidates) - 240} more)")

        if not args.apply:
            print("[dry-run] pass --apply to write labels")
            return 0

        tx = program.startTransaction("Extract vtbl labels from class methods")
        ok = skip = fail = 0
        try:
            for c in candidates:
                addr = af.getAddress(c["vtbl_addr"])
                label = c["label"]
                syms = list(st.getSymbols(addr))
                if any(s.getName() == label for s in syms):
                    skip += 1
                    continue
                conflict = any(
                    s.getName().startswith("g_vtblT") and s.getName() != label for s in syms
                )
                if conflict and args.allow_shared_vtbl:
                    conflict = False
                if conflict:
                    skip += 1
                    continue
                try:
                    sym = st.createLabel(addr, label, SourceType.USER_DEFINED)
                    if not syms:
                        sym.setPrimary()
                    ok += 1
                except Exception as ex:
                    fail += 1
                    print(f"[fail] {c['vtbl_addr']} {label} err={ex}")
        finally:
            program.endTransaction(tx, True)

        program.save("extract vtbl labels from class methods", None)
        print(f"[done] ok={ok} skip={skip} fail={fail}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
