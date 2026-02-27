#!/usr/bin/env python3
"""
Attach global functions to class namespaces using embedded class-name stems.

Safety gates:
- Function must currently be in Global namespace.
- Function name must resolve to exactly one class by stem match.
- Class namespace must already exist.

Matching:
- Class "TMapDialog" contributes stem "MapDialog".
- Function names are split into alnum/underscore tokens.
- A stem match is accepted if:
  1) token equals stem, or
  2) token endswith stem, or
  3) a CamelCase segment inside token equals stem.

Usage:
  .venv/bin/python new_scripts/attach_class_methods_by_embedded_token.py
  .venv/bin/python new_scripts/attach_class_methods_by_embedded_token.py --apply
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

import pyghidra

GHIDRA_DIR = Path(
    "/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC"
)
PROJECT_NAME = "imperialism-decomp"
PROGRAM_PATH = "/Imperialism.exe"
TOKEN_RE = re.compile(r"[A-Za-z0-9_]+")
CAMEL_RE = re.compile(r"[A-Z][a-z0-9]*")


def open_project_with_lock_cleanup(root: Path):
    try:
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)
    except Exception:
        for lock_file in (root / f"{PROJECT_NAME}.lock", root / f"{PROJECT_NAME}.lock~"):
            if lock_file.exists():
                lock_file.unlink()
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)


def token_matches_stem(token: str, stem: str) -> bool:
    if token == stem:
        return True
    if token.endswith(stem):
        return True
    segments = CAMEL_RE.findall(token)
    return stem in segments


def infer_class_candidates(func_name: str, class_stems: dict[str, str]) -> set[str]:
    tokens = TOKEN_RE.findall(func_name)
    out: set[str] = set()
    for tok in tokens:
        if len(tok) < 4:
            continue
        for stem, class_name in class_stems.items():
            if len(stem) < 4:
                continue
            if token_matches_stem(tok, stem):
                out.add(class_name)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true", help="Write namespace attachments")
    ap.add_argument("--max-print", type=int, default=200)
    ap.add_argument("--start", default="", help="Optional inclusive start address (hex)")
    ap.add_argument("--end", default="", help="Optional inclusive end address (hex)")
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    def parse_hex_opt(text: str) -> int | None:
        t = (text or "").strip()
        if not t:
            return None
        if t.lower().startswith("0x"):
            return int(t, 16)
        return int(t, 16)

    addr_start = parse_hex_opt(args.start)
    addr_end = parse_hex_opt(args.end)

    root = Path(args.project_root).resolve()
    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        st = program.getSymbolTable()
        fm = program.getFunctionManager()
        global_ns = program.getGlobalNamespace()

        class_map = {}
        class_stems = {}
        it_cls = st.getClassNamespaces()
        while it_cls.hasNext():
            ns = it_cls.next()
            cname = ns.getName()
            class_map[cname] = ns
            if cname.startswith("T") and len(cname) > 1:
                class_stems[cname[1:]] = cname

        candidates = []
        fit = fm.getFunctions(True)
        while fit.hasNext():
            f = fit.next()
            ep = int(f.getEntryPoint().getOffset() & 0xFFFFFFFF)
            if addr_start is not None and ep < addr_start:
                continue
            if addr_end is not None and ep > addr_end:
                continue
            if f.getParentNamespace() != global_ns:
                continue
            owners = infer_class_candidates(f.getName(), class_stems)
            if len(owners) != 1:
                continue
            cname = next(iter(owners))
            cns = class_map.get(cname)
            if cns is None:
                continue
            candidates.append((f, cname, cns))

        print(f"[summary] class_stems={len(class_stems)} unique_global_candidates={len(candidates)}")
        for f, cname, _ in candidates[: args.max_print]:
            print(f"{f.getEntryPoint()} {f.getName()} -> {cname}")
        if len(candidates) > args.max_print:
            print(f"... ({len(candidates) - args.max_print} more)")

        if not args.apply:
            print("[dry-run] pass --apply to write attachments")
            return 0

        tx = program.startTransaction("Attach class methods by embedded token")
        ok = 0
        skip = 0
        fail = 0
        try:
            for f, _cname, cns in candidates:
                try:
                    if f.getParentNamespace() == cns:
                        skip += 1
                        continue
                    f.setParentNamespace(cns)
                    ok += 1
                except Exception as ex:
                    fail += 1
                    print(f"[fail] {f.getEntryPoint()} {f.getName()} err={ex}")
        finally:
            program.endTransaction(tx, True)

        program.save("attach class methods by embedded token", None)
        print(f"[done] ok={ok} skip={skip} fail={fail}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
