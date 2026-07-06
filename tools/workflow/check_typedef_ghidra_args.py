#!/usr/bin/env python3
"""Audit Hard-Rule-9 typedef casts against binary evidence (dropped-arg detector).

`check_typedef_cast_drift` catches two *source files* disagreeing about a cast
signature — but when every callsite shares the same wrong arity (the QuickDraw
pattern: old ports systematically dropped arguments behind `undefined4 f(void)`
externs), drift can't see it. This audits each typedef-cast signature against
the target function in the Ghidra DB:

  STRONG findings (binary ground truth — `RET imm` purge bytes):
    CONVENTION  typedef says caller-clean (__cdecl/default) but the callee
                purges stack bytes on return (it is __stdcall/__thiscall).
    ARG_COUNT   typedef arity (in stack dwords) disagrees with the callee's
                RET-imm purge for a callee-cleaned convention.

  WEAK leads (Ghidra analysis, frequently wrong — verify before acting):
    GHIDRA_DELTA  caller-clean target whose Ghidra parameter count differs
                  from the typedef arity.

Report-only by default; --strict exits 1 on STRONG findings. Needs the Ghidra
query daemon (`just ghidra-daemon`) or pays one-shot JVM startup.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

from tools.common.repo import repo_root_from_file
from tools.common.symbols import functions_by_name
from tools.workflow.check_typedef_cast_drift import TYPEDEF_RE, normalize, strip_param_names

DWORDS_PER_TYPE = {"double": 2, "__int64": 2, "LONGLONG": 2}


def arg_dwords(args_text: str) -> int | None:
    """Stack dwords a typedef's argument list pushes; None when unknowable."""
    text = normalize(args_text)
    if text in ("", "void"):
        return 0
    total = 0
    for part in strip_param_names(text).split(","):
        part = part.strip()
        if part in ("...",):
            return None  # varargs: arity is per-callsite
        if "(" in part:
            return None  # function-pointer param spelled inline; count unclear
        base = part.replace("const", "").replace("unsigned", "").strip()
        if "*" in base or "&" in base:
            total += 1
            continue
        total += DWORDS_PER_TYPE.get(base.split()[-1] if base.split() else "", 1)
    return total


def classify(
    conv: str, dwords: int | None, ret_imm: int, ghidra_params: int
) -> tuple[str, str] | None:
    """(severity, verdict) for one typedef signature vs binary facts."""
    caller_clean = conv in ("(default)", "__cdecl")
    if caller_clean and ret_imm > 0:
        return (
            "STRONG",
            f"CONVENTION: typedef is {conv} but callee purges {ret_imm} bytes on RET "
            "(callee-cleaned __stdcall/__thiscall — the cast eats its stack args)",
        )
    if dwords is None:
        return None
    if conv == "__stdcall" and ret_imm != dwords * 4:
        return (
            "STRONG",
            f"ARG_COUNT: typedef pushes {dwords} dwords but callee purges {ret_imm} bytes",
        )
    if conv == "__thiscall" and ret_imm not in (dwords * 4, max(0, (dwords - 1) * 4)):
        return (
            "STRONG",
            f"ARG_COUNT: typedef pushes {dwords} dwords (± this) but callee purges "
            f"{ret_imm} bytes",
        )
    if caller_clean and ret_imm == 0 and ghidra_params not in (dwords, -1):
        return (
            "WEAK",
            f"GHIDRA_DELTA: typedef has {dwords} args, Ghidra models {ghidra_params} "
            "(Ghidra params are a hypothesis — verify who pushes what)",
        )
    return None


def collect_typedefs(root: Path):
    by_name: dict[str, set[tuple[str, str, str]]] = defaultdict(set)
    files_of: dict[str, set[str]] = defaultdict(set)
    for path in sorted(root.rglob("*.cpp")):
        text = path.read_text(encoding="utf-8", errors="replace")
        for m in TYPEDEF_RE.finditer(text):
            by_name[m.group("name")].add(
                (normalize(m.group("ret")), m.group("conv") or "(default)", m.group("args"))
            )
            files_of[m.group("name")].add(path.name)
    return by_name, files_of


def resolve_addresses(repo_root: Path, names: set[str]) -> dict[str, int]:
    """typedef target name -> original address, via symbols.csv (thunk-tolerant)."""
    by_symbol = functions_by_name(repo_root)
    out: dict[str, int] = {}
    for name in names:
        for candidate in (name, f"thunk_{name}"):
            if candidate in by_symbol:
                out[name] = by_symbol[candidate][0]
                break
    return out


def query_func_sig(repo_root: Path, addrs: list[int]) -> dict[int, dict[str, str]]:
    proc = subprocess.run(
        ["uv", "run", "python", "-m", "tools.ghidra.query", "func-sig"]
        + [f"0x{a:x}" for a in addrs],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=True,
    )
    rows: dict[int, dict[str, str]] = {}
    lines = [ln for ln in proc.stdout.splitlines() if "|" in ln]
    header = lines[0].split("|")  # pipe-split-ok: func-sig stdout, not a config table
    for line in lines[1:]:
        row = dict(zip(header, line.split("|")))  # pipe-split-ok: func-sig is our own fixed table
        try:
            rows[int(row["address"], 16)] = row
        except (KeyError, ValueError):
            continue
    return rows


def main() -> int:
    repo_root = repo_root_from_file(__file__)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default="src/game")
    parser.add_argument("--strict", action="store_true", help="Exit 1 on STRONG findings")
    args = parser.parse_args()

    by_name, files_of = collect_typedefs(repo_root / args.root)
    addresses = resolve_addresses(repo_root, set(by_name))
    unresolved = sorted(set(by_name) - set(addresses))
    if not addresses:
        print("no typedef-cast targets resolved to addresses; nothing to audit")
        return 0

    sigs = query_func_sig(repo_root, sorted(addresses.values()))

    strong = weak = 0
    for name in sorted(addresses):
        addr = addresses[name]
        fact = sigs.get(addr)
        if fact is None or not fact.get("cc"):
            continue
        ret_imm = int(fact["ret_imm"] or 0)
        ghidra_params = int(fact["params"]) if fact["params"] else -1
        for _ret, conv, args_text in sorted(by_name[name]):
            verdict = classify(conv, arg_dwords(args_text), ret_imm, ghidra_params)
            if verdict is None:
                continue
            severity, message = verdict
            strong += severity == "STRONG"
            weak += severity == "WEAK"
            print(f"{severity} {name} @0x{addr:x} [{', '.join(sorted(files_of[name]))}]")
            print(f"       typedef: ({conv})({normalize(args_text)})")
            print(f"       {message}")

    print(
        f"typedef targets: {len(by_name)}; audited: {len(sigs)}; "
        f"unresolved names: {len(unresolved)}; strong findings: {strong}; weak leads: {weak}"
    )
    if unresolved:
        print("unresolved (no symbols.csv function row): " + ", ".join(unresolved[:10]))
    return 1 if (args.strict and strong) else 0


if __name__ == "__main__":
    sys.exit(main())
