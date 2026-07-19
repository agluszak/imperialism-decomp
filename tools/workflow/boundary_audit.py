#!/usr/bin/env python3
"""Manual/autogen boundary audit: every autogen stub referenced from manual code.

Joins, per autogen stub symbol:
  * stub name + original address (computed from the generated stub surface)
  * every reference from manual sources (src/game, include/game), split into
    ordinary calls, address-takes, extern re-declarations, and typedef casts
  * caller (file) count
  * original function size (config/original_entities.csv)
  * optionally — with GHIDRA_INSTALL_DIR set — Ghidra calling convention,
    parameter count, and the RET-imm purge bytes (binary ground truth)

and classifies each boundary:

  METHOD        callee purges stack (RET imm) and/or Ghidra says __thiscall:
                declare a real method on the owning class
  SINGLETON     METHOD whose callers all load ECX from a known global manager
                (subset of METHOD; needs manual confirmation)
  VIRTUAL       reached through a vtable slot (not statically detectable here;
                assign by hand when the callsite is a vtable dispatch)
  FREE_CDECL    plain-RET callee referenced by ordinary calls only
  FREE_STDCALL  RET-imm callee whose Ghidra cc is __stdcall
  CALLBACK      manual code takes the stub's address (function pointer needed)
  ILT           original address is an ILT jump thunk: resolve to the target,
                never call the thunk (repo rule)
  DEAD          no manual reference at all — porting it is optional backlog
  UNKNOWN       referenced, but no Ghidra facts available in this environment

The classification is a lead generator, not ground truth: convention labels
follow the calling-conventions skill rules (verify ECX/EDX and RET in the
listing before declaring anything).

Usage:
  uv run python -m tools.workflow.boundary_audit            # referenced only
  uv run python -m tools.workflow.boundary_audit --all      # include DEAD
  uv run python -m tools.workflow.boundary_audit --json out.json
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from tools.common import ghidra_env
from tools.common.file_scan import is_excluded_scan_path
from tools.common.repo import repo_root_from_file
from tools.common.symbols import functions_by_name

# ILT thunk range for Imperialism.exe: the .text ILT jump tables live below the
# first real function bodies. Thunks are also 6-byte JMPs; Ghidra size confirms.
ILT_NAME_RE = re.compile(r"^(thunk_|ILT_)")

# CRT/MFC library segment of Imperialism.exe: everything at/above this address is
# statically linked library code (operator new 0x606f73, CString 0x605797,
# _realloc 0x5e7fc0, ...). Calls there want the real library declaration, not a
# port — and they are not manual/autogen boundary debt.
LIBRARY_RANGE_START = 0x5E0000


@dataclass
class Boundary:
    name: str
    address: int
    stub_file: str
    size: int = 0
    calls: list[str] = field(default_factory=list)  # "file:line"
    address_takes: list[str] = field(default_factory=list)
    externs: list[str] = field(default_factory=list)
    typedef_casts: list[str] = field(default_factory=list)
    cc: str = ""
    params: int = -1
    ret_imm: int = -1
    classification: str = "UNKNOWN"

    @property
    def referenced(self) -> bool:
        return bool(self.calls or self.address_takes or self.typedef_casts)

    @property
    def caller_files(self) -> set[str]:
        return {ref.split(":")[0] for ref in self.calls + self.address_takes}


def collect_stubs(repo_root: Path) -> dict[str, Boundary]:
    """Compute the stub surface in-process (stubs are disposable build artifacts,
    so derive the identifiers the generator would emit instead of reading files)."""
    from tools.stubgen import (
        ILT_THUNK_RANGE,
        compute_stub_rows,
        dedupe_identifier,
        function_name_from_prototype,
        sanitize_identifier,
    )

    out: dict[str, Boundary] = {}
    seen: set[str] = set()
    for address, name, prototype in compute_stub_rows(repo_root):
        raw_name = function_name_from_prototype(prototype) or name or "sub_{:08X}".format(address)
        ident = sanitize_identifier(raw_name, address)
        ident = dedupe_identifier(ident, address, seen)
        # ILT jmp-thunk stubs carry no reccmp marker and were never part of the
        # boundary surface; their manual references are the ilt-ossification
        # gate's queue, not boundary debt.
        if address in ILT_THUNK_RANGE:
            continue
        out.setdefault(ident, Boundary(name=ident, address=address, stub_file="(generated)"))
    return out


def manual_sources(repo_root: Path):
    for base in (repo_root / "src" / "game", repo_root / "include" / "game"):
        for path in sorted(base.rglob("*")):
            if path.suffix not in (".cpp", ".h"):
                continue
            if is_excluded_scan_path(path):
                continue
            yield path


def scan_references(repo_root: Path, stubs: dict[str, Boundary]) -> None:
    names = set(stubs)
    word_re = re.compile(r"[A-Za-z_]\w*")
    for path in manual_sources(repo_root):
        rel = str(path.relative_to(repo_root))
        for lineno, line in enumerate(
            path.read_text(encoding="utf-8", errors="replace").splitlines(), 1
        ):
            if "//" in line:
                line = line.split("//", 1)[0]
            for word in word_re.finditer(line):
                token = word.group(0)
                base = token[:-2] if token.endswith("_t") else token
                if base not in names:
                    continue
                stub = stubs[base]
                ref = f"{rel}:{lineno}"
                after = line[word.end() :].lstrip()
                before = line[: word.start()].rstrip()
                # Qualified/member access is a class API, not the global stub
                # symbol (e.g. runtimeClass->CreateObject(), T::CreateObject).
                if before.endswith(("::", "->", ".")):
                    continue
                if token.endswith("_t"):
                    stub.typedef_casts.append(ref)
                elif before.endswith("&") or before.endswith("& "):
                    stub.address_takes.append(ref)
                elif before.endswith("extern") or " extern " in f" {before} ":
                    stub.externs.append(ref)
                elif re.match(r"^extern\b", line.strip()):
                    stub.externs.append(ref)
                elif after.startswith("("):
                    # A definition line inside the stub files never reaches here
                    # (manual_sources excludes generated dirs).
                    stub.calls.append(ref)
    for stub in stubs.values():
        for attr in ("calls", "address_takes", "externs", "typedef_casts"):
            setattr(stub, attr, sorted(set(getattr(stub, attr))))


def enrich_from_symbols(repo_root: Path, stubs: dict[str, Boundary]) -> None:
    by_name = functions_by_name(repo_root)
    for stub in stubs.values():
        row = by_name.get(stub.name)
        if row and row[0] == stub.address:
            stub.size = row[1]


def enrich_from_ghidra(repo_root: Path, stubs: dict[str, Boundary]) -> None:
    if ghidra_env.install_dir() is None:
        return
    wanted = [s for s in stubs.values() if s.referenced]
    if not wanted:
        return
    addrs = sorted({s.address for s in wanted})
    proc = subprocess.run(
        ["uv", "run", "python", "-m", "tools.ghidra.query", "func-sig"]
        + [f"0x{a:x}" for a in addrs],
        cwd=repo_root,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        print(f"warning: func-sig query failed; classifying without binary facts", file=sys.stderr)
        return
    lines = [ln for ln in proc.stdout.splitlines() if "|" in ln]
    if not lines:
        return
    header = lines[0].split("|")  # pipe-split-ok: func-sig stdout, not a config table
    facts: dict[int, dict[str, str]] = {}
    for line in lines[1:]:
        row = dict(zip(header, line.split("|")))  # pipe-split-ok: func-sig table
        try:
            facts[int(row["address"], 16)] = row
        except (KeyError, ValueError):
            continue
    for stub in wanted:
        fact = facts.get(stub.address)
        if not fact:
            continue
        stub.cc = fact.get("cc") or ""
        stub.params = int(fact["params"]) if fact.get("params") else -1
        stub.ret_imm = int(fact["ret_imm"]) if fact.get("ret_imm") else 0
        if not stub.size and fact.get("size"):
            stub.size = int(fact["size"])


def classify(stub: Boundary) -> str:
    if not stub.referenced:
        return "DEAD"
    if stub.address >= LIBRARY_RANGE_START:
        return "LIBRARY"
    if ILT_NAME_RE.match(stub.name) or (0 < stub.size <= 6 and stub.ret_imm == 0 and stub.cc):
        return "ILT"
    if stub.address_takes:
        return "CALLBACK"
    if stub.ret_imm == -1:  # no Ghidra facts in this environment
        return "UNKNOWN"
    if stub.cc == "__thiscall" or (stub.ret_imm > 0 and stub.cc not in ("__stdcall",)):
        return "METHOD"
    if stub.ret_imm > 0 and stub.cc == "__stdcall":
        return "FREE_STDCALL"
    if stub.ret_imm == 0:
        return "FREE_CDECL"
    return "UNKNOWN"


def main() -> int:
    repo_root = repo_root_from_file(__file__)
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--all", action="store_true", help="Include unreferenced (DEAD) stubs")
    parser.add_argument("--json", help="Also write the full report as JSON to this path")
    args = parser.parse_args()

    stubs = collect_stubs(repo_root)
    scan_references(repo_root, stubs)
    enrich_from_symbols(repo_root, stubs)
    enrich_from_ghidra(repo_root, stubs)
    for stub in stubs.values():
        stub.classification = classify(stub)

    referenced = [s for s in stubs.values() if s.referenced]
    referenced.sort(key=lambda s: (-len(s.caller_files), -len(s.calls), s.name))

    print(f"autogen stubs: {len(stubs)}; referenced from manual sources: {len(referenced)}")
    counts: dict[str, int] = defaultdict(int)
    for stub in stubs.values():
        counts[stub.classification] += 1
    print("classes: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    print()
    for stub in referenced if not args.all else sorted(stubs.values(), key=lambda s: s.name):
        facts = ""
        if stub.ret_imm >= 0:
            facts = f" cc={stub.cc or '?'} params={stub.params} ret_imm={stub.ret_imm}"
        print(
            f"{stub.classification:12} {stub.name} @0x{stub.address:x} "
            f"size={stub.size}{facts}"
        )
        for label, refs in (
            ("call", stub.calls),
            ("addr-take", stub.address_takes),
            ("typedef", stub.typedef_casts),
            ("extern", stub.externs),
        ):
            for ref in refs:
                print(f"    {label:9} {ref}")

    if args.json:
        payload = [
            {
                "name": s.name,
                "address": f"0x{s.address:x}",
                "classification": s.classification,
                "size": s.size,
                "cc": s.cc,
                "params": s.params,
                "ret_imm": s.ret_imm,
                "calls": s.calls,
                "address_takes": s.address_takes,
                "typedef_casts": s.typedef_casts,
                "externs": s.externs,
            }
            for s in (sorted(stubs.values(), key=lambda s: s.name) if args.all else referenced)
        ]
        Path(args.json).write_text(json.dumps(payload, indent=2) + "\n")
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
