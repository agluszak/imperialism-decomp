#!/usr/bin/env python3
"""Recover original-binary global-data addresses from reccmp asm diffs.

reccmp renders an original-side operand it cannot resolve as an ``<OFFSETn>``
placeholder, while the recompiled side shows the real symbol from the PDB
(``mov eax, [g_Foo (DATA)]``). Every such mismatched instruction pair in an
otherwise-matching function is evidence: the original raw operand address (we
re-disassemble it here with capstone) belongs to the recomp symbol on the same
line. Aggregated over the whole report, consistently-voted pairs identify
original .data/.rdata addresses for globals the source already models — the
missing piece is only the ``// GLOBAL:`` annotation.

Output: a pipe CSV of candidates ranked by vote count, with conflict and
already-known status. Feed accepted rows to config/symbols.csv (type=global)
and `just annotate-globals` (tools/workflow/annotate_globals_from_symbols.py),
which inserts the markers above the matching declarations in
src/game/global_data_tables.cpp.

Read-only: this tool never writes to config or source.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import struct
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

import capstone

from tools.common.repo import repo_root_from_file
from tools.workflow.prune_ilt_thunks import original_exe_from_user_yml

DATA_REF_RE = re.compile(r"(?P<name>[^\s\[\],]+) \(DATA\)")
ANNOT_KIND_RE = re.compile(r"\((DATA|OFFSET|FUNCTION|IMPORT|STRING|FLOAT)\)")
PLACEHOLDER_RE = re.compile(r"<OFFSET\d+>")


class PeImage:
    def __init__(self, exe_bytes: bytes):
        self.exe = exe_bytes
        pe = struct.unpack_from("<I", exe_bytes, 0x3C)[0]
        nsec = struct.unpack_from("<H", exe_bytes, pe + 6)[0]
        opt = struct.unpack_from("<H", exe_bytes, pe + 20)[0]
        self.base = struct.unpack_from("<I", exe_bytes, pe + 0x34)[0]
        off = pe + 24 + opt
        self.sections = []
        for _ in range(nsec):
            name = exe_bytes[off : off + 8].rstrip(b"\0").decode()
            vsize, va, rsize, raw = struct.unpack_from("<IIII", exe_bytes, off + 8)
            self.sections.append((name, self.base + va, vsize, raw))
            off += 40

    def read(self, addr: int, size: int) -> bytes | None:
        for _name, lo, vsize, raw in self.sections:
            if lo <= addr < lo + vsize:
                off = raw + (addr - lo)
                return self.exe[off : off + size]
        return None

    def data_ranges(self) -> list[tuple[int, int]]:
        return [
            (lo, lo + vsize)
            for name, lo, vsize, _raw in self.sections
            if name in (".rdata", ".data")
        ]


def run_report(target: str, build_dir: Path) -> list[dict]:
    with tempfile.NamedTemporaryFile("r", suffix=".json", delete=False) as tf:
        json_path = tf.name
    subprocess.run(
        ["uv", "run", "reccmp-reccmp", "--target", target, "--json", json_path, "--silent"],
        cwd=build_dir,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    return json.loads(Path(json_path).read_text())["data"]


def instruction_data_refs(pe: PeImage, addr: int, ranges: list[tuple[int, int]]) -> list[int]:
    """Disassemble one instruction at addr; return operand values inside data sections."""
    raw = pe.read(addr, 16)
    if not raw:
        return []
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    refs: list[int] = []
    for ins in md.disasm(raw, addr):
        for op in ins.operands:
            vals = []
            if op.type == capstone.x86.X86_OP_MEM and op.mem.base == 0 and op.mem.index == 0:
                vals.append(op.mem.disp)
            elif op.type == capstone.x86.X86_OP_MEM and op.mem.disp:
                vals.append(op.mem.disp)
            elif op.type == capstone.x86.X86_OP_IMM:
                vals.append(op.imm)
            for v in vals:
                if any(lo <= v < hi for lo, hi in ranges):
                    refs.append(v)
        break
    return refs


def mnemonic(text: str) -> str:
    return text.split(None, 1)[0] if text else ""


def main() -> int:
    repo_root = repo_root_from_file(__file__)
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--target", default="IMPERIALISM")
    ap.add_argument("--build-dir", default=str(repo_root / "build-msvc500"))
    ap.add_argument("--report-json", default="", help="Reuse an existing full (non-diet) report")
    ap.add_argument("--original-exe", default="")
    ap.add_argument("--min-votes", type=int, default=2)
    ap.add_argument("--min-match", type=float, default=0.3, help="Skip functions below this")
    ap.add_argument("--out", default="", help="Write candidate CSV here (default: stdout)")
    args = ap.parse_args()

    exe_path = (
        Path(args.original_exe) if args.original_exe else original_exe_from_user_yml(repo_root)
    )
    pe = PeImage(exe_path.read_bytes())
    ranges = pe.data_ranges()

    if args.report_json:
        data = json.loads(Path(args.report_json).read_text())["data"]
    else:
        data = run_report(args.target, Path(args.build_dir))

    votes: dict[tuple[int, str], int] = Counter()
    by_addr: dict[int, set[str]] = defaultdict(set)
    by_name: dict[str, set[int]] = defaultdict(set)

    for entity in data:
        if (entity.get("matching") or 0) < args.min_match:
            continue
        for hunk in entity.get("diff") or []:
            for block in hunk[1]:
                orig_lines = block.get("orig")
                recomp_lines = block.get("recomp")
                if not orig_lines or not recomp_lines:
                    continue
                if len(orig_lines) != len(recomp_lines):
                    continue
                for (oaddr, otext), (_raddr, rtext) in zip(orig_lines, recomp_lines):
                    if mnemonic(otext) != mnemonic(rtext):
                        continue
                    names = DATA_REF_RE.findall(rtext)
                    # exactly one plain (DATA) ref and no other annotation kinds
                    if len(names) != 1 or len(ANNOT_KIND_RE.findall(rtext)) != 1:
                        continue
                    if "+" in names[0]:
                        continue  # NAME+K offsets need base disambiguation
                    refs = instruction_data_refs(pe, int(oaddr, 16), ranges)
                    if len(set(refs)) != 1:
                        continue
                    addr = refs[0]
                    votes[(addr, names[0])] += 1
                    by_addr[addr].add(names[0])
                    by_name[names[0]].add(addr)

    known_addrs: dict[int, str] = {}
    with (repo_root / "config" / "symbols.csv").open() as fd:
        reader = csv.DictReader(fd, delimiter="|")
        for row in reader:
            try:
                known_addrs[int(row["address"], 16)] = row["name"]
            except ValueError:
                continue

    out_rows = []
    for (addr, name), n in sorted(votes.items(), key=lambda kv: -kv[1]):
        if n < args.min_votes:
            continue
        conflict = ""
        if len(by_addr[addr]) > 1:
            conflict = "addr->" + ",".join(sorted(by_addr[addr] - {name}))[:60]
        elif len(by_name[name]) > 1:
            conflict = "name->" + ",".join(hex(a) for a in sorted(by_name[name] - {addr}))[:60]
        out_rows.append(
            {
                "address": f"{addr:x}",
                "symbol": name,
                "votes": str(n),
                "conflict": conflict,
                "known_as": known_addrs.get(addr, ""),
            }
        )

    lines = ["address|symbol|votes|conflict|known_as"]
    lines += ["|".join(r[k] for k in ("address", "symbol", "votes", "conflict", "known_as")) for r in out_rows]
    payload = "\n".join(lines) + "\n"
    if args.out:
        Path(args.out).write_text(payload)
        clean = sum(1 for r in out_rows if not r["conflict"] and not r["known_as"])
        print(
            f"candidates={len(out_rows)} clean_new={clean} "
            f"(conflicts={sum(1 for r in out_rows if r['conflict'])}, "
            f"already_known={sum(1 for r in out_rows if r['known_as'])}) -> {args.out}"
        )
    else:
        sys.stdout.write(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
