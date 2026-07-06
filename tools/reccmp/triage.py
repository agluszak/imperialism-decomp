#!/usr/bin/env python3
"""Classify reccmp asm-diff mismatches into actionable buckets (`just triage`).

Reading a `just compare 0xADDR` diff and diagnosing WHY each line mismatches is
the hot path of the port loop. This automates the first pass: it walks the
structured diff from a full reccmp JSON report and buckets every mismatched
instruction pair, then prints per-bucket counts, examples, and the standard
next action from the decomp-loop heuristics:

  field_offset        same instruction, same base register, different this/other
                      offset -> class-layout error (declaration order, padding,
                      missing field)
  stack_layout        offset off EBP/ESP differs -> locals/EH-frame layout;
                      confirm with `just stackcmp 0xADDR`
  call_target         call resolves to a different function; reports the orig
                      callee's symbols.csv name + ownership (a stub callee often
                      means "port or pair the callee first")
  missing_annotation  recomp shows a (DATA)/(STRING)/(FLOAT) symbol where the
                      orig side is an unresolved <OFFSETn>/raw address -> add
                      // GLOBAL: / // STRING: (mine with `just global-xref-oracle`)
  constant            same shape, different immediate -> wrong constant/enum
                      (flagged when the orig value lies in .data/.rdata: it is
                      probably an address, i.e. an annotation gap)
  reg_alloc           identical modulo register names -> allocator noise; usually
                      statement order / temp reuse; chase LAST
  codegen             different instructions entirely (orig-only / recomp-only
                      runs land here) -> inlining, early returns, EH shape

Usage:
    just triage 0xADDR [0xADDR ...]          # or --file src/game/Foo.cpp
    (add --report-json to reuse a saved full report)
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

from tools.common.pipe_csv import read_pipe_rows
from tools.common.repo import repo_root_from_file
from tools.reccmp.compare_batch import addrs_from_file
from tools.reccmp.global_xref_oracle import PeImage, run_report
from tools.workflow.prune_ilt_thunks import original_exe_from_user_yml

SRC_TAG_RE = re.compile(r"\s*\t\([^)]*:\d+\)\s*$")
MEM_OFF_RE = re.compile(r"\[(e[a-z]{2})(?: \+ (0x[0-9a-fA-F]+))?\]")
REG_RE = re.compile(r"\b(e?[abcd]x|e?[sd]i|e?[bs]p|[abcd][lh])\b")
HEX_RE = re.compile(r"\b0x[0-9a-fA-F]+\b")
PLACEHOLDER_RE = re.compile(r"<OFFSET\d+>")
ANNOT_RE = re.compile(r"\((DATA|STRING|FLOAT|FUNCTION|IMPORT)\)")

SUGGESTIONS = {
    "field_offset": "class-layout error: check field declaration order/padding/missing "
                    "fields on the receiver class (ctor init placement, ASSERT_SIZE)",
    "stack_layout": "locals/frame layout: run `just stackcmp 0xADDR`; check local "
                    "declaration order and EH objects",
    "call_target": "wrong/unported callee: port it, fix the pairing, or fix the "
                   "dispatch (see per-line callee ownership below)",
    "missing_annotation": "unannotated global/string: add // GLOBAL: / // STRING: "
                          "(mine candidates with `just global-xref-oracle`)",
    "constant": "wrong immediate: enum/flag/constant value, or an address that needs "
                "a data annotation (marked 'in-data' below)",
    "reg_alloc": "register allocation only: usually statement order or temp reuse; "
                 "often resolves itself once real mismatches above are fixed",
    "codegen": "structural difference: inlining, early return, EH shape, or missing "
               "statements — read the block in context (`just compare 0xADDR`)",
}
BUCKET_ORDER = list(SUGGESTIONS)


def mnemonic(text: str) -> str:
    return text.split(None, 1)[0].lower() if text else ""


def clean(text: str) -> str:
    return SRC_TAG_RE.sub("", text).strip()


def classify_pair(otext: str, rtext: str, data_ranges, symbols, ownership):
    """(bucket, detail) for one paired orig/recomp instruction mismatch."""
    o, r = clean(otext), clean(rtext)
    if o == r:
        return None
    if mnemonic(o) != mnemonic(r):
        return "codegen", f"{o}  vs  {r}"

    if mnemonic(o) == "call":
        oop, rop = o[4:].strip(), r[4:].strip()
        if oop == rop:
            return None
        omem, rmem = MEM_OFF_RE.search(oop), MEM_OFF_RE.search(rop)
        if omem and rmem and omem.group(1) == rmem.group(1):
            return "call_target", (
                f"vtable slot {omem.group(2) or '0x0'} vs {rmem.group(2) or '0x0'} "
                f"via [{omem.group(1)}] — override in wrong slot or wrong class model"
            )
        m = HEX_RE.search(oop)
        if m and not omem:
            target = int(m.group(0), 16)
            name = symbols.get(target, "?")
            owner = ownership.get(target, "stub/unowned")
            return "call_target", f"orig callee 0x{target:x} {name} [{owner}]  vs  {rop}"
        return "call_target", f"{oop}  vs  {rop}"

    r_annot = ANNOT_RE.search(r)
    if r_annot and not ANNOT_RE.search(o) and (PLACEHOLDER_RE.search(o) or HEX_RE.search(o)):
        return "missing_annotation", f"recomp {r_annot.group(1)}: {r}  vs  orig: {o}"

    omems = MEM_OFF_RE.findall(o)
    rmems = MEM_OFF_RE.findall(r)
    if (
        omems
        and len(omems) == len(rmems)
        and [m[0] for m in omems] == [m[0] for m in rmems]
        and MEM_OFF_RE.sub("[M]", o) == MEM_OFF_RE.sub("[M]", r)
    ):
        for (reg, ooff), (_reg, roff) in zip(omems, rmems):
            if ooff != roff:
                bucket = "stack_layout" if reg in ("ebp", "esp") else "field_offset"
                return bucket, f"[{reg} + {ooff or '0x0'}] vs [{reg} + {roff or '0x0'}]  in  {o}"

    # Branch displacements drift as a *consequence* of other mismatches — not constants.
    if HEX_RE.sub("IMM", o) == HEX_RE.sub("IMM", r) and not mnemonic(o).startswith(("j", "loop")):
        ovals = HEX_RE.findall(o)
        rvals = HEX_RE.findall(r)
        for ov, rv in zip(ovals, rvals):
            if ov != rv:
                oint = int(ov, 16)
                in_data = any(lo <= oint < hi for lo, hi in data_ranges)
                note = " (orig value in-data: likely unannotated address)" if in_data else ""
                return "constant", f"{ov} vs {rv}{note}  in  {o}"

    if REG_RE.sub("R", o) == REG_RE.sub("R", r):
        return "reg_alloc", f"{o}  vs  {r}"

    return "codegen", f"{o}  vs  {r}"


def triage_entity(entity, data_ranges, symbols, ownership):
    """bucket -> [(orig_addr, detail)] for one report entity."""
    buckets: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for hunk in entity.get("diff") or []:
        for block in hunk[1]:
            if "both" in block:
                continue
            orig_lines = block.get("orig") or []
            recomp_lines = block.get("recomp") or []
            if orig_lines and len(orig_lines) == len(recomp_lines):
                for (oaddr, otext), (_raddr, rtext) in zip(orig_lines, recomp_lines):
                    verdict = classify_pair(otext, rtext, data_ranges, symbols, ownership)
                    if verdict:
                        buckets[verdict[0]].append((oaddr, verdict[1]))
            else:
                side = "orig-only" if orig_lines else "recomp-only"
                lines = orig_lines or recomp_lines
                if not lines:
                    continue
                preview = "; ".join(clean(t) for _a, t in lines[:3])
                addr = lines[0][0]
                buckets["codegen"].append(
                    (addr, f"{side} x{len(lines)}: {preview}")
                )
    return buckets


def load_symbol_maps(repo_root: Path):
    symbols: dict[int, str] = {}
    for row in read_pipe_rows(repo_root / "config" / "symbols.csv"):
        try:
            symbols[int(row["address"], 16)] = row.get("name") or ""
        except ValueError:
            continue
    ownership: dict[int, str] = {}
    for row in read_pipe_rows(repo_root / "config" / "function_ownership.csv"):
        try:
            ownership[int(row["address"], 16)] = row.get("ownership") or ""
        except ValueError:
            continue
    return symbols, ownership


def main() -> int:
    repo_root = repo_root_from_file(__file__)
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--target", default="IMPERIALISM")
    ap.add_argument("--build-dir", default=str(repo_root / "build-msvc500"))
    ap.add_argument("--report-json", default="", help="Reuse a saved full (non-diet) report")
    ap.add_argument("--original-exe", default="")
    ap.add_argument("--examples", type=int, default=8, help="Examples printed per bucket")
    ap.add_argument("--file", action="append", default=[], type=Path,
                    help="Triage every // FUNCTION marker in the file(s)")
    ap.add_argument("addrs", nargs="*", help="original-binary offsets (hex)")
    args = ap.parse_args()

    wanted = [int(a, 16) for a in args.addrs]
    for f in args.file:
        wanted.extend(addrs_from_file(f))
    if not wanted:
        print("no addresses given (pass hex offsets and/or --file SRC.cpp)", file=sys.stderr)
        return 2

    exe_path = (
        Path(args.original_exe) if args.original_exe else original_exe_from_user_yml(repo_root)
    )
    data_ranges = PeImage(exe_path.read_bytes()).data_ranges()
    symbols, ownership = load_symbol_maps(repo_root)

    if args.report_json:
        data = json.loads(Path(args.report_json).read_text())["data"]
    else:
        data = run_report(args.target, Path(args.build_dir))
    by_addr = {int(e["address"], 16): e for e in data}

    rc = 0
    for addr in wanted:
        entity = by_addr.get(addr)
        print("=" * 72)
        if entity is None:
            print(f"0x{addr:08x}: not in reccmp report (not paired? run `just addr`)")
            rc = 1
            continue
        pct = entity.get("matching", 0.0) * 100.0
        print(f"0x{addr:08x}  {pct:6.2f}%  {entity['name']}")
        if pct >= 100.0:
            print("  fully matching — nothing to triage")
            continue
        buckets = triage_entity(entity, data_ranges, symbols, ownership)
        if not buckets:
            print("  no diff hunks in report (score <100 without diff: check pairing)")
            continue
        counts = Counter({k: len(v) for k, v in buckets.items()})
        print("  buckets: " + "  ".join(f"{k}={counts[k]}" for k in BUCKET_ORDER if counts[k]))
        for bucket in BUCKET_ORDER:
            if bucket not in buckets:
                continue
            print(f"\n  [{bucket}] {SUGGESTIONS[bucket]}")
            for line_addr, detail in buckets[bucket][: args.examples]:
                print(f"    {line_addr}  {detail}")
            extra = len(buckets[bucket]) - args.examples
            if extra > 0:
                print(f"    ... {extra} more")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
