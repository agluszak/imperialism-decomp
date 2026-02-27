#!/usr/bin/env python3
"""
Resolve class ownership for target functions using vtable slot references.

For each target function:
1) Collect direct DATA refs to target.
2) Optionally include single-JMP thunk wrappers to target, then collect DATA refs to those thunks.
3) Infer owner class from slot symbol names (best) or nearest enclosing g_vtblT* anchor.
4) Emit detailed evidence and a conservative attach-candidate CSV.

Usage:
  .venv/bin/python new_scripts/resolve_vtable_owner_for_targets.py \
    --targets 0x00584320 0x00584ea0 \
    --out-prefix tmp_decomp/trade_owner_probe
"""

from __future__ import annotations

import argparse
import csv
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

import pyghidra

GHIDRA_DIR = Path(
    "/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC"
)
PROJECT_NAME = "imperialism-decomp"
PROGRAM_PATH = "/Imperialism.exe"

RX_VTBL_BASE = re.compile(r"^g_vtbl(T[A-Za-z0-9_]+)$")
# Use non-greedy class capture to avoid folding nested suffixes like:
# g_vtblTTraderAmtBar_Slot198_Slot0318
RX_VTBL_SLOT = re.compile(r"^g_vtbl(T[A-Za-z0-9_]*?)_Slot([0-9]+)(?:_|$)")
RX_VSLOT = re.compile(r"^g_vslot(T[A-Za-z0-9_]*?)_Slot([0-9a-fA-F]+)(?:_|$)")


@dataclass
class EvidenceRow:
    target_addr: int
    target_name: str
    source_kind: str  # target | thunk
    source_addr: int
    source_name: str
    slot_addr: int
    slot_symbol: str
    owner_class: str
    owner_vtbl_addr: int
    slot_idx: int
    infer_mode: str  # symbol_slot | vtbl_span


def parse_hex(text: str) -> int:
    t = text.strip()
    if t.lower().startswith("0x"):
        return int(t, 16)
    return int(t, 16)


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


def collect_vtbl_anchors(st) -> list[tuple[int, str]]:
    anchors: list[tuple[int, str]] = []
    it = st.getAllSymbols(True)
    while it.hasNext():
        s = it.next()
        name = s.getName()
        m = RX_VTBL_BASE.match(name)
        if not m:
            continue
        # Keep only canonical vtbl anchors, not per-slot labels.
        if "_Slot" in name:
            continue
        try:
            a = parse_hex(str(s.getAddress()))
        except Exception:
            continue
        anchors.append((a, m.group(1)))
    anchors.sort(key=lambda x: x[0])
    return anchors


def is_single_jmp_to(program, func, target_addr: int) -> bool:
    listing = program.getListing()
    insns = []
    it = listing.getInstructions(func.getBody(), True)
    while it.hasNext():
        insns.append(it.next())
    if len(insns) != 1:
        return False
    ins = insns[0]
    if str(ins.getMnemonicString()).upper() != "JMP":
        return False
    for r in ins.getReferencesFrom():
        to_addr = addr_u32(r.getToAddress())
        if to_addr == target_addr:
            return True
    return False


def infer_owner_for_slot(
    slot_addr: int, slot_symbol_name: str, vtbl_anchors: list[tuple[int, str]]
) -> tuple[str, int, int, str] | None:
    # Highest confidence: explicit slot symbol names.
    m = RX_VTBL_SLOT.match(slot_symbol_name or "")
    if m:
        cname = m.group(1)
        sidx = int(m.group(2))
        return cname, slot_addr - sidx * 4, sidx, "symbol_slot"
    m = RX_VSLOT.match(slot_symbol_name or "")
    if m:
        cname = m.group(1)
        sidx = int(m.group(2), 16) // 4
        return cname, slot_addr - sidx * 4, sidx, "symbol_slot"

    # Fallback: nearest enclosing g_vtblT* span.
    if not vtbl_anchors:
        return None
    lo = None
    hi = None
    for i, (addr, cname) in enumerate(vtbl_anchors):
        if addr <= slot_addr:
            lo = (addr, cname, i)
        if addr > slot_addr:
            hi = (addr, cname, i)
            break
    if lo is None:
        return None
    base_addr, cname, _idx = lo
    if hi is not None and slot_addr >= hi[0]:
        return None
    delta = slot_addr - base_addr
    if delta < 0 or delta % 4 != 0:
        return None
    return cname, base_addr, delta // 4, "vtbl_span"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--targets", nargs="+", required=True, help="Function entry addresses")
    ap.add_argument("--include-jmp-thunks", action="store_true", default=True)
    ap.add_argument(
        "--out-prefix",
        default="tmp_decomp/target_owner_probe",
        help="Output prefix (without extension)",
    )
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    target_addrs = [parse_hex(x) for x in args.targets]
    root = Path(args.project_root).resolve()
    out_prefix = Path(args.out_prefix)
    if not out_prefix.is_absolute():
        out_prefix = root / out_prefix
    out_prefix.parent.mkdir(parents=True, exist_ok=True)

    out_evidence = out_prefix.with_name(out_prefix.name + "_evidence.csv")
    out_summary = out_prefix.with_name(out_prefix.name + "_summary.csv")
    out_attach = out_prefix.with_name(out_prefix.name + "_attach.csv")

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    evidence_rows: list[EvidenceRow] = []

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()
        rm = program.getReferenceManager()
        st = program.getSymbolTable()

        vtbl_anchors = collect_vtbl_anchors(st)

        for taddr in target_addrs:
            tf = fm.getFunctionAt(af.getAddress(f"0x{taddr:08x}"))
            if tf is None:
                print(f"[warn] missing function at 0x{taddr:08x}")
                continue
            target_name = tf.getName()

            sources: list[tuple[str, int, str]] = [("target", taddr, target_name)]
            if args.include_jmp_thunks:
                refs = rm.getReferencesTo(tf.getEntryPoint())
                while refs.hasNext():
                    r = refs.next()
                    caller = fm.getFunctionContaining(r.getFromAddress())
                    if caller is None:
                        continue
                    caddr = addr_u32(caller.getEntryPoint())
                    if caddr == taddr:
                        continue
                    if is_single_jmp_to(program, caller, taddr):
                        sources.append(("thunk", caddr, caller.getName()))

            # Dedup sources while preserving order.
            seen = set()
            dedup_sources = []
            for row in sources:
                key = (row[0], row[1])
                if key in seen:
                    continue
                seen.add(key)
                dedup_sources.append(row)

            for skind, saddr, sname in dedup_sources:
                sfunc = fm.getFunctionAt(af.getAddress(f"0x{saddr:08x}"))
                refs = rm.getReferencesTo(sfunc.getEntryPoint() if sfunc else af.getAddress(f"0x{saddr:08x}"))
                while refs.hasNext():
                    r = refs.next()
                    if not r.getReferenceType().isData():
                        continue
                    from_addr = r.getFromAddress()
                    slot_addr = addr_u32(from_addr)
                    sym = st.getPrimarySymbol(from_addr)
                    sslot = sym.getName() if sym is not None else ""

                    inferred = infer_owner_for_slot(slot_addr, sslot, vtbl_anchors)
                    if inferred is None:
                        continue
                    owner_class, owner_vtbl_addr, slot_idx, mode = inferred
                    evidence_rows.append(
                        EvidenceRow(
                            target_addr=taddr,
                            target_name=target_name,
                            source_kind=skind,
                            source_addr=saddr,
                            source_name=sname,
                            slot_addr=slot_addr,
                            slot_symbol=sslot,
                            owner_class=owner_class,
                            owner_vtbl_addr=owner_vtbl_addr,
                            slot_idx=slot_idx,
                            infer_mode=mode,
                        )
                    )

    # Write evidence.
    with out_evidence.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=[
                "target_addr",
                "target_name",
                "source_kind",
                "source_addr",
                "source_name",
                "slot_addr",
                "slot_symbol",
                "owner_class",
                "owner_vtbl_addr",
                "slot_idx",
                "infer_mode",
            ],
        )
        w.writeheader()
        for r in evidence_rows:
            w.writerow(
                {
                    "target_addr": f"0x{r.target_addr:08x}",
                    "target_name": r.target_name,
                    "source_kind": r.source_kind,
                    "source_addr": f"0x{r.source_addr:08x}",
                    "source_name": r.source_name,
                    "slot_addr": f"0x{r.slot_addr:08x}",
                    "slot_symbol": r.slot_symbol,
                    "owner_class": r.owner_class,
                    "owner_vtbl_addr": f"0x{r.owner_vtbl_addr:08x}",
                    "slot_idx": r.slot_idx,
                    "infer_mode": r.infer_mode,
                }
            )

    # Aggregate -> conservative attach candidates.
    by_target: dict[int, list[EvidenceRow]] = defaultdict(list)
    for r in evidence_rows:
        by_target[r.target_addr].append(r)

    summary_rows = []
    attach_rows = []
    for taddr in sorted(by_target):
        rs = by_target[taddr]
        tname = rs[0].target_name
        owner_counts = Counter(r.owner_class for r in rs)
        owner_unique = sorted(owner_counts)
        top_owner = owner_counts.most_common(1)[0][0]
        top_count = owner_counts[top_owner]
        strong_unique = 1 if len(owner_unique) == 1 else 0
        inferred_modes = sorted({r.infer_mode for r in rs})
        slot_samples = sorted({f"0x{r.slot_addr:08x}" for r in rs})[:8]
        summary_rows.append(
            {
                "target_addr": f"0x{taddr:08x}",
                "target_name": tname,
                "evidence_rows": len(rs),
                "owner_class_count": len(owner_unique),
                "owner_classes": ";".join(owner_unique),
                "top_owner_class": top_owner,
                "top_owner_hits": top_count,
                "strong_unique_owner": strong_unique,
                "infer_modes": ";".join(inferred_modes),
                "slot_samples": ";".join(slot_samples),
            }
        )
        if strong_unique:
            attach_rows.append(
                {
                    "address": f"0x{taddr:08x}",
                    "class_name": top_owner,
                    "reason": "single-owner by vtable slot refs",
                }
            )

    with out_summary.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=[
                "target_addr",
                "target_name",
                "evidence_rows",
                "owner_class_count",
                "owner_classes",
                "top_owner_class",
                "top_owner_hits",
                "strong_unique_owner",
                "infer_modes",
                "slot_samples",
            ],
        )
        w.writeheader()
        w.writerows(summary_rows)

    with out_attach.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["address", "class_name", "reason"])
        w.writeheader()
        w.writerows(attach_rows)

    print(f"[done] evidence={out_evidence} rows={len(evidence_rows)}")
    print(f"[done] summary={out_summary} rows={len(summary_rows)}")
    print(f"[done] attach={out_attach} rows={len(attach_rows)}")
    for r in summary_rows[:80]:
        print(
            f"{r['target_addr']} {r['target_name']} owners={r['owner_classes']} "
            f"strong={r['strong_unique_owner']} hits={r['evidence_rows']}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
