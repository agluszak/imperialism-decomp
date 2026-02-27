#!/usr/bin/env python3
"""
Generate a redecomp-ready TradeControl contract markdown from existing artifacts.

Default inputs target batch723/batch724 outputs.
"""

from __future__ import annotations

import argparse
import csv
from collections import Counter
from pathlib import Path


def parse_int(text: str) -> int:
    t = text.strip().lower()
    if t.startswith("0x"):
        return int(t, 16)
    return int(t, 10)


def parse_struct_fields(struct_log: Path, type_path: str) -> tuple[int, list[tuple[int, str, str]]]:
    text = struct_log.read_text(encoding="utf-8", errors="ignore").splitlines()
    header = f"TYPE {type_path} size="
    size = 0
    fields: list[tuple[int, str, str]] = []
    in_block = False
    for line in text:
        if not in_block:
            if line.startswith(header):
                in_block = True
                size_s = line.split("size=")[-1].strip()
                size = parse_int(size_s)
            continue
        if not line.startswith("  +0x"):
            break
        # "  +0x04 fieldName : uint"
        try:
            left, right = line.strip().split(":", 1)
            off_s, name = left.split(" ", 1)
            off = parse_int(off_s.replace("+", ""))
            name = name.strip()
            dtype = right.strip()
            fields.append((off, name, dtype))
        except Exception:
            continue
    if not in_block:
        raise RuntimeError(f"type block not found: {type_path} in {struct_log}")
    return size, fields


def load_methods(csv_path: Path):
    rows = []
    with csv_path.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        for r in reader:
            try:
                addr = parse_int(r.get("address", ""))
            except Exception:
                continue
            name = (r.get("name") or "").strip()
            sig = (r.get("signature") or "").strip()
            ns = (r.get("namespace") or "").strip()
            rows.append(
                {
                    "address": addr,
                    "address_hex": f"0x{addr:08x}",
                    "name": name,
                    "signature": sig,
                    "namespace": ns,
                }
            )
    rows.sort(key=lambda x: x["address"])
    return rows


def split_primary_vs_thunks(rows):
    prim = [r for r in rows if not r["name"].startswith("thunk_")]
    th = [r for r in rows if r["name"].startswith("thunk_")]
    return prim, th


def parse_slot_consensus(class_target_pairs: str):
    parts = [p for p in class_target_pairs.split(";") if p]
    targets = []
    for part in parts:
        if ":" not in part:
            continue
        _, target = part.split(":", 1)
        target = target.strip()
        if target == "<none>":
            continue
        if "@0x" in target:
            name, addr = target.rsplit("@", 1)
            targets.append((name, addr))
        else:
            targets.append((target, ""))
    if not targets:
        return "<none>", "", 0, 0
    freq = Counter(targets)
    (best_name, best_addr), best_count = freq.most_common(1)[0]
    distinct = len(freq)
    total = sum(freq.values())
    return best_name, best_addr, distinct, best_count


def load_slots(slot_csv: Path, slot_limit: int):
    out = []
    with slot_csv.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        for r in reader:
            idx = int(r["slot_idx"])
            if idx >= slot_limit:
                continue
            off = r["slot_off"]
            method = r["interface_method"]
            distinct = int(r.get("distinct_target_count", "0") or 0)
            present = int(r.get("present_class_count", "0") or 0)
            best_name, best_addr, _, best_count = parse_slot_consensus(r.get("class_target_pairs", ""))
            if distinct <= 1:
                consensus = f"{best_name}@{best_addr}" if best_addr else best_name
            else:
                consensus = f"mixed ({distinct}); dominant={best_name}@{best_addr} ({best_count}/{present})"
            out.append(
                {
                    "idx": idx,
                    "off": off,
                    "method": method,
                    "present": present,
                    "distinct": distinct,
                    "consensus": consensus,
                }
            )
    out.sort(key=lambda x: x["idx"])
    return out


def write_contract(
    out_path: Path,
    struct_size: int,
    fields: list[tuple[int, str, str]],
    tcontrol_rows,
    trade_rows,
    slots,
    args,
):
    tcontrol_primary, tcontrol_thunks = split_primary_vs_thunks(tcontrol_rows)
    trade_primary, trade_thunks = split_primary_vs_thunks(trade_rows)

    named_fields = [f for f in fields if f[1] != "<anon>"]

    lines: list[str] = []
    lines.append("# TradeControl Redecomp Contract")
    lines.append("")
    lines.append("## Sources")
    lines.append(f"- struct: `{args.struct_log}` (`{args.struct_type_path}`)")
    lines.append(f"- TControl methods: `{args.tcontrol_methods}`")
    lines.append(f"- TradeControl methods: `{args.tradecontrol_methods}`")
    lines.append(f"- vtable slot summary: `{args.slot_summary}` (first `{args.slot_limit}` slots)")
    lines.append("")
    lines.append("## Field Layout")
    lines.append(f"- type: `{args.struct_type_path}`")
    lines.append(f"- size: `0x{struct_size:x}`")
    lines.append("")
    lines.append("| Offset | Name | Type |")
    lines.append("|---|---|---|")
    for off, name, dtype in named_fields:
        lines.append(f"| `+0x{off:02x}` | `{name}` | `{dtype}` |")
    lines.append("")
    lines.append("## Method Signatures")
    lines.append("")
    lines.append(f"### TControl primary (`{len(tcontrol_primary)}`)")
    lines.append("| Address | Signature |")
    lines.append("|---|---|")
    for r in tcontrol_primary:
        lines.append(f"| `{r['address_hex']}` | `{r['signature']}` |")
    lines.append("")
    lines.append(f"- TControl thunk mirrors: `{len(tcontrol_thunks)}` (kept in source CSV)")
    lines.append("")
    lines.append(f"### TradeControl primary (`{len(trade_primary)}`)")
    lines.append("| Address | Signature |")
    lines.append("|---|---|")
    for r in trade_primary:
        lines.append(f"| `{r['address_hex']}` | `{r['signature']}` |")
    lines.append("")
    lines.append(f"- TradeControl thunk mirrors: `{len(trade_thunks)}` (kept in source CSV)")
    lines.append("")
    lines.append("## VTable Slot Map")
    lines.append("| Slot | Offset | Interface Method | Consensus Target | Distinct Targets |")
    lines.append("|---|---|---|---|---|")
    for s in slots:
        lines.append(
            f"| `{s['idx']}` | `{s['off']}` | `{s['method']}` | `{s['consensus']}` | `{s['distinct']}` |"
        )
    lines.append("")
    lines.append("## Header Skeleton")
    lines.append("```cpp")
    lines.append("// Layout contract only; keep unresolved slots/methods as-is until stronger evidence.")
    lines.append("struct TControl;")
    lines.append("struct TradeControl;")
    lines.append("")
    lines.append("struct TradeControl {")
    lines.append("    void* pVtable;")
    for off, name, dtype in named_fields:
        if off == 0:
            continue
        lines.append(f"    // +0x{off:02x}: {dtype} {name};")
    lines.append("};")
    lines.append("```")
    lines.append("")

    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--struct-log",
        default="tmp_decomp/batch724_struct_dump_trade_tcontrol.log",
        help="Struct dump log path",
    )
    ap.add_argument("--struct-type-path", default="/TradeControl", help="Type path in struct dump")
    ap.add_argument(
        "--tcontrol-methods",
        default="tmp_decomp/batch723_tcontrol_methods_post_move.csv",
        help="TControl method CSV",
    )
    ap.add_argument(
        "--tradecontrol-methods",
        default="tmp_decomp/batch723_tradecontrol_methods_post_move.csv",
        help="TradeControl method CSV",
    )
    ap.add_argument(
        "--slot-summary",
        default="tmp_decomp/batch724_tradecontract_vtbl_slot_summary.csv",
        help="Trade vtable slot summary CSV",
    )
    ap.add_argument("--slot-limit", type=int, default=123, help="Number of interface slots to emit")
    ap.add_argument(
        "--out",
        default="tradecontrol_redecomp_contract.md",
        help="Output markdown path",
    )
    args = ap.parse_args()

    struct_log = Path(args.struct_log)
    tcontrol_methods = Path(args.tcontrol_methods)
    tradecontrol_methods = Path(args.tradecontrol_methods)
    slot_summary = Path(args.slot_summary)
    out_path = Path(args.out)

    size, fields = parse_struct_fields(struct_log, args.struct_type_path)
    t_rows = load_methods(tcontrol_methods)
    tc_rows = load_methods(tradecontrol_methods)
    slots = load_slots(slot_summary, args.slot_limit)

    write_contract(out_path, size, fields, t_rows, tc_rows, slots, args)
    print(
        f"[done] wrote {out_path} "
        f"(fields={len([f for f in fields if f[1] != '<anon>'])}, "
        f"tcontrol={len(t_rows)}, tradecontrol={len(tc_rows)}, slots={len(slots)})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

