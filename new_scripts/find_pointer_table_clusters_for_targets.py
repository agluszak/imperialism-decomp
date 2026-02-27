#!/usr/bin/env python3
"""
Find contiguous dword pointer-table clusters that reference a target address set.

Typical usage (TradeControl vtable hunting):
  .venv/bin/python new_scripts/find_pointer_table_clusters_for_targets.py \
    --targets-csv tmp_decomp/batch785_tradecontrol_namespace_all.csv \
    --out-hits-csv tmp_decomp/batch785_tradecontrol_ptr_hits.csv \
    --out-clusters-csv tmp_decomp/batch785_tradecontrol_ptr_clusters.csv
"""

from __future__ import annotations

import argparse
import csv
from collections import Counter, defaultdict
from pathlib import Path

import pyghidra

GHIDRA_DIR = Path(
    "/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC"
)
PROJECT_NAME = "imperialism-decomp"
PROGRAM_PATH = "/Imperialism.exe"


def parse_hex(text: str) -> int:
    t = text.strip().lower()
    if t.startswith("0x"):
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


def load_target_set(path: Path, column: str) -> set[int]:
    rows = list(csv.DictReader(path.open("r", encoding="utf-8", newline="")))
    out: set[int] = set()
    for row in rows:
        raw = (row.get(column) or "").strip()
        if not raw:
            continue
        try:
            out.add(parse_hex(raw))
        except Exception:
            continue
    return out


def fmt_addr(v: int) -> str:
    return f"0x{v:08x}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--targets-csv", required=True, help="CSV containing target addresses")
    ap.add_argument(
        "--targets-col",
        default="address",
        help="CSV column with addresses (default: address)",
    )
    ap.add_argument(
        "--min-cluster-len",
        type=int,
        default=4,
        help="Minimum contiguous hit-run length to keep",
    )
    ap.add_argument(
        "--addr-min",
        default="",
        help="Optional scan start address (inclusive)",
    )
    ap.add_argument(
        "--addr-max",
        default="",
        help="Optional scan end address (inclusive)",
    )
    ap.add_argument("--out-hits-csv", required=True)
    ap.add_argument("--out-clusters-csv", required=True)
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    root = Path(args.project_root).resolve()
    targets_csv = Path(args.targets_csv)
    if not targets_csv.is_absolute():
        targets_csv = root / targets_csv
    if not targets_csv.exists():
        print(f"[error] missing targets csv: {targets_csv}")
        return 1

    out_hits = Path(args.out_hits_csv)
    if not out_hits.is_absolute():
        out_hits = root / out_hits
    out_clusters = Path(args.out_clusters_csv)
    if not out_clusters.is_absolute():
        out_clusters = root / out_clusters
    out_hits.parent.mkdir(parents=True, exist_ok=True)
    out_clusters.parent.mkdir(parents=True, exist_ok=True)

    targets = load_target_set(targets_csv, args.targets_col)
    if not targets:
        print("[error] no target addresses parsed")
        return 1

    scan_min = parse_hex(args.addr_min) if args.addr_min else None
    scan_max = parse_hex(args.addr_max) if args.addr_max else None

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    hits: list[dict[str, str]] = []
    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        mem = program.getMemory()
        st = program.getSymbolTable()
        fm = program.getFunctionManager()
        af = program.getAddressFactory().getDefaultAddressSpace()

        for block in mem.getBlocks():
            if not block.isInitialized():
                continue
            bstart = block.getStart().getOffset() & 0xFFFFFFFF
            bend = block.getEnd().getOffset() & 0xFFFFFFFF
            if scan_min is not None and bend < scan_min:
                continue
            if scan_max is not None and bstart > scan_max:
                continue

            addr_i = bstart
            while addr_i + 3 <= bend:
                if scan_min is not None and addr_i < scan_min:
                    addr_i += 4
                    continue
                if scan_max is not None and addr_i > scan_max:
                    break
                addr = af.getAddress(fmt_addr(addr_i))
                try:
                    v = mem.getInt(addr) & 0xFFFFFFFF
                except Exception:
                    addr_i += 4
                    continue
                if v in targets:
                    slot_sym_obj = st.getPrimarySymbol(addr)
                    slot_sym = slot_sym_obj.getName() if slot_sym_obj is not None else ""
                    fn = fm.getFunctionAt(af.getAddress(fmt_addr(v)))
                    target_name = fn.getName() if fn is not None else ""
                    target_ns = ""
                    if fn is not None:
                        ns = fn.getParentNamespace()
                        if ns is not None:
                            target_ns = ns.getName()
                    hits.append(
                        {
                            "slot_addr": fmt_addr(addr_i),
                            "slot_block": block.getName(),
                            "slot_symbol": slot_sym,
                            "value_addr": fmt_addr(v),
                            "value_name": target_name,
                            "value_namespace": target_ns,
                        }
                    )
                addr_i += 4

    hits.sort(key=lambda r: (r["slot_block"], r["slot_addr"]))
    with out_hits.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=[
                "slot_addr",
                "slot_block",
                "slot_symbol",
                "value_addr",
                "value_name",
                "value_namespace",
            ],
        )
        w.writeheader()
        w.writerows(hits)

    by_block: dict[str, list[dict[str, str]]] = defaultdict(list)
    for h in hits:
        by_block[h["slot_block"]].append(h)

    clusters: list[dict[str, str]] = []
    for block_name, rows in by_block.items():
        rows.sort(key=lambda r: parse_hex(r["slot_addr"]))
        run: list[dict[str, str]] = []
        for row in rows:
            cur = parse_hex(row["slot_addr"])
            if not run:
                run = [row]
                continue
            prev = parse_hex(run[-1]["slot_addr"])
            if cur - prev == 4:
                run.append(row)
                continue
            if len(run) >= args.min_cluster_len:
                unique_targets = sorted({r["value_addr"] for r in run})
                names = Counter(
                    (r["value_name"] or r["value_addr"]) for r in run
                ).most_common(8)
                clusters.append(
                    {
                        "slot_block": block_name,
                        "cluster_start": run[0]["slot_addr"],
                        "cluster_end": run[-1]["slot_addr"],
                        "hit_count": str(len(run)),
                        "unique_target_count": str(len(unique_targets)),
                        "top_targets": ";".join(f"{name}:{cnt}" for name, cnt in names),
                    }
                )
            run = [row]
        if len(run) >= args.min_cluster_len:
            unique_targets = sorted({r["value_addr"] for r in run})
            names = Counter((r["value_name"] or r["value_addr"]) for r in run).most_common(8)
            clusters.append(
                {
                    "slot_block": block_name,
                    "cluster_start": run[0]["slot_addr"],
                    "cluster_end": run[-1]["slot_addr"],
                    "hit_count": str(len(run)),
                    "unique_target_count": str(len(unique_targets)),
                    "top_targets": ";".join(f"{name}:{cnt}" for name, cnt in names),
                }
            )

    clusters.sort(
        key=lambda r: (
            -int(r["hit_count"]),
            -int(r["unique_target_count"]),
            r["cluster_start"],
        )
    )
    with out_clusters.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=[
                "slot_block",
                "cluster_start",
                "cluster_end",
                "hit_count",
                "unique_target_count",
                "top_targets",
            ],
        )
        w.writeheader()
        w.writerows(clusters)

    print(f"[done] targets={len(targets)} hits={len(hits)} clusters={len(clusters)}")
    print(f"[saved] {out_hits}")
    print(f"[saved] {out_clusters}")
    for c in clusters[:40]:
        print(
            f"[cluster] {c['cluster_start']}..{c['cluster_end']} block={c['slot_block']} "
            f"hits={c['hit_count']} unique={c['unique_target_count']} top={c['top_targets']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
