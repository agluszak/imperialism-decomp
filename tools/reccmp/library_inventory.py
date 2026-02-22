#!/usr/bin/env python3
"""Classify symbols into likely library buckets and summarize reccmp impact."""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path

from symbol_buckets import classify_name, parse_function_symbols, parse_reccmp_report


def parse_args() -> argparse.Namespace:
    repo_root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser()
    parser.add_argument("--symbols-csv", default=str(repo_root / "config" / "symbols.csv"))
    parser.add_argument(
        "--report-json",
        default=str(repo_root / "build-msvc500" / "reccmp_report.json"),
        help="reccmp JSON report path; used for per-bucket similarity stats if present.",
    )
    parser.add_argument("--top", type=int, default=12, help="Examples per bucket.")
    parser.add_argument(
        "--json-out",
        default="",
        help="Optional output JSON file with full bucket stats.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    symbols = parse_function_symbols(Path(args.symbols_csv))
    score_by_addr = parse_reccmp_report(Path(args.report_json))

    counts: Counter[str] = Counter()
    score_sum: defaultdict[str, float] = defaultdict(float)
    score_count: Counter[str] = Counter()
    aligned_count: Counter[str] = Counter()
    examples: defaultdict[str, list[tuple[int, str, float | None]]] = defaultdict(list)

    for symbol in symbols:
        addr = symbol.address
        name = symbol.name
        bucket = classify_name(name)
        counts[bucket] += 1
        score = score_by_addr.get(addr)
        if score is not None:
            score_sum[bucket] += score
            score_count[bucket] += 1
            if score >= 100.0:
                aligned_count[bucket] += 1
        if len(examples[bucket]) < args.top:
            examples[bucket].append((addr, name, score))

    total = sum(counts.values())
    print(f"total functions: {total}")
    print()
    print("bucket summary:")
    for bucket, n in counts.most_common():
        pct = (n / total) * 100.0 if total else 0.0
        if score_count[bucket]:
            avg = score_sum[bucket] / score_count[bucket]
            aligned = aligned_count[bucket]
            print(
                f"  {bucket:28s} {n:6d} ({pct:6.2f}%)  "
                f"reccmp: compared={score_count[bucket]:6d} avg={avg:6.2f}% aligned={aligned:5d}"
            )
        else:
            print(f"  {bucket:28s} {n:6d} ({pct:6.2f}%)")
    print()

    for bucket, _ in counts.most_common():
        print(f"{bucket} examples:")
        for addr, name, score in examples[bucket]:
            if score is None:
                print(f"  0x{addr:08x}  {name}")
            else:
                print(f"  0x{addr:08x}  {name}  ({score:.2f}%)")
        print()

    if args.json_out:
        out_path = Path(args.json_out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "total_functions": total,
            "buckets": {
                bucket: {
                    "count": counts[bucket],
                    "percent": (counts[bucket] / total) * 100.0 if total else 0.0,
                    "reccmp_compared": score_count[bucket],
                    "reccmp_avg_similarity": (
                        score_sum[bucket] / score_count[bucket] if score_count[bucket] else None
                    ),
                    "reccmp_aligned_count": aligned_count[bucket],
                    "examples": [
                        {
                            "address": f"0x{addr:08x}",
                            "name": name,
                            "similarity": score,
                        }
                        for addr, name, score in examples[bucket]
                    ],
                }
                for bucket in counts
            },
        }
        out_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        print(f"Wrote: {out_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
