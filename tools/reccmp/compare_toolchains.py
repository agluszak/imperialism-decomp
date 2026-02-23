#!/usr/bin/env python3
"""Compare function similarity between two build directories/toolchains."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


def parse_args() -> argparse.Namespace:
    repo_root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser()
    parser.add_argument("--a-name", default="msvc500")
    parser.add_argument("--a-build", default=str(repo_root / "build-msvc500"))
    parser.add_argument("--b-name", default="msvc420")
    parser.add_argument("--b-build", default=str(repo_root / "build-msvc420"))
    parser.add_argument("--report", default="reccmp_report.json")
    parser.add_argument(
        "--mode",
        choices=("global", "manual-sources"),
        default="manual-sources",
        help="global = top deltas across all functions; manual-sources = src/game grouped report",
    )
    parser.add_argument("--top", type=int, default=15)
    parser.add_argument("--src-root", default=str(repo_root / "src" / "game"))
    return parser.parse_args()


def load_report(path: Path) -> dict[int, float]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    result: dict[int, float] = {}
    for row in raw.get("data", []):
        addr = int(row["address"], 16)
        result[addr] = float(row.get("matching", 0.0)) * 100.0
    return result


def iter_manual_function_addresses(src_root: Path) -> dict[str, list[int]]:
    annot = re.compile(r"^\s*//\s*FUNCTION:\s*IMPERIALISM\s+0x([0-9A-Fa-f]+)\s*$")
    per_file: dict[str, list[int]] = {}
    for cpp in sorted(src_root.glob("*.cpp")):
        addrs: list[int] = []
        for line in cpp.read_text(encoding="utf-8", errors="ignore").splitlines():
            match = annot.match(line)
            if match:
                addrs.append(int(match.group(1), 16))
        if addrs:
            per_file[cpp.as_posix()] = addrs
    return per_file


def run_global(a_name: str, a: dict[int, float], b_name: str, b: dict[int, float], top: int) -> int:
    keys = sorted(set(a) & set(b))
    if not keys:
        print("No overlapping function addresses between reports.")
        return 1

    rows = []
    for addr in keys:
        a_val = a.get(addr, 0.0)
        b_val = b.get(addr, 0.0)
        rows.append((b_val - a_val, addr, a_val, b_val))

    avg_a = sum(r[2] for r in rows) / len(rows)
    avg_b = sum(r[3] for r in rows) / len(rows)
    better_b = sum(1 for r in rows if r[0] > 0.0001)
    better_a = sum(1 for r in rows if r[0] < -0.0001)
    same = len(rows) - better_a - better_b

    print(f"Compared: {len(rows)}")
    print(f"{a_name} better: {better_a} | {b_name} better: {better_b} | same: {same}")
    print(f"Average similarity: {a_name}={avg_a:.4f}% {b_name}={avg_b:.4f}% delta={avg_b - avg_a:+.4f} pp")
    print("")

    print(f"Top {top} where {b_name} is better:")
    for delta, addr, a_val, b_val in sorted((r for r in rows if r[0] > 0.0001), reverse=True)[:top]:
        print(f"  0x{addr:08X}  {a_name}={a_val:6.2f}%  {b_name}={b_val:6.2f}%  delta={delta:+6.2f}pp")
    print("")
    print(f"Top {top} where {a_name} is better:")
    for delta, addr, a_val, b_val in sorted((r for r in rows if r[0] < -0.0001))[:top]:
        print(f"  0x{addr:08X}  {a_name}={a_val:6.2f}%  {b_name}={b_val:6.2f}%  delta={delta:+6.2f}pp")
    return 0


def run_manual_sources(
    a_name: str,
    a: dict[int, float],
    b_name: str,
    b: dict[int, float],
    src_root: Path,
    top: int,
) -> int:
    per_file = iter_manual_function_addresses(src_root)
    if not per_file:
        print(f"No FUNCTION annotations found in {src_root}")
        return 1

    print("Manual source comparison (FUNCTION annotations)\n")
    for path, addrs in per_file.items():
        rows = []
        for addr in addrs:
            a_val = a.get(addr, 0.0)
            b_val = b.get(addr, 0.0)
            rows.append((addr, a_val, b_val, b_val - a_val))

        avg_a = sum(r[1] for r in rows) / len(rows)
        avg_b = sum(r[2] for r in rows) / len(rows)
        print(
            f"{path}: count={len(rows)} "
            f"avg_{a_name}={avg_a:.2f}% avg_{b_name}={avg_b:.2f}% "
            f"delta={avg_b - avg_a:+.2f}pp"
        )
        for addr, a_val, b_val, delta in sorted(rows, key=lambda r: abs(r[3]), reverse=True)[:top]:
            print(
                f"  0x{addr:08X}  {a_name}={a_val:6.2f}%  "
                f"{b_name}={b_val:6.2f}%  delta={delta:+6.2f}pp"
            )
        print("")
    return 0


def main() -> int:
    args = parse_args()
    a_build = Path(args.a_build)
    b_build = Path(args.b_build)
    report_rel = Path(args.report)

    a = load_report(a_build / report_rel)
    b = load_report(b_build / report_rel)

    if args.mode == "global":
        return run_global(args.a_name, a, args.b_name, b, args.top)

    return run_manual_sources(
        args.a_name,
        a,
        args.b_name,
        b,
        Path(args.src_root),
        args.top,
    )


if __name__ == "__main__":
    raise SystemExit(main())
