#!/usr/bin/env python3
"""Run targeted reccmp compares for canary addresses and summarize progress."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.common.pipe_csv import read_pipe_rows
from tools.common.repo import repo_root_from_file, resolve_repo_path

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
MATCH_100_RE = re.compile(r"0x[0-9a-fA-F]+:\s+(.+?)\s+([0-9]+(?:\.[0-9]+)?)% match\.")
MATCH_SIMILAR_RE = re.compile(r"^(.+?) is only ([0-9]+(?:\.[0-9]+)?)% similar")


def parse_args() -> argparse.Namespace:
    repo_root = repo_root_from_file(__file__)
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="IMPERIALISM")
    parser.add_argument("--build-dir", default=str(repo_root / "build-msvc500"))
    parser.add_argument(
        "--canary-csv",
        default=str(repo_root / "config" / "canary_targets_tgreatpower.csv"),
        help="Pipe-delimited canary config.",
    )
    parser.add_argument(
        "--output-json",
        default="canary_snapshot_tgreatpower.json",
        help="Path relative to --build-dir unless absolute.",
    )
    parser.add_argument(
        "--fail-on-below-floor",
        action="store_true",
        help="Exit non-zero if any canary is below floor or unparseable.",
    )
    return parser.parse_args()


def parse_float(raw: str) -> float | None:
    value = raw.strip()
    if not value:
        return None
    return float(value)


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


def parse_similarity(output_text: str) -> tuple[float | None, str | None]:
    clean = strip_ansi(output_text)
    pct: float | None = None
    symbol_name: str | None = None
    for line in clean.splitlines():
        line = line.strip()
        if not line:
            continue
        m_100 = MATCH_100_RE.search(line)
        if m_100 is not None:
            symbol_name = m_100.group(1).strip()
            pct = float(m_100.group(2))
            continue
        m_sim = MATCH_SIMILAR_RE.search(line)
        if m_sim is not None:
            symbol_name = m_sim.group(1).strip()
            pct = float(m_sim.group(2))
    return pct, symbol_name


def status_for_score(score: float | None, floor: float | None, stretch: float | None) -> str:
    if score is None:
        return "parse_error"
    if stretch is not None and score >= stretch:
        return "stretch_met"
    if floor is not None and score >= floor:
        return "floor_met"
    if floor is not None and score < floor:
        return "below_floor"
    return "ok"


def resolve_output_json(build_dir: Path, output_arg: str) -> Path:
    output = Path(output_arg)
    if output.is_absolute():
        return output
    return build_dir / output


def main() -> int:
    args = parse_args()
    repo_root = repo_root_from_file(__file__)
    build_dir = resolve_repo_path(repo_root, args.build_dir)
    canary_csv = resolve_repo_path(repo_root, args.canary_csv)
    output_json = resolve_output_json(build_dir, args.output_json)

    rows = read_pipe_rows(canary_csv)
    if not rows:
        raise RuntimeError(f"No canaries in {canary_csv}")

    results: list[dict[str, Any]] = []

    for row in rows:
        address = (row.get("address") or "").strip()
        if not address:
            continue
        expected_name = (row.get("name") or "").strip()
        priority = (row.get("priority") or "").strip()
        floor = parse_float(row.get("floor") or "")
        stretch = parse_float(row.get("stretch") or "")

        cmd = [
            "uv",
            "run",
            "reccmp-reccmp",
            "--target",
            args.target,
            "--verbose",
            address,
        ]
        proc = subprocess.run(
            cmd,
            cwd=build_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
        output = proc.stdout
        score, parsed_name = parse_similarity(output)
        result = {
            "address": address,
            "name": expected_name,
            "priority": priority,
            "floor": floor,
            "stretch": stretch,
            "score": score,
            "parsed_name": parsed_name,
            "status": status_for_score(score, floor, stretch),
            "return_code": proc.returncode,
        }
        if score is not None and floor is not None:
            result["delta_to_floor"] = round(score - floor, 2)
        if score is not None and stretch is not None:
            result["delta_to_stretch"] = round(score - stretch, 2)
        results.append(result)

    output_json.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "target": args.target,
        "build_dir": str(build_dir),
        "canary_csv": str(canary_csv),
        "results": results,
    }
    output_json.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    print(f"Target: {args.target}")
    print(f"Build dir: {build_dir}")
    print(f"Canary file: {canary_csv}")
    print(f"Snapshot: {output_json}")
    print("")
    print("Address      Score   Floor  Stretch  Status        Name")
    print("-----------  ------  -----  -------  ------------  ------------------------------")
    below_count = 0
    parse_error_count = 0
    for result in results:
        score = result["score"]
        floor = result["floor"]
        stretch = result["stretch"]
        status = result["status"]
        name = result["name"] or (result["parsed_name"] or "")
        score_str = f"{score:.2f}%" if score is not None else "n/a"
        floor_str = f"{floor:.2f}%" if floor is not None else "-"
        stretch_str = f"{stretch:.2f}%" if stretch is not None else "-"
        print(
            f"{result['address']:<11}  {score_str:>6}  {floor_str:>5}  {stretch_str:>7}  "
            f"{status:<12}  {name}"
        )
        if status == "below_floor":
            below_count += 1
        if status == "parse_error":
            parse_error_count += 1

    print("")
    print(
        f"Summary: total={len(results)}, below_floor={below_count}, parse_error={parse_error_count}"
    )

    if args.fail_on_below_floor and (below_count > 0 or parse_error_count > 0):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
