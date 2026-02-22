#!/usr/bin/env python3
"""Sweep old-MSVC compile flag profiles and score with reccmp."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Profile:
    name: str
    flags_csv: str = ""
    link_flags_csv: str = ""


DEFAULT_PROFILES: list[Profile] = [
    Profile("baseline", ""),
    Profile("o1_ob1_oy_off", "/O1,/Ob1,/Oy-"),
    Profile("o1_ob2_oy_off", "/O1,/Ob2,/Oy-"),
    Profile("o2_ob1_oy_off", "/O2,/Ob1,/Oy-"),
    Profile("o2_ob2_oy_off", "/O2,/Ob2,/Oy-"),
    Profile("o2_ob2_oy_on", "/O2,/Ob2,/Oy"),
    Profile("o2_ob2_oy_on_gf_gy", "/O2,/Ob2,/Oy,/Gf,/Gy"),
]


def parse_args() -> argparse.Namespace:
    repo_root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="IMPERIALISM")
    parser.add_argument("--docker-image", default="imperialism-msvc500")
    parser.add_argument(
        "--docker-network",
        default="none",
        help="Docker network mode used for build container (default: none).",
    )
    parser.add_argument("--build-root", default=str(repo_root / "build-flag-sweep"))
    parser.add_argument(
        "--profile",
        action="append",
        default=[],
        help="Run only selected profile name(s); repeatable.",
    )
    parser.add_argument(
        "--address",
        action="append",
        default=["0x00606fc0", "0x00606fd2"],
        help="Address to report per-profile similarity for (hex). Repeatable.",
    )
    parser.add_argument(
        "--json-out",
        default="",
        help="Optional path for full sweep results JSON.",
    )
    return parser.parse_args()


def parse_addr(text: str) -> int:
    s = text.strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    return int(s, 16)


def run(cmd: list[str], cwd: Path) -> None:
    subprocess.run(cmd, cwd=cwd, check=True)


def run_capture(cmd: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=cwd, check=True, text=True, capture_output=True)


def parse_report(path: Path, sample_addrs: list[int]) -> dict:
    report = json.loads(path.read_text(encoding="utf-8"))
    rows = report.get("data", [])
    aligned = 0
    total_matching = 0.0
    by_addr: dict[int, float] = {}

    for row in rows:
        matching = float(row.get("matching", 0.0))
        total_matching += matching
        if matching >= 1.0:
            aligned += 1
        addr_text = str(row.get("address", "")).strip().lower()
        if addr_text.startswith("0x"):
            try:
                addr = int(addr_text[2:], 16)
                by_addr[addr] = matching * 100.0
            except ValueError:
                pass

    compared = len(rows)
    avg_matching = (total_matching / compared) * 100.0 if compared else 0.0
    out = {
        "compared": compared,
        "aligned": aligned,
        "avg_matching_pct": avg_matching,
        "samples": {f"0x{a:08x}": by_addr.get(a, -1.0) for a in sample_addrs},
    }
    return out


def make_cmake_flags(profile: Profile) -> str:
    parts = ["-DCMAKE_BUILD_TYPE=RelWithDebInfo"]
    if profile.flags_csv:
        parts.append(f"-DIMPERIALISM_MATCH_FLAGS_CSV={profile.flags_csv}")
    if profile.link_flags_csv:
        parts.append(f"-DIMPERIALISM_MATCH_LINK_FLAGS_CSV={profile.link_flags_csv}")
    return " ".join(parts)


def main() -> int:
    try:
        args = parse_args()
        repo_root = Path(__file__).resolve().parents[2]
        build_root = Path(args.build_root).resolve()
        build_root.mkdir(parents=True, exist_ok=True)

        requested = set(args.profile)
        profiles = [
            p for p in DEFAULT_PROFILES if not requested or p.name in requested
        ]
        if not profiles:
            raise RuntimeError("No profiles selected.")

        sample_addrs = [parse_addr(a) for a in args.address]

        results: list[dict] = []
        for profile in profiles:
            build_dir = build_root / profile.name
            build_dir.mkdir(parents=True, exist_ok=True)

            cmake_flags = make_cmake_flags(profile)
            print(f"[{profile.name}] build with CMAKE_FLAGS={cmake_flags}")
            run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--network",
                    args.docker_network,
                    "-e",
                    f"CMAKE_FLAGS={cmake_flags}",
                    "-v",
                    f"{repo_root}:/imperialism",
                    "-v",
                    f"{build_dir}:/build",
                    args.docker_image,
                ],
                cwd=repo_root,
            )

            run(
                ["uv", "run", "reccmp-project", "detect", "--what", "recompiled"],
                cwd=build_dir,
            )
            report_path = build_dir / "reccmp_report.json"
            run(
                [
                    "uv",
                    "run",
                    "reccmp-reccmp",
                    "--target",
                    args.target,
                    "--json",
                    str(report_path),
                    "--silent",
                    "--no-color",
                ],
                cwd=build_dir,
            )

            stats = parse_report(report_path, sample_addrs)
            entry = {
                "profile": profile.name,
                "flags_csv": profile.flags_csv,
                "link_flags_csv": profile.link_flags_csv,
                **stats,
            }
            results.append(entry)
            print(
                "[{}] aligned={} avg={:.2f}%".format(
                    profile.name,
                    entry["aligned"],
                    entry["avg_matching_pct"],
                )
            )

        results.sort(
            key=lambda r: (int(r["aligned"]), float(r["avg_matching_pct"])),
            reverse=True,
        )

        print("\nProfile ranking:")
        for idx, row in enumerate(results, start=1):
            sample_bits = " ".join(
                f"{addr}={score:.2f}%"
                for addr, score in row["samples"].items()
            )
            print(
                "{}. {} aligned={} avg={:.2f}% {}".format(
                    idx,
                    row["profile"],
                    row["aligned"],
                    row["avg_matching_pct"],
                    sample_bits,
                )
            )

        if args.json_out:
            out_path = Path(args.json_out).resolve()
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
            print(f"\nWrote JSON: {out_path}")

        return 0
    except subprocess.CalledProcessError as exc:
        print(f"ERROR: command failed ({exc.returncode}): {' '.join(exc.cmd)}", file=sys.stderr)
        return exc.returncode or 1
    except Exception as exc:  # pragma: no cover - CLI error path
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
