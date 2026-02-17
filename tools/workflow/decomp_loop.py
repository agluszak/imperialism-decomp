#!/usr/bin/env python3
"""One-command decomp loop helper.

Optional stages:
1) sync exports from Ghidra
2) regenerate autogen stubs
3) detect recompiled output for reccmp
4) run reccmp compare
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--export-ghidra", action="store_true")
    parser.add_argument("--ghidra-install-dir")
    parser.add_argument("--ghidra-project-dir")
    parser.add_argument("--ghidra-project-name")
    parser.add_argument("--ghidra-program-name")
    parser.add_argument("--output-dir", default="config")
    parser.add_argument("--decomp-output-dir", default="src/ghidra_autogen")
    parser.add_argument("--decomp-max-functions-per-file", type=int, default=250)
    parser.add_argument("--types-output-dir", default="include/ghidra_autogen")
    parser.add_argument("--name-overrides", default="config/name_overrides.csv")

    parser.add_argument("--use-prototypes", action="store_true")
    parser.add_argument("--stubgen-target", default="IMPERIALISM")

    parser.add_argument("--build-dir", default="build-msvc500")
    parser.add_argument("--detect-recompiled", action="store_true")
    parser.add_argument("--compare-target")
    return parser.parse_args()


def run(cmd: list[str], cwd: Path) -> None:
    print("+", " ".join(cmd))
    subprocess.run(cmd, cwd=cwd, check=True)


def require(value: str | None, flag_name: str) -> str:
    if value:
        return value
    raise ValueError(f"Missing required argument {flag_name}")


def main() -> int:
    try:
        args = parse_args()
        repo_root = Path(__file__).resolve().parents[2]

        if args.export_ghidra:
            ghidra_cmd = [
                "uv",
                "run",
                "python",
                "tools/ghidra/sync_exports.py",
                "--ghidra-install-dir",
                require(args.ghidra_install_dir, "--ghidra-install-dir"),
                "--ghidra-project-dir",
                require(args.ghidra_project_dir, "--ghidra-project-dir"),
                "--ghidra-project-name",
                require(args.ghidra_project_name, "--ghidra-project-name"),
                "--output-dir",
                args.output_dir,
                "--decomp-output-dir",
                args.decomp_output_dir,
                "--types-output-dir",
                args.types_output_dir,
                "--decomp-max-functions-per-file",
                str(args.decomp_max_functions_per_file),
                "--name-overrides",
                args.name_overrides,
            ]
            if args.ghidra_program_name:
                ghidra_cmd.extend(["--ghidra-program-name", args.ghidra_program_name])
            run(ghidra_cmd, cwd=repo_root)

        stubgen_cmd = [
            "uv",
            "run",
            "python",
            "tools/stubgen.py",
            "--target",
            args.stubgen_target,
            "--name-overrides",
            args.name_overrides,
        ]
        if args.use_prototypes:
            stubgen_cmd.append("--use-prototypes")
        run(stubgen_cmd, cwd=repo_root)

        build_dir = (repo_root / args.build_dir).resolve()
        if args.detect_recompiled:
            run(
                [
                    "uv",
                    "run",
                    "reccmp-project",
                    "detect",
                    "--what",
                    "recompiled",
                ],
                cwd=build_dir,
            )

        if args.compare_target:
            run(
                [
                    "uv",
                    "run",
                    "reccmp-reccmp",
                    "--target",
                    args.compare_target,
                ],
                cwd=build_dir,
            )
        return 0
    except Exception as exc:  # pragma: no cover - CLI error path
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
