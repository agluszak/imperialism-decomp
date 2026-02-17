#!/usr/bin/env python3
"""Single-entry export sync using pyghidra (in-process, no pyghidraRun subprocess)."""

from __future__ import annotations

import argparse
import csv
import os
import re
import sys
import tomllib
from pathlib import Path

import pyghidra

REPO_CONFIG_PATH = "ghidra.toml"
EXPECTED_PYGHIDRA_VERSION = "3.0.2"
WS_RE = re.compile(r"\s")


def parse_args() -> argparse.Namespace:
    repo_root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--ghidra-install-dir",
        default=os.getenv("GHIDRA_INSTALL_DIR"),
        help="Path to ghidra_12.0.2_PUBLIC installation directory",
    )
    parser.add_argument(
        "--ghidra-project-dir",
        default=os.getenv("GHIDRA_PROJECT_DIR"),
        help="Directory containing the Ghidra project",
    )
    parser.add_argument(
        "--ghidra-project-name",
        default=os.getenv("GHIDRA_PROJECT_NAME"),
        help="Ghidra project name (without .gpr suffix)",
    )
    parser.add_argument(
        "--ghidra-program-name",
        default=os.getenv("GHIDRA_PROGRAM_NAME"),
        help="Program name inside project (defaults from ghidra.toml)",
    )
    parser.add_argument(
        "--output-dir",
        default=os.getenv("OUTPUT_DIR", str(repo_root / "config")),
        help="Output directory for symbols.ghidra.txt and symbols.csv",
    )
    parser.add_argument(
        "--decomp-output-dir",
        default=os.getenv("DECOMP_OUTPUT_DIR", str(repo_root / "src" / "ghidra_autogen")),
        help="Output directory for split decompiled function bodies",
    )
    parser.add_argument(
        "--types-output-dir",
        default=os.getenv("TYPES_OUTPUT_DIR", str(repo_root / "include" / "ghidra_autogen")),
        help="Output directory for split datatype headers",
    )
    parser.add_argument(
        "--decomp-max-functions-per-file",
        type=int,
        default=None,
        help="Maximum number of functions per generated decompiled .cpp file",
    )
    parser.add_argument(
        "--name-overrides",
        default=os.getenv("NAME_OVERRIDES", str(repo_root / "config" / "name_overrides.csv")),
        help="Optional pipe-delimited file: address|name|prototype",
    )
    return parser.parse_args()


def require(value: str | None, name: str) -> str:
    if value:
        return value
    raise ValueError(
        f"Missing required argument: {name}. You can also set env var {name.upper().replace('-', '_')}."
    )


def read_repo_config(repo_root: Path) -> dict:
    config_path = repo_root / REPO_CONFIG_PATH
    if not config_path.is_file():
        raise FileNotFoundError(f"Missing {config_path}")
    with config_path.open("rb") as fd:
        return tomllib.load(fd)


def read_ghidra_props(ghidra_install_dir: Path) -> tuple[str, str]:
    props_path = ghidra_install_dir / "Ghidra" / "application.properties"
    if not props_path.is_file():
        raise FileNotFoundError(f"Missing Ghidra application.properties: {props_path}")

    version = None
    release = None
    for raw in props_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        if line.startswith("application.version="):
            version = line.split("=", 1)[1].strip()
        elif line.startswith("application.release.name="):
            release = line.split("=", 1)[1].strip()

    if not version or not release:
        raise RuntimeError(f"Could not read version/release from {props_path}")
    return version, release


def clean_field(text: str) -> str:
    return " ".join(text.replace("|", " ").split())


def parse_override_rows(path: Path) -> dict[int, tuple[str, str]]:
    if not path.is_file():
        return {}
    rows: dict[int, tuple[str, str]] = {}
    with path.open("r", encoding="utf-8", newline="") as fd:
        reader = csv.DictReader(fd, delimiter="|")
        for row in reader:
            addr_text = (row.get("address") or "").strip()
            if not addr_text:
                continue
            addr = int(addr_text, 16)
            name = clean_field((row.get("name") or "").strip())
            proto = clean_field((row.get("prototype") or "").strip())
            rows[addr] = (name, proto)
    return rows


def apply_overrides_to_symbols_csv(path: Path, overrides: dict[int, tuple[str, str]]) -> tuple[int, int]:
    if not path.is_file() or not overrides:
        return (0, 0)

    with path.open("r", encoding="utf-8", newline="") as fd:
        reader = csv.DictReader(fd, delimiter="|")
        fieldnames = list(reader.fieldnames or [])
        rows = list(reader)

    renamed_count = 0
    proto_count = 0
    for row in rows:
        row_type = (row.get("type") or "").strip().lower()
        if row_type != "function":
            continue
        addr_text = (row.get("address") or "").strip()
        if not addr_text:
            continue
        addr = int(addr_text, 16)
        override = overrides.get(addr)
        if override is None:
            continue
        if override[0] and row.get("name", "") != override[0]:
            row["name"] = override[0]
            renamed_count += 1
        if "prototype" in row and override[1] and row.get("prototype", "") != override[1]:
            row["prototype"] = override[1]
            proto_count += 1

    with path.open("w", encoding="utf-8", newline="") as fd:
        writer = csv.DictWriter(fd, fieldnames=fieldnames, delimiter="|", lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    return (renamed_count, proto_count)


def apply_overrides_to_symbols_txt(path: Path, overrides: dict[int, tuple[str, str]]) -> tuple[int, int]:
    if not path.is_file() or not overrides:
        return (0, 0)

    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    output: list[str] = []
    renamed_count = 0
    skipped_whitespace = 0

    for line in lines:
        stripped = line.strip()
        if not stripped:
            output.append(line)
            continue
        parts = stripped.split()
        if len(parts) < 3:
            output.append(line)
            continue
        name, addr_text, kind = parts[0], parts[1], parts[2]
        if kind.lower() != "f":
            output.append(line)
            continue
        try:
            addr = int(addr_text, 16)
        except ValueError:
            output.append(line)
            continue
        override = overrides.get(addr)
        if override is None or not override[0]:
            output.append(line)
            continue
        new_name = override[0]
        if WS_RE.search(new_name):
            skipped_whitespace += 1
            output.append(line)
            continue
        output.append(f"{new_name} {addr_text} {kind}")
        if new_name != name:
            renamed_count += 1

    path.write_text("\n".join(output) + "\n", encoding="utf-8")
    return (renamed_count, skipped_whitespace)


def apply_overrides_to_index_csv(path: Path, overrides: dict[int, tuple[str, str]]) -> tuple[int, int]:
    if not path.is_file() or not overrides:
        return (0, 0)

    with path.open("r", encoding="utf-8", newline="") as fd:
        reader = csv.DictReader(fd, delimiter="|")
        fieldnames = list(reader.fieldnames or [])
        rows = list(reader)

    renamed_count = 0
    proto_count = 0
    for row in rows:
        addr_text = (row.get("address") or "").strip()
        if not addr_text:
            continue
        addr = int(addr_text, 16)
        override = overrides.get(addr)
        if override is None:
            continue
        if override[0] and row.get("name", "") != override[0]:
            row["name"] = override[0]
            renamed_count += 1
        if "prototype" in row and override[1] and row.get("prototype", "") != override[1]:
            row["prototype"] = override[1]
            proto_count += 1

    with path.open("w", encoding="utf-8", newline="") as fd:
        writer = csv.DictWriter(fd, fieldnames=fieldnames, delimiter="|", lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    return (renamed_count, proto_count)


def main() -> int:
    try:
        repo_root = Path(__file__).resolve().parents[2]
        args = parse_args()
        cfg = read_repo_config(repo_root)

        gh_cfg = cfg.get("ghidra", {})
        exp_cfg = cfg.get("exports", {})
        expected_version = str(gh_cfg.get("version", "")).strip()
        expected_release = str(gh_cfg.get("release", "")).strip()
        default_program = str(gh_cfg.get("program_name", "Imperialism.exe")).strip()
        default_max_per_file = int(exp_cfg.get("decomp_max_functions_per_file", 250))

        if not expected_version or not expected_release:
            raise RuntimeError(
                f"{REPO_CONFIG_PATH} must define [ghidra].version and [ghidra].release"
            )

        pyghidra_version = getattr(pyghidra, "__version__", "unknown")
        if pyghidra_version != EXPECTED_PYGHIDRA_VERSION:
            raise RuntimeError(
                f"Unsupported pyghidra runtime: {pyghidra_version}. "
                f"Expected {EXPECTED_PYGHIDRA_VERSION}."
            )

        ghidra_install_dir = Path(require(args.ghidra_install_dir, "--ghidra-install-dir"))
        ghidra_project_dir = Path(require(args.ghidra_project_dir, "--ghidra-project-dir"))
        ghidra_project_name = require(args.ghidra_project_name, "--ghidra-project-name")
        ghidra_program_name = args.ghidra_program_name or default_program
        output_dir = Path(args.output_dir).resolve()
        decomp_output_dir = Path(args.decomp_output_dir).resolve()
        types_output_dir = Path(args.types_output_dir).resolve()
        name_overrides_path = Path(args.name_overrides).resolve()
        max_per_file = (
            args.decomp_max_functions_per_file
            if args.decomp_max_functions_per_file is not None
            else default_max_per_file
        )

        actual_version, actual_release = read_ghidra_props(ghidra_install_dir)
        if actual_version != expected_version or actual_release != expected_release:
            raise RuntimeError(
                f"Unsupported Ghidra runtime: {actual_version} {actual_release}. "
                f"Expected {expected_version} {expected_release}."
            )

        output_dir.mkdir(parents=True, exist_ok=True)
        decomp_output_dir.mkdir(parents=True, exist_ok=True)
        types_output_dir.mkdir(parents=True, exist_ok=True)

        symbols_txt = output_dir / "symbols.ghidra.txt"
        symbols_csv = output_dir / "symbols.csv"
        script_path = Path(__file__).resolve().parent / "SyncExports_Ghidra.py"
        if not script_path.is_file():
            raise FileNotFoundError(f"Missing script: {script_path}")

        script_args = [
            str(symbols_txt),
            str(symbols_csv),
            str(decomp_output_dir),
            str(types_output_dir),
            str(max_per_file),
            expected_version,
            expected_release,
        ]

        pyghidra.start(install_dir=ghidra_install_dir)
        project = pyghidra.open_project(ghidra_project_dir, ghidra_project_name, create=False)
        from java.lang import Object as JavaObject

        consumer = JavaObject()
        program = None
        try:
            program_path = (
                ghidra_program_name
                if ghidra_program_name.startswith("/")
                else f"/{ghidra_program_name}"
            )
            domain_file = project.getProjectData().getFile(program_path)
            if domain_file is None:
                raise FileNotFoundError(
                    f'Program "{ghidra_program_name}" not found in project "{ghidra_project_name}".'
                )
            program = domain_file.getReadOnlyDomainObject(
                consumer,
                -1,
                pyghidra.task_monitor(),
            )
            pyghidra.ghidra_script(
                script_path,
                project=project,
                program=program,
                script_args=script_args,
                echo_stdout=True,
                echo_stderr=True,
            )
        finally:
            if program is not None:
                program.release(consumer)
            project.close()

        overrides = parse_override_rows(name_overrides_path)
        if overrides:
            renamed_csv, proto_csv = apply_overrides_to_symbols_csv(symbols_csv, overrides)
            renamed_txt, skipped_txt = apply_overrides_to_symbols_txt(symbols_txt, overrides)
            renamed_idx, proto_idx = apply_overrides_to_index_csv(
                decomp_output_dir / "index.csv", overrides
            )
            print(
                "Applied name overrides from {}: csv names {}, csv prototypes {}, "
                "symbols.txt names {}, index names {}, index prototypes {}{}".format(
                    name_overrides_path,
                    renamed_csv,
                    proto_csv,
                    renamed_txt,
                    renamed_idx,
                    proto_idx,
                    (
                        ", symbols.txt skipped (whitespace names) {}".format(skipped_txt)
                        if skipped_txt
                        else ""
                    ),
                )
            )
        else:
            print(f"No name overrides applied (missing/empty): {name_overrides_path}")

        print("Done.")
        print(f"  {symbols_txt}")
        print(f"  {symbols_csv}")
        print(f"  {decomp_output_dir}")
        print(f"  {types_output_dir}")
        return 0
    except Exception as exc:  # pragma: no cover - CLI error path
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
