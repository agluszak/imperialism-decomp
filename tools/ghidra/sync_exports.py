#!/usr/bin/env python3
"""Single-entry export sync using pyghidra (in-process, no pyghidraRun subprocess)."""

from __future__ import annotations

import argparse
import csv
import io
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path

import pyghidra
from tools.common import ghidra_env
from tools.common.pipe_csv import read_pipe_table
from tools.common.repo import repo_root_from_file, resolve_repo_path
from tools.common.vtable_extents import containing_vtable_extent, load_verified_vtable_extents
from tools.ghidra.merge_curated_symbols import (
    index_symbols_by_address,
    merge_curated_symbols_csv,
    write_symbols_csv,
)
from tools.source_model import build_model
REPO_CONFIG_PATH = "ghidra.toml"
WS_RE = re.compile(r"\s")


def parse_args() -> argparse.Namespace:
    repo_root = repo_root_from_file(__file__)
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--ghidra-install-dir",
        default=os.getenv("GHIDRA_INSTALL_DIR"),
        help="Path to ghidra_12.1_PUBLIC installation directory",
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
        help="Output directory for symbols.ghidra.txt and original_entities.csv",
    )
    parser.add_argument(
        "--decomp-output-dir",
        default=os.getenv(
            "DECOMP_OUTPUT_DIR",
            str(repo_root / "build-msvc500" / "evidence" / "ghidra-export" / "src"),
        ),
        help="Output directory for split decompiled function bodies",
    )
    parser.add_argument(
        "--types-output-dir",
        default=os.getenv(
            "TYPES_OUTPUT_DIR",
            str(repo_root / "build-msvc500" / "evidence" / "ghidra-export" / "include"),
        ),
        help="Output directory for split datatype headers",
    )
    parser.add_argument(
        "--inventory-only",
        action="store_true",
        help=(
            "Export only symbols.ghidra.txt + original_entities.csv (the raw "
            "inventory); skip the expensive decompiled-body and type-header "
            "evidence snapshot."
        ),
    )
    parser.add_argument(
        "--decomp-max-functions-per-file",
        type=int,
        default=None,
        help="Maximum number of functions per generated decompiled .cpp file",
    )
    parser.add_argument(
        "--no-preserve-curated-symbols",
        action="store_true",
        help="Replace original_entities.csv wholesale instead of preserving curated rows.",
    )
    parser.add_argument(
        "--curated-git-ref",
        default=None,
        help="Recover curated original_entities.csv rows from this Git ref before merging.",
    )
    parser.add_argument(
        "--curated-addresses-only",
        action="store_true",
        help="During recovery, do not import addresses absent from the curated inventory.",
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


def read_pipe_text(text: str) -> tuple[list[str], list[dict[str, str]]]:
    reader = csv.DictReader(io.StringIO(text), delimiter="|")
    return list(reader.fieldnames or []), [dict(row) for row in reader]


def main() -> int:
    try:
        repo_root = repo_root_from_file(__file__)
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

        ghidra_install_dir = Path(require(args.ghidra_install_dir, "--ghidra-install-dir"))
        ghidra_project_dir = Path(require(args.ghidra_project_dir, "--ghidra-project-dir"))
        ghidra_project_name = require(args.ghidra_project_name, "--ghidra-project-name")
        ghidra_program_name = args.ghidra_program_name or default_program
        output_dir = resolve_repo_path(repo_root, args.output_dir)
        decomp_output_dir = resolve_repo_path(repo_root, args.decomp_output_dir)
        types_output_dir = resolve_repo_path(repo_root, args.types_output_dir)
        max_per_file = (
            args.decomp_max_functions_per_file
            if args.decomp_max_functions_per_file is not None
            else default_max_per_file
        )

        ghidra_env.enforce_versions(ghidra_install_dir)

        output_dir.mkdir(parents=True, exist_ok=True)
        decomp_output_dir.mkdir(parents=True, exist_ok=True)
        types_output_dir.mkdir(parents=True, exist_ok=True)

        symbols_txt = output_dir / "symbols.ghidra.txt"
        symbols_csv = output_dir / "original_entities.csv"
        curated_by_addr: dict[int, dict[str, str]] = {}
        curated_rows: list[dict[str, str]] = []
        if not args.no_preserve_curated_symbols:
            if args.curated_git_ref:
                result = subprocess.run(
                    [
                        "git",
                        "show",
                        f"{args.curated_git_ref}:config/original_entities.csv",
                    ],
                    cwd=repo_root,
                    check=True,
                    capture_output=True,
                    text=True,
                )
                _curated_fields, curated_rows = read_pipe_text(result.stdout)
            elif symbols_csv.is_file():
                _curated_fields, curated_rows = read_pipe_table(symbols_csv)
            else:
                curated_rows = []
            curated_by_addr = index_symbols_by_address(curated_rows)
        embedded_owner_addresses: set[int] = set()
        embedded_path = repo_root / "config" / "embedded_function_labels.csv"
        if embedded_path.is_file():
            _embedded_fields, embedded_rows = read_pipe_table(embedded_path)
            embedded_owner_addresses = {
                int((row.get("owner") or "").strip(), 16) for row in embedded_rows
            }
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
            "inventory-only" if args.inventory_only else "full",
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

        # A Ghidra label inside a verified vtable pointer run is not an entity
        # boundary. Keep the raw inventory clean even if an old project archive
        # still carries such a label; the collision gate independently rejects
        # the committed row so this filter cannot hide drift.
        extents = load_verified_vtable_extents(
            repo_root / "config" / "verified_vtable_extents.csv"
        )
        fieldnames, rows = read_pipe_table(symbols_csv)
        model = build_model(repo_root, "IMPERIALISM")
        source_names = {
            address: claim.name
            for address, claim in model.functions.items()
            if claim.name
        }
        source_names.update(model.globals)
        kept_by_address: dict[int, dict[str, str]] = {}
        passthrough_rows = []
        dropped_interior = 0
        dropped_vtable_starts = 0
        dropped_duplicates = 0
        for row in rows:
            try:
                address = int((row.get("address") or "").strip(), 16)
            except ValueError:
                passthrough_rows.append(row)
                continue
            if address in model.vtables:
                dropped_vtable_starts += 1
                continue
            if containing_vtable_extent(address, extents) is not None:
                dropped_interior += 1
                continue
            previous = kept_by_address.get(address)
            if previous is None:
                kept_by_address[address] = row
                continue
            dropped_duplicates += 1
            wanted_name = source_names.get(address)
            previous_rank = (
                int((previous.get("name") or "") == wanted_name),
                int((previous.get("type") or "") == "function"),
            )
            row_rank = (
                int((row.get("name") or "") == wanted_name),
                int((row.get("type") or "") == "function"),
            )
            if row_rank > previous_rank:
                kept_by_address[address] = row
        kept_rows = passthrough_rows + list(kept_by_address.values())
        merge_stats = None
        if curated_by_addr:
            if args.curated_addresses_only:
                kept_rows = [
                    row
                    for row in kept_rows
                    if int((row.get("address") or "0"), 16) in curated_by_addr
                ]
            kept_rows, merge_stats = merge_curated_symbols_csv(
                fieldnames,
                kept_rows,
                curated_by_addr,
                set(model.vtables),
            )
            for row in kept_rows:
                try:
                    address = int((row.get("address") or "").strip(), 16)
                except ValueError:
                    continue
                if address not in embedded_owner_addresses:
                    continue
                curated = curated_by_addr.get(address)
                if curated is not None and (curated.get("size") or "").strip():
                    row["size"] = curated["size"]
            filtered_rows = []
            for row in kept_rows:
                address_text = (row.get("address") or "").strip()
                try:
                    address = int(address_text, 16)
                except ValueError:
                    filtered_rows.append(row)
                    continue
                if address in model.vtables:
                    continue
                if containing_vtable_extent(address, extents) is not None:
                    continue
                filtered_rows.append(row)
            kept_rows = filtered_rows
            if args.curated_addresses_only:
                merged_by_addr = index_symbols_by_address(kept_rows)
                kept_rows = [
                    merged_by_addr[address]
                    for row in curated_rows
                    if (address := int((row.get("address") or "0"), 16)) in merged_by_addr
                ]
        write_symbols_csv(symbols_csv, fieldnames, kept_rows)

        # Wholesale refresh: the exported inventory replaces original_entities.csv
        # outright. Curated knowledge lives in source (markers/decls) and in the DB
        # (via ghidra-apply-source), never merged back here.


        print("Done.")
        print(
            f"  dropped source-vtable entities: {dropped_vtable_starts}; "
            f"interior vtable entities: {dropped_interior}; "
            f"duplicate-address rows: {dropped_duplicates}"
        )
        if merge_stats is not None:
            print(
                f"  curated merge: names={merge_stats.preserved_names} "
                f"symbols={merge_stats.preserved_symbols} "
                f"prototypes={merge_stats.preserved_prototypes} "
                f"function_types={merge_stats.preserved_function_types} "
                f"orphans={merge_stats.retained_orphans}"
            )
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
