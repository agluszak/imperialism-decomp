#!/usr/bin/env python3
"""Validate the active tooling surface against justfile and required dependencies.

Also lints tools/ for raw pipe-splitting of config tables: splitting a row on
the pipe character and indexing parts[N] hardcodes column positions and silently
breaks when the schema gains a column (the prune_ilt_thunks/
gen_library_annotations parts[3] bug class). Use tools.common.pipe_csv (read_pipe_rows/read_pipe_table/
header_column_indices) instead; genuinely non-tabular splits are whitelisted
with a `# pipe-split-ok[: reason]` comment on the same line.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

from tools.common.pipe_csv import read_pipe_rows
from tools.common.repo import repo_root_from_file, resolve_repo_path

JUST_MODULE_RE = re.compile(r"python\s+-m\s+([A-Za-z0-9_.]+)")
PIPE_SPLIT_RE = re.compile(r"""\.split\(\s*(['"])\|\1\s*\)""")
PIPE_SPLIT_PRAGMA = "pipe-split-ok"


def parse_args() -> argparse.Namespace:
    repo_root = repo_root_from_file(__file__)
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", default=str(repo_root / "config" / "tooling_surface.csv"))
    parser.add_argument("--justfile", default=str(repo_root / "justfile"))
    return parser.parse_args()


def module_exists(repo_root: Path, module_name: str) -> bool:
    module_rel = Path(*module_name.split("."))
    file_path = repo_root / f"{module_rel.as_posix()}.py"
    if file_path.is_file():
        return True
    package_path = repo_root / module_rel
    init_py = package_path / "__init__.py"
    return package_path.is_dir() and init_py.is_file()


def parse_just_modules(justfile_path: Path) -> set[str]:
    text = justfile_path.read_text(encoding="utf-8", errors="ignore")
    # Only repo tool modules belong in the manifest (not stdlib ones like unittest).
    return {m.group(1) for m in JUST_MODULE_RE.finditer(text) if m.group(1).startswith("tools.")}


def find_raw_pipe_splits(repo_root: Path) -> list[str]:
    """Flag `.split("|")` in tools/ without a `# pipe-split-ok` pragma (see module doc)."""
    offenders: list[str] = []
    for py in sorted((repo_root / "tools").rglob("*.py")):
        try:
            text = py.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            if PIPE_SPLIT_RE.search(line) and PIPE_SPLIT_PRAGMA not in line:
                rel = py.relative_to(repo_root).as_posix()
                offenders.append(
                    f"{rel}:{lineno}: raw pipe-split of a config table; use "
                    f"tools.common.pipe_csv or annotate `# {PIPE_SPLIT_PRAGMA}: <reason>`"
                )
    return offenders


def main() -> int:
    args = parse_args()
    repo_root = repo_root_from_file(__file__)
    manifest_path = resolve_repo_path(repo_root, args.manifest)
    justfile_path = resolve_repo_path(repo_root, args.justfile)

    if not manifest_path.is_file():
        raise SystemExit(f"Missing manifest: {manifest_path}")
    if not justfile_path.is_file():
        raise SystemExit(f"Missing justfile: {justfile_path}")

    rows = read_pipe_rows(manifest_path)
    manifest_modules: set[str] = set()
    manifest_just_modules: set[str] = set()
    errors: list[str] = []

    for row in rows:
        kind = (row.get("kind") or "").strip().lower()
        entry = (row.get("entry") or "").strip()
        source = (row.get("source") or "").strip().lower()
        if not kind or not entry:
            errors.append(f"Malformed row (missing kind/entry): {row}")
            continue

        if kind == "module":
            manifest_modules.add(entry)
            if source.startswith("just:"):
                manifest_just_modules.add(entry)
            if not module_exists(repo_root, entry):
                errors.append(f"Missing module file for entry: {entry}")
            continue

        if kind == "file":
            file_path = repo_root / entry
            if not file_path.is_file():
                errors.append(f"Missing required file entry: {entry}")
            continue

        errors.append(f"Unsupported kind '{kind}' for entry '{entry}'")

    errors.extend(find_raw_pipe_splits(repo_root))

    just_modules = parse_just_modules(justfile_path)
    missing_from_manifest = sorted(just_modules - manifest_modules)
    stale_manifest_just = sorted(manifest_just_modules - just_modules)

    for module in missing_from_manifest:
        errors.append(f"justfile module not tracked in manifest: {module}")
    for module in stale_manifest_just:
        errors.append(f"manifest module marked just:* but not present in justfile: {module}")

    print(f"Manifest entries: {len(rows)}")
    print(f"justfile python modules: {len(just_modules)}")
    print(f"Tracked modules in manifest: {len(manifest_modules)}")

    if errors:
        print("Tooling surface check failed:")
        for err in errors:
            print(f"  - {err}")
        return 1

    print("Tooling surface check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
