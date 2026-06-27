#!/usr/bin/env python3
"""Populate the local gitignored MSVC 5.0 header mirror."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import tempfile
from pathlib import Path

from tools.common.repo import repo_root_from_file, resolve_repo_path

DEFAULT_REPO_URL = "https://github.com/archaic-msvc/msvc500.git"
HEADER_DIRS = ("include", "mfc/include", "atl/include")


def parse_args() -> argparse.Namespace:
    repo_root = repo_root_from_file(__file__)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source",
        help="Existing MSVC tree to copy from. Defaults to cloning the portable MSVC500 repo.",
    )
    parser.add_argument(
        "--repo-url",
        default=DEFAULT_REPO_URL,
        help=f"MSVC500 git repository to clone when --source is omitted (default: {DEFAULT_REPO_URL}).",
    )
    parser.add_argument(
        "--ref",
        help="Optional git ref to check out after cloning.",
    )
    parser.add_argument(
        "--dest",
        default=str(repo_root / "vendor" / "msvc500" / "headers"),
        help="Destination header mirror directory.",
    )
    return parser.parse_args()


def run(cmd: list[str], cwd: Path | None = None) -> None:
    subprocess.run(cmd, cwd=cwd, check=True)


def clone_source(repo_url: str, ref: str | None, parent: Path) -> Path:
    source = parent / "msvc500"
    run(["git", "clone", "--depth", "1", repo_url, str(source)])
    if ref:
        run(["git", "fetch", "--depth", "1", "origin", ref], cwd=source)
        run(["git", "checkout", "FETCH_HEAD"], cwd=source)
    return source


def validate_source(source: Path) -> None:
    missing = [rel for rel in HEADER_DIRS if not (source / rel).is_dir()]
    if missing:
        missing_text = ", ".join(missing)
        raise SystemExit(f"MSVC source tree is missing required header dirs: {missing_text}")


def refresh_headers(source: Path, dest: Path) -> None:
    validate_source(source)
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)

    for rel in HEADER_DIRS:
        src = source / rel
        dst = dest / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(src, dst)
        count = sum(1 for path in dst.rglob("*") if path.is_file())
        print(f"copied {rel} ({count} files)")


def main() -> int:
    args = parse_args()
    repo_root = repo_root_from_file(__file__)
    dest = resolve_repo_path(repo_root, args.dest)

    if args.source:
        source = Path(args.source).expanduser().resolve()
        refresh_headers(source, dest)
        print(f"MSVC500 header mirror refreshed at {dest}")
        return 0

    with tempfile.TemporaryDirectory(prefix="msvc500-headers-") as tmp:
        source = clone_source(args.repo_url, args.ref, Path(tmp))
        refresh_headers(source, dest)
    print(f"MSVC500 header mirror refreshed at {dest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
