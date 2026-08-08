#!/usr/bin/env python3
"""Populate the local gitignored DirectX 5 SDK header/lib mirror."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import tempfile
import urllib.request
from pathlib import Path

from tools.common.repo import repo_root_from_file, resolve_repo_path

# Same installer the Docker image uses (see docker/msvc500/Dockerfile).
DEFAULT_INSTALLER_URL = "https://archive.org/download/idx5sdk/idx5sdk.exe"
SDK_DIRS = {"inc": "include", "lib": "lib"}


def parse_args() -> argparse.Namespace:
    repo_root = repo_root_from_file(__file__)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source",
        help=(
            "Existing DX5 SDK tree holding inc/ and lib/ (or a local idx5sdk.exe). "
            "Defaults to downloading the archive.org installer."
        ),
    )
    parser.add_argument(
        "--installer-url",
        default=DEFAULT_INSTALLER_URL,
        help=f"DX5 SDK installer to download when --source is omitted (default: {DEFAULT_INSTALLER_URL}).",
    )
    parser.add_argument(
        "--dest",
        default=str(repo_root / "vendor" / "directx"),
        help="Destination mirror directory.",
    )
    return parser.parse_args()


def run(cmd: list[str], cwd: Path | None = None) -> None:
    subprocess.run(cmd, cwd=cwd, check=True)


def extract_installer(installer: Path, workdir: Path) -> Path:
    """Unpack the WEXTRACT SFX + nested MSZip cab; return the sdk/ tree."""
    if shutil.which("7z") is None:
        raise SystemExit("7z is required to extract the DX5 SDK installer (install p7zip-full)")
    sfx_dir = workdir / "sfx"
    cab_dir = workdir / "cab"
    run(["7z", "x", f"-o{sfx_dir}", "-y", str(installer), "DX5SDK.EXE"])
    run(["7z", "x", f"-o{cab_dir}", "-y", str(sfx_dir / "DX5SDK.EXE")])
    return cab_dir / "cdrom" / "sdk"


def validate_source(source: Path) -> None:
    missing = [rel for rel in SDK_DIRS if not (source / rel).is_dir()]
    if missing:
        missing_text = ", ".join(missing)
        raise SystemExit(f"DX5 SDK tree is missing required dirs: {missing_text}")


def refresh_mirror(source: Path, dest: Path) -> None:
    validate_source(source)
    for rel, out in SDK_DIRS.items():
        dst = dest / out
        if dst.exists():
            shutil.rmtree(dst)
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(source / rel, dst)
        count = sum(1 for path in dst.rglob("*") if path.is_file())
        print(f"copied {rel} -> {out} ({count} files)")


def main() -> int:
    args = parse_args()
    repo_root = repo_root_from_file(__file__)
    dest = resolve_repo_path(repo_root, args.dest)

    if args.source:
        source = Path(args.source).expanduser().resolve()
        if source.is_file():
            with tempfile.TemporaryDirectory(prefix="dx5sdk-") as tmp:
                refresh_mirror(extract_installer(source, Path(tmp)), dest)
        else:
            refresh_mirror(source, dest)
        print(f"DirectX 5 SDK mirror refreshed at {dest}")
        return 0

    with tempfile.TemporaryDirectory(prefix="dx5sdk-") as tmp:
        installer = Path(tmp) / "idx5sdk.exe"
        print(f"downloading {args.installer_url}")
        urllib.request.urlretrieve(args.installer_url, installer)
        refresh_mirror(extract_installer(installer, Path(tmp)), dest)
    print(f"DirectX 5 SDK mirror refreshed at {dest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
