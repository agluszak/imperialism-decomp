"""Runtime result-bundle retention and diagnostic artifacts."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys


REPO_ROOT = Path(__file__).resolve().parents[2]
RETENTION_ENV = "IMPERIALISM_RUNTIME_BUNDLE_RETENTION"
# Each run bundle carries its own game/ sandbox (~165 MB), so ten per test name is tens
# of gigabytes across the suite. Three is enough to compare a failure with its neighbours.
BUNDLE_RETENTION = 3


def bundle_retention() -> int:
    raw = os.environ.get(RETENTION_ENV, "")
    try:
        return max(int(raw), 0)
    except ValueError:
        return BUNDLE_RETENTION


def capture_failure_screenshot(
    destination: Path, *, owner_pid: int | None = None, wineprefix: Path | None = None
) -> None:
    """Best-effort diagnostic artifact; screenshots never affect pass/fail."""
    try:
        command = [
            sys.executable,
            "tools/runtime/screenshot.py",
            str(destination),
        ]
        if owner_pid is not None:
            command.extend(["--pid", str(owner_pid)])
        if wineprefix is not None:
            command.extend(["--wineprefix", str(wineprefix.resolve())])
        subprocess.run(
            command,
            cwd=REPO_ROOT,
            capture_output=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        pass


def make_tree_writable(root: Path) -> None:
    """Add owner write to every directory and file under `root`.

    A run bundle stages the retail assets read-only (game/Data is dr-xr-xr-x with
    r--r--r-- files), and a directory without write permission cannot have its entries
    unlinked. Without this, retention silently did nothing.
    """
    for dirpath, _dirnames, filenames in os.walk(root, topdown=True):
        directory = Path(dirpath)
        try:
            directory.chmod(directory.stat().st_mode | 0o700)
        except OSError:
            continue
        for filename in filenames:
            target = directory / filename
            try:
                target.chmod(target.stat().st_mode | 0o200)
            except OSError:
                pass


def remove_run_dir(path: Path) -> bool:
    """Delete one run bundle, read-only sandbox and all. True when it is gone.

    shutil.rmtree(..., ignore_errors=True) is not enough here: it hides the
    PermissionError from the staged assets and leaves the whole bundle behind, which is
    how 250 of them (43 GB) accumulated before anyone noticed (imperialism-decomp-mx2a).
    """
    if not path.exists():
        return True
    shutil.rmtree(path, ignore_errors=True)
    if not path.exists():
        return True
    make_tree_writable(path)
    shutil.rmtree(path, ignore_errors=True)
    return not path.exists()


def stale_run_dirs(result_dir: Path, name: str, keep: int) -> list[Path]:
    """Run bundles of `name` beyond the `keep` newest, oldest first.

    The timestamp is in the directory name, so a lexicographic sort is chronological.
    """
    runs = sorted(path for path in result_dir.glob(f"{name}-2*") if path.is_dir())
    return runs[:-keep] if keep > 0 else runs


def prune_old_run_dirs(
    result_dir: Path, name: str, keep: int | None = None
) -> tuple[int, list[Path]]:
    """Apply retention for one test name. Returns (removed, still-present)."""
    removed = 0
    survivors: list[Path] = []
    for stale in stale_run_dirs(result_dir, name, bundle_retention() if keep is None else keep):
        if remove_run_dir(stale):
            removed += 1
        else:
            survivors.append(stale)
    return removed, survivors
