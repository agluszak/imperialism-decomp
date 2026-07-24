"""Runtime result-bundle retention and diagnostic artifacts."""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess


REPO_ROOT = Path(__file__).resolve().parents[2]
BUNDLE_RETENTION = 10


def capture_failure_screenshot(destination: Path) -> None:
    """Best-effort diagnostic artifact; screenshots never affect pass/fail."""
    try:
        subprocess.run(
            [
                "uv",
                "run",
                "--with",
                "python-xlib",
                "--with",
                "pillow",
                "python",
                "tools/runtime/screenshot.py",
                str(destination),
            ],
            cwd=REPO_ROOT,
            capture_output=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        pass


def prune_old_run_dirs(result_dir: Path, name: str, keep: int = BUNDLE_RETENTION) -> None:
    runs = sorted(path for path in result_dir.glob(f"{name}-2*") if path.is_dir())
    for stale in runs[:-keep] if keep > 0 else runs:
        shutil.rmtree(stale, ignore_errors=True)
