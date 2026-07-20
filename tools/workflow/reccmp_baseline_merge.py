"""Git integration for generated reccmp progress baselines.

The merge driver deliberately keeps Git's current-side file intact and records a
pending refresh. Once the merge/rebase/cherry-pick has completed, tracked hooks
rebuild the merged tree and regenerate both baseline files together. The generated
changes remain unstaged so a human can review them before committing.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path
from typing import Callable, Sequence

BASELINE_PATHS = frozenset(
    {
        "config/baselines/reccmp_progress_baseline.json",
        "config/baselines/reccmp_progress_baseline.report.json",
    }
)
PENDING_NAME = "reccmp-baseline-refresh.pending"
SKIP_ENV = "IMPERIALISM_SKIP_RECCMP_BASELINE_REFRESH"
DRIVER_NAME = "reccmp-baseline"
DRIVER_COMMAND = (
    'python3 -m tools.workflow.reccmp_baseline_merge merge-driver '
    "%O %A %B %P"
)

Runner = Callable[[Sequence[str], Path], None]


def _run_checked(command: Sequence[str], cwd: Path) -> None:
    subprocess.run(command, cwd=cwd, check=True)


def _git_output(repo_root: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", *args], cwd=repo_root, text=True
    ).strip()


def find_repo_root() -> Path:
    return Path(
        subprocess.check_output(
            ["git", "rev-parse", "--show-toplevel"], text=True
        ).strip()
    )


def pending_path(repo_root: Path) -> Path:
    value = _git_output(repo_root, "rev-parse", "--git-path", PENDING_NAME)
    path = Path(value)
    return path if path.is_absolute() else repo_root / path


def mark_pending(marker: Path, logical_path: str) -> None:
    paths: set[str] = set()
    if marker.exists():
        paths.update(line for line in marker.read_text(encoding="utf-8").splitlines())
    paths.add(logical_path)
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text("".join(f"{path}\n" for path in sorted(paths)), encoding="utf-8")


def run_merge_driver(repo_root: Path, logical_path: str) -> int:
    """Keep %A unchanged and request a post-operation regeneration."""
    if logical_path not in BASELINE_PATHS:
        print(
            f"reccmp baseline merge driver refused unexpected path: {logical_path}",
            file=sys.stderr,
        )
        return 1
    mark_pending(pending_path(repo_root), logical_path)
    print(
        f"reccmp baseline conflict deferred for regeneration: {logical_path}",
        file=sys.stderr,
    )
    return 0


def refresh_pending(
    repo_root: Path,
    marker: Path,
    *,
    event: str,
    squash: bool = False,
    strict: bool = False,
    runner: Runner = _run_checked,
) -> int:
    """Regenerate both baselines after the surrounding Git operation completes."""
    if not marker.exists():
        return 0
    if os.environ.get(SKIP_ENV):
        print(
            f"reccmp baseline refresh remains pending ({SKIP_ENV} is set)",
            file=sys.stderr,
        )
        return 0
    if event == "post-merge" and squash:
        print(
            "reccmp baseline refresh deferred until the squash commit",
            file=sys.stderr,
        )
        return 0
    unresolved = _git_output(
        repo_root, "diff", "--name-only", "--diff-filter=U"
    )
    if unresolved:
        print(
            "reccmp baseline refresh deferred until all merge conflicts are resolved",
            file=sys.stderr,
        )
        return 0

    print("Regenerating reccmp baselines after Git integration...", file=sys.stderr)
    try:
        runner(["just", "build"], repo_root)
        runner(["just", "stats-baseline-update"], repo_root)
    except (OSError, subprocess.CalledProcessError) as exc:
        print(
            "WARNING: automatic reccmp baseline regeneration failed; "
            f"the pending marker was kept for retry: {exc}",
            file=sys.stderr,
        )
        return 1 if strict else 0

    marker.unlink(missing_ok=True)
    print(
        "Reccmp baselines regenerated as unstaged changes; review them before commit.",
        file=sys.stderr,
    )
    return 0


def install(repo_root: Path) -> int:
    """Install the local driver config while preserving the tracked Beads hooks."""
    hooks_path = subprocess.run(
        ["git", "config", "--local", "--get", "core.hooksPath"],
        cwd=repo_root,
        text=True,
        capture_output=True,
        check=False,
    ).stdout.strip()
    hooks_parts = Path(hooks_path).parts
    uses_beads_hooks = hooks_parts[-2:] == (".beads", "hooks")
    if hooks_path and not uses_beads_hooks:
        print(
            "Refusing to replace custom core.hooksPath "
            f"{hooks_path!r}; install the reccmp hook calls there manually.",
            file=sys.stderr,
        )
        return 1

    commands = (
        ["git", "config", "--local", "core.hooksPath", ".beads/hooks"],
        [
            "git",
            "config",
            "--local",
            f"merge.{DRIVER_NAME}.name",
            "Regenerate generated reccmp baselines after integration",
        ],
        [
            "git",
            "config",
            "--local",
            f"merge.{DRIVER_NAME}.driver",
            DRIVER_COMMAND,
        ],
    )
    for command in commands:
        subprocess.run(command, cwd=repo_root, check=True)
    print("Installed reccmp baseline merge driver and tracked Git hooks.")
    return 0


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    driver = subparsers.add_parser("merge-driver")
    driver.add_argument("ancestor")
    driver.add_argument("current")
    driver.add_argument("other")
    driver.add_argument("path")

    refresh = subparsers.add_parser("refresh")
    refresh.add_argument("--event", required=True)
    refresh.add_argument("--squash", action="store_true")
    refresh.add_argument("--strict", action="store_true")

    subparsers.add_parser("install")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    repo_root = find_repo_root()
    if args.command == "merge-driver":
        return run_merge_driver(repo_root, args.path)
    if args.command == "refresh":
        return refresh_pending(
            repo_root,
            pending_path(repo_root),
            event=args.event,
            squash=args.squash,
            strict=args.strict,
        )
    if args.command == "install":
        return install(repo_root)
    raise AssertionError(args.command)


if __name__ == "__main__":
    raise SystemExit(main())
