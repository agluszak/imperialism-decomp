"""Command-line entry point for exploratory random-control runtime testing."""

from __future__ import annotations

import argparse
from pathlib import Path

from tools.runtime.explore import run_explorer
from tools.runtime.runtime_tests import BUILD_DIR, fixture_directory


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument(
        "--runs",
        type=int,
        default=1,
        help="campaigns to run; 0 keeps trying seeds until a crash or hang is found",
    )
    parser.add_argument("--steps", type=int, default=500)
    parser.add_argument("--timeout", type=float, default=900.0)
    parser.add_argument("--phase-timeout-ms", type=int, default=5000)
    parser.add_argument("--settle-ticks", type=int, default=2)
    parser.add_argument("--no-minimize", action="store_true")
    parser.add_argument(
        "--replay",
        type=Path,
        help="run a reproducer JSON previously emitted by this tool",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.seed < 1:
        raise SystemExit("--seed must be a positive integer")
    if args.runs < 0:
        raise SystemExit("--runs must be non-negative")
    if args.steps < 1 and args.replay is None:
        raise SystemExit("--steps must be positive")
    if args.timeout <= 0:
        raise SystemExit("--timeout must be positive")
    if args.phase_timeout_ms < 1:
        raise SystemExit("--phase-timeout-ms must be positive")
    if args.settle_ticks < 0 or args.settle_ticks > 100:
        raise SystemExit("--settle-ticks must be between 0 and 100")
    return run_explorer(
        args,
        result_dir=BUILD_DIR / "runtime-results",
        fixture_dir=fixture_directory(),
    )


if __name__ == "__main__":
    raise SystemExit(main())
