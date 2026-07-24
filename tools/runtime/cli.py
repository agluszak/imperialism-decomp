"""CLI for discovering and running semantic runtime tests and suites."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET

from tools.runtime.catalog import TESTS, find_test, suite_names, tests_in_suite


REPO_ROOT = Path(__file__).resolve().parents[2]
RESULT_DIR = REPO_ROOT / "build-runtime-tests" / "runtime-results"


def add_run_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("name")
    parser.add_argument("--timeout", type=float, default=300)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--phase-timeout-ms", type=int, default=60000)
    parser.add_argument("--rerun-seh", action="store_true")


def run_one(args: argparse.Namespace) -> int:
    if find_test(args.name) is None:
        raise SystemExit(f"unknown runtime test {args.name!r}; run `just runtime-test-list`")
    if args.seed < 1:
        raise SystemExit("--seed must be a positive integer")
    from tools.runtime.runtime_tests import run_test

    return run_test(args)


def list_tests(_: argparse.Namespace) -> int:
    for test in TESTS:
        fixture = f" fixture={test.fixture}" if test.fixture else ""
        print(f"{test.name:38s} suites={','.join(test.suite)}{fixture}")
    return 0


def _suite_command(test_name: str, args: argparse.Namespace) -> list[str]:
    command = [
        sys.executable,
        "-m",
        "tools.runtime.cli",
        "run",
        test_name,
        "--seed",
        str(args.seed),
        "--timeout",
        str(args.timeout),
        "--phase-timeout-ms",
        str(args.phase_timeout_ms),
    ]
    if args.rerun_seh:
        command.append("--rerun-seh")
    return command


def run_suite(args: argparse.Namespace) -> int:
    tests = tests_in_suite(args.suite)
    if not tests:
        raise SystemExit(f"unknown or empty suite {args.suite!r}; choices: {', '.join(suite_names())}")

    def invoke(name: str) -> tuple[str, int]:
        completed = subprocess.run(_suite_command(name, args), cwd=REPO_ROOT, check=False)
        return name, completed.returncode

    with ThreadPoolExecutor(max_workers=args.jobs) as executor:
        results = list(executor.map(lambda test: invoke(test.name), tests))
    failed = [name for name, returncode in results if returncode != 0]
    if args.junit is not None:
        suite = ET.Element(
            "testsuite",
            name=f"imperialism-runtime-{args.suite}",
            tests=str(len(results)),
            failures=str(len(failed)),
        )
        for name, returncode in results:
            case = ET.SubElement(suite, "testcase", classname="runtime", name=name)
            if returncode != 0:
                failure = ET.SubElement(case, "failure", message="semantic runtime test failed")
                result_path = RESULT_DIR / f"{name}.json"
                failure.text = result_path.read_text(encoding="utf-8") if result_path.is_file() else ""
        args.junit.parent.mkdir(parents=True, exist_ok=True)
        ET.ElementTree(suite).write(args.junit, encoding="utf-8", xml_declaration=True)
    print(f"suite {args.suite}: {len(results) - len(failed)} passed, {len(failed)} failed")
    if failed:
        print("failed: " + ", ".join(failed))
    return 1 if failed else 0


def show_result(args: argparse.Namespace) -> int:
    path = RESULT_DIR / f"{args.name}.json"
    if not path.is_file():
        raise SystemExit(f"no runtime result for {args.name!r}")
    parsed = json.loads(path.read_text(encoding="utf-8"))
    print(json.dumps(parsed, indent=2, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="run one instrumented semantic test")
    add_run_arguments(run)
    run.set_defaults(func=run_one)
    listing = commands.add_parser("list", help="list registered runtime tests")
    listing.set_defaults(func=list_tests)
    suite = commands.add_parser("suite", help="run a catalog suite")
    suite.add_argument("suite", choices=suite_names())
    suite.add_argument("--jobs", type=int, default=1)
    suite.add_argument("--timeout", type=float, default=300)
    suite.add_argument("--seed", type=int, default=1)
    suite.add_argument("--phase-timeout-ms", type=int, default=60000)
    suite.add_argument("--rerun-seh", action="store_true")
    suite.add_argument("--junit", type=Path)
    suite.set_defaults(func=run_suite)
    show = commands.add_parser("show", help="show the latest canonical result")
    show.add_argument("name")
    show.set_defaults(func=show_result)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0] not in {"run", "list", "suite", "show"}:
        arguments.insert(0, "run")
    args = build_parser().parse_args(arguments)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
