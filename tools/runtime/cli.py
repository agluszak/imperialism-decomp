"""CLI for discovering and running semantic runtime tests and suites."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import json
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET

from tools.runtime.artifacts import (
    BUNDLE_RETENTION,
    bundle_retention,
    prune_old_run_dirs,
)
from tools.runtime.catalog import (
    TESTS,
    find_test,
    promotion_candidates,
    suite_names,
    tests_in_suite,
)
from tools.runtime.runner import format_console_summary


REPO_ROOT = Path(__file__).resolve().parents[2]
RESULT_DIR = REPO_ROOT / "build-runtime-tests" / "runtime-results"


def add_run_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("name")
    parser.add_argument("--timeout", type=float)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--rerun-seh", action="store_true")
    parser.add_argument(
        "--require-fixtures",
        action="store_true",
        help="fail instead of skipping when a local retail-derived fixture is missing",
    )
    parser.add_argument(
        "--gdb",
        action="store_true",
        help="attach the debugger on the first attempt instead of only on failure",
    )
    parser.add_argument(
        "--no-gdb",
        action="store_true",
        help="run directly under Wine as a debugger-sensitivity control",
    )


def run_one(args: argparse.Namespace) -> int:
    test = find_test(args.name)
    if test is None:
        raise SystemExit(f"unknown runtime test {args.name!r}; run `just runtime-test-list`")
    if args.seed < 1:
        raise SystemExit("--seed must be a positive integer")
    if args.timeout is None:
        args.timeout = test.default_timeout
    if test.execution == "harness":
        from tools.runtime.harness_selftest import run_harness_selftest

        return run_harness_selftest(test, args.seed, REPO_ROOT / "build-runtime-tests", RESULT_DIR)
    from tools.runtime.runtime_tests import run_test

    return run_test(args)


def list_tests(_: argparse.Namespace) -> int:
    for test in TESTS:
        fixture = f" fixture={test.fixture.filename}" if test.fixture else ""
        expected = " expected_failure" if test.expected_failure else ""
        print(
            f"{test.name:38s} factory={test.native_factory:34s} execution={test.execution:7s} "
            f"suites={','.join(test.suites)} evidence={test.evidence_kind}"
            f"{fixture}{expected}"
        )
    return 0


def _suite_command(test_name: str, args: argparse.Namespace) -> list[str]:
    test = find_test(test_name)
    if test is None:
        raise ValueError(f"suite contains unknown runtime test {test_name!r}")
    timeout = test.default_timeout if args.timeout is None else args.timeout
    command = [
        sys.executable,
        "-m",
        "tools.runtime.cli",
        "run",
        test_name,
        "--seed",
        str(args.seed),
        "--timeout",
        str(timeout),
    ]
    if args.rerun_seh:
        command.append("--rerun-seh")
    if getattr(args, "gdb", False):
        command.append("--gdb")
    if args.no_gdb:
        command.append("--no-gdb")
    if args.require_fixtures:
        command.append("--require-fixtures")
    return command


@dataclass(frozen=True)
class SuiteCaseResult:
    name: str
    returncode: int
    status: str
    result: dict


def _read_suite_case(name: str, returncode: int) -> SuiteCaseResult:
    result_path = RESULT_DIR / f"{name}.json"
    try:
        parsed = json.loads(result_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        parsed = {"status": "failed", "failure": f"missing or invalid canonical result: {error}"}
    reported_status = parsed.get("status")
    if returncode == 0 and reported_status in {"passed", "skipped", "expected_failure"}:
        status = reported_status
    else:
        status = "failed"
    return SuiteCaseResult(name, returncode, status, parsed)


def run_suite(args: argparse.Namespace) -> int:
    tests = tests_in_suite(args.suite)
    if not tests:
        raise SystemExit(f"unknown or empty suite {args.suite!r}; choices: {', '.join(suite_names())}")

    def invoke(name: str) -> SuiteCaseResult:
        (RESULT_DIR / f"{name}.json").unlink(missing_ok=True)
        completed = subprocess.run(_suite_command(name, args), cwd=REPO_ROOT, check=False)
        return _read_suite_case(name, completed.returncode)

    with ThreadPoolExecutor(max_workers=args.jobs) as executor:
        results = list(executor.map(lambda test: invoke(test.name), tests))
    failed = [result for result in results if result.status == "failed"]
    skipped = [result for result in results if result.status == "skipped"]
    expected_failures = [
        result for result in results if result.status == "expected_failure"
    ]
    passed = [result for result in results if result.status == "passed"]
    if args.junit is not None:
        suite = ET.Element(
            "testsuite",
            name=f"imperialism-runtime-{args.suite}",
            tests=str(len(results)),
            failures=str(len(failed)),
            skipped=str(len(skipped) + len(expected_failures)),
        )
        for result in results:
            summary = result.result.get("summary", {})
            duration = summary.get("duration_seconds")
            case_attributes = {"classname": "runtime", "name": result.name}
            if isinstance(duration, (int, float)):
                case_attributes["time"] = str(duration)
            case = ET.SubElement(suite, "testcase", **case_attributes)
            concise = format_console_summary(result.result)
            if result.status == "failed":
                failure = ET.SubElement(case, "failure", message=concise)
                failure.text = json.dumps(result.result, indent=2, sort_keys=True)
            elif result.status in {"skipped", "expected_failure"}:
                ET.SubElement(
                    case,
                    "skipped",
                    message=(
                        "expected failure: " + str(result.result.get("failure", "matched"))
                        if result.status == "expected_failure"
                        else str(result.result.get("failure", "runtime test skipped"))
                    ),
                )
            system_out = ET.SubElement(case, "system-out")
            system_out.text = concise
        args.junit.parent.mkdir(parents=True, exist_ok=True)
        ET.ElementTree(suite).write(args.junit, encoding="utf-8", xml_declaration=True)
    print(
        f"suite {args.suite}: {len(passed)} passed, {len(expected_failures)} expected failures, "
        f"{len(skipped)} skipped, "
        f"{len(failed)} failed"
    )
    if skipped:
        print("skipped: " + ", ".join(result.name for result in skipped))
    if failed:
        print("failed: " + ", ".join(result.name for result in failed))
        for result in failed:
            print(format_console_summary(result.result))
    candidates = promotion_candidates({result.name: result.result for result in results})
    for candidate in candidates:
        print(
            f"promotion candidate: {candidate.name} -> "
            f"{','.join(candidate.promotion_suites)} (order {candidate.promotion_order})"
        )
    return 1 if failed else 0


def show_result(args: argparse.Namespace) -> int:
    path = RESULT_DIR / f"{args.name}.json"
    if not path.is_file():
        raise SystemExit(f"no runtime result for {args.name!r}")
    parsed = json.loads(path.read_text(encoding="utf-8"))
    print(json.dumps(parsed, indent=2, sort_keys=True))
    return 0


def run_determinism(args: argparse.Namespace) -> int:
    from tools.runtime.determinism import classify_leaks

    tests = tests_in_suite(args.suite)
    if not tests:
        raise SystemExit(f"unknown or empty suite {args.suite!r}")

    def run_order(label: str, ordered_tests: tuple, use_gdb: bool) -> dict[str, dict]:
        observations: dict[str, dict] = {}
        for test in ordered_tests:
            run_args = argparse.Namespace(
                seed=args.seed,
                timeout=args.timeout,
                rerun_seh=False,
                gdb=use_gdb,
                no_gdb=not use_gdb,
                require_fixtures=args.require_fixtures,
            )
            (RESULT_DIR / f"{test.name}.json").unlink(missing_ok=True)
            completed = subprocess.run(
                _suite_command(test.name, run_args), cwd=REPO_ROOT, check=False
            )
            case = _read_suite_case(test.name, completed.returncode)
            observations[test.name] = case.result
        print(f"determinism {label}: captured {len(observations)} tests")
        return observations

    baseline = run_order("same_order_1", tests, False)
    comparisons = [
        ("same_order", run_order("same_order_2", tests, False)),
        ("reverse_order", run_order("reverse_order", tuple(reversed(tests)), False)),
    ]
    if args.gdb:
        comparisons.append(("gdb", run_order("gdb", tests, True)))
    findings = [
        finding
        for label, observations in comparisons
        for finding in classify_leaks(baseline, observations, label)
    ]
    report = {
        "suite": args.suite,
        "seed": args.seed,
        "orders": [label for label, _ in comparisons],
        "findings": findings,
        "status": "failed" if findings else "passed",
    }
    report_path = RESULT_DIR / f"determinism-{args.suite}.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 1 if findings else 0


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
    suite.add_argument("--timeout", type=float)
    suite.add_argument("--seed", type=int, default=1)
    suite.add_argument("--rerun-seh", action="store_true")
    suite.add_argument("--no-gdb", action="store_true")
    suite.add_argument(
        "--require-fixtures",
        action="store_true",
        help="fail instead of skipping when a local retail-derived fixture is missing",
    )
    suite.add_argument("--junit", type=Path)
    suite.set_defaults(func=run_suite)
    show = commands.add_parser("show", help="show the latest canonical result")
    show.add_argument("name")
    show.set_defaults(func=show_result)
    determinism = commands.add_parser(
        "determinism", help="repeat a suite in same/reverse order and compare observations"
    )
    determinism.add_argument("suite", choices=suite_names())
    determinism.add_argument("--seed", type=int, default=1)
    determinism.add_argument("--timeout", type=float)
    determinism.add_argument("--gdb", action="store_true")
    determinism.add_argument("--require-fixtures", action="store_true")
    determinism.set_defaults(func=run_determinism)
    clean = commands.add_parser(
        "clean", help="stop this worktree's warm wineserver and Xvfb, drop its prefix"
    )
    clean.set_defaults(func=clean_worktree_runtime)
    prune = commands.add_parser(
        "prune", help="drop old run bundles, keeping the newest per test name"
    )
    prune.add_argument("--keep", type=int, default=None,
                       help=f"bundles to keep per test (default {BUNDLE_RETENTION}, "
                            "0 removes every bundle)")
    prune.set_defaults(func=prune_run_bundles)
    return parser


def prune_run_bundles(args: argparse.Namespace) -> int:
    """Apply bundle retention across every test name, not just the one that just ran.

    Each bundle stages its own read-only game/ sandbox, so this is the supported way to
    reclaim the space: hand-deleting one needs a chmod first (imperialism-decomp-mx2a).
    """
    keep = bundle_retention() if args.keep is None else max(args.keep, 0)
    if not RESULT_DIR.is_dir():
        print(f"no run bundles: {RESULT_DIR} does not exist")
        return 0
    names = sorted({path.name.rsplit("-2", 1)[0] for path in RESULT_DIR.iterdir() if path.is_dir()})
    removed_total = 0
    stuck: list[Path] = []
    for name in names:
        removed, survivors = prune_old_run_dirs(RESULT_DIR, name, keep)
        removed_total += removed
        stuck.extend(survivors)
    remaining = sum(1 for path in RESULT_DIR.iterdir() if path.is_dir())
    print(f"pruned {removed_total} run bundle(s) across {len(names)} test name(s); "
          f"{remaining} kept (retention {keep})")
    for path in stuck:
        print(f"  could not remove: {path}")
    return 1 if stuck else 0


def clean_worktree_runtime(_: argparse.Namespace) -> int:
    """Stop the warm wineserver and Xvfb this worktree kept, and drop its prefix.

    The runtime session deliberately leaves both running between tests; this is how a
    worktree gives them back when it is done, or recovers if one wedges.
    """
    import json
    import os
    import shutil
    import subprocess

    from tools.runtime.wine import BUILD_DIR, prefix_environment, worktree_prefix

    prefix = worktree_prefix()
    if prefix.is_dir():
        subprocess.run(
            ["wineserver", "-k"], env=prefix_environment(prefix), check=False, capture_output=True
        )
        shutil.rmtree(prefix, ignore_errors=True)
        print(f"removed {prefix}")
    display_state = BUILD_DIR / "xvfb-display.json"
    try:
        state = json.loads(display_state.read_text(encoding="utf-8"))
        os.kill(int(state["pid"]), 15)
        print(f"stopped Xvfb {state['display']} (pid {state['pid']})")
    except (OSError, ValueError, KeyError, TypeError):
        pass
    display_state.unlink(missing_ok=True)
    return 0


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0] not in {
        "run",
        "list",
        "suite",
        "determinism",
        "show",
        "clean",
        "prune",
    }:
        arguments.insert(0, "run")
    args = build_parser().parse_args(arguments)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
