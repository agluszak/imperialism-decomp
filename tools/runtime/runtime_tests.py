#!/usr/bin/env python3
"""Run one compiled semantic test in the instrumented Imperialism executable.

Each run is isolated in its own WINEPREFIX and produces a per-run bundle under
build-runtime-tests/runtime-results/<run-id>/ containing result.json, the final
heartbeat.json, wine.log, run.json (host metadata + failure classification) and,
on failure, a best-effort screenshot. Cleanup only ever touches the run's own
Wine server and game process — never other agents' sessions.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

REPO_ROOT = Path(__file__).resolve().parents[2]
BUILD_DIR = REPO_ROOT / "build-runtime-tests"
sys.path.insert(0, str(REPO_ROOT))

from tools.workflow.ui_platform_diff import build_report

HEARTBEAT_STALE_SECONDS = 15.0
FIRST_HEARTBEAT_SECONDS = 60.0
POLL_INTERVAL_SECONDS = 0.5
BUNDLE_RETENTION = 10

# Logical fixture names per test. The files themselves are retail-derived local
# saves and stay out of git; missing fixtures skip the test explicitly.
FIXTURES = {"load_saved_game": "beginning_of_game.imp"}


def fixture_directory() -> Path:
    override = os.environ.get("IMPERIALISM_SAVE_FIXTURES")
    if override:
        return Path(override)
    return REPO_ROOT / "tests" / "runtime" / "fixtures"


def retail_game_dir() -> Path:
    original = os.environ.get("ORIGINAL_BINARY")
    if not original:
        raise SystemExit("Set ORIGINAL_BINARY to a complete retail installation")
    game_dir = Path(original).resolve().parent
    if not (game_dir / "Data").is_dir():
        raise SystemExit(f"Missing {game_dir / 'Data'}")
    return game_dir


def windows_path(path: Path, environment: dict[str, str]) -> str:
    result = subprocess.run(
        ["winepath", "-w", str(path)],
        check=True,
        capture_output=True,
        text=True,
        env=environment,
    )
    return result.stdout.strip()


def semantic_node_paths(nodes: dict[str, dict]) -> dict[str, tuple[str, dict]]:
    paths: dict[str, str] = {}
    occurrences: dict[tuple[str | None, str], int] = {}
    result: dict[str, tuple[str, dict]] = {}
    for node_id, row in nodes.items():
        semantic = row["semantic"]
        parent_id = semantic["parent_id"]
        tag = semantic["tag"]
        occurrence_key = (parent_id, tag)
        occurrence = occurrences.get(occurrence_key, 0) + 1
        occurrences[occurrence_key] = occurrence
        tag_value = int.from_bytes(tag.encode("ascii"), "big")
        segment = f"{tag_value:08x}#{occurrence}"
        path = segment if parent_id is None else f"{paths[parent_id]}/{segment}"
        paths[node_id] = path
        result[path] = (node_id, row)
    return result


def expected_case_for_event(report: dict, event: int) -> tuple[str, dict]:
    event_key = f"0x{event:04x}"
    matches = [
        (function_key, function["cases"][event_key])
        for function_key, function in report["functions"].items()
        if event_key in function["cases"]
    ]
    if len(matches) != 1:
        raise ValueError(
            f"event {event_key} maps to {len(matches)} generated UI cases; expected one"
        )
    return matches[0]


def compare_ui_snapshot(report: dict, snapshot: dict) -> dict:
    event = int(snapshot["event"])
    event_key = f"0x{event:04x}"
    function_key, case = expected_case_for_event(report, event)
    expected = semantic_node_paths(case["nodes"])
    live = {str(node["path"]): node for node in snapshot.get("nodes", [])}
    differences: list[dict] = []

    for path in sorted(set(expected) - set(live)):
        node_id, row = expected[path]
        differences.append(
            {
                "kind": "missing_node",
                "path": path,
                "node_id": node_id,
                "tag": row["tag"],
                "source": row["mac_source"] or row["windows_binary_evidence"],
            }
        )
    for path in sorted(set(live) - set(expected)):
        node = live[path]
        differences.append(
            {
                "kind": "extra_node",
                "path": path,
                "tag": node["tag"],
                "class": node["class"],
            }
        )

    field_map = {
        "class_name": "class",
        "geometry": "bounds",
        "state": "state",
        "enabled": "enabled",
        "control_value": "control_value",
    }
    for path in sorted(set(expected) & set(live)):
        node_id, row = expected[path]
        semantic = row["semantic"]
        actual = live[path]
        checks = [
            (expected_name, live_name, semantic[expected_name])
            for expected_name, live_name in field_map.items()
        ]
        family = semantic["family"]
        if family.get("picture_id") is not None:
            checks.append(("picture_id", "picture_id", family["picture_id"]))
        text = family.get("text")
        if text is not None and text.get("value") is not None:
            checks.append(("text", "text", text["value"]))
        for expected_name, live_name, expected_value in checks:
            if isinstance(expected_value, tuple):
                expected_value = list(expected_value)
            actual_value = actual.get(live_name)
            if actual_value != expected_value:
                differences.append(
                    {
                        "kind": "field_mismatch",
                        "path": path,
                        "node_id": node_id,
                        "tag": row["tag"],
                        "field": expected_name,
                        "expected": expected_value,
                        "actual": actual_value,
                        "classification": row["classification"],
                        "source": row["mac_source"] or row["windows_binary_evidence"],
                    }
                )

    return {
        "event": event_key,
        "factory": function_key,
        "source": case["source"],
        "nodes_checked": len(expected),
        "status": "passed" if not differences else "failed",
        "differences": differences,
    }


def apply_ui_oracle(result: dict) -> None:
    snapshots = result.get("ui_snapshots", [])
    if not snapshots:
        return
    report, errors = build_report(REPO_ROOT)
    if errors:
        raise ValueError("UI platform model is invalid: " + "; ".join(errors))
    comparisons = [compare_ui_snapshot(report, snapshot) for snapshot in snapshots]
    result["ui_oracle"] = {
        "status": (
            "passed"
            if all(comparison["status"] == "passed" for comparison in comparisons)
            else "failed"
        ),
        "snapshots": comparisons,
    }
    if result["ui_oracle"]["status"] == "failed":
        result["status"] = "failed"
        result["failure"] = "Mac-derived UI oracle mismatch"


def compare_map_state(map_state: dict, expected: dict) -> dict:
    """Field-wise comparison of the driver's normalized simulation snapshot."""
    differences = {
        key: {"expected": value, "actual": map_state.get(key)}
        for key, value in expected.items()
        if map_state.get(key) != value
    }
    return {
        "status": "passed" if not differences else "failed",
        "differences": differences,
    }


def apply_map_oracle(result: dict, name: str, seed: int) -> None:
    """Compare map_state against the committed seed-specific expectation.

    Missing expectation files skip explicitly (new tests/seeds); to record one,
    copy the passing run's map_state block into the expectation path.
    """
    map_state = result.get("map_state")
    if not map_state:
        return
    expectation_path = (
        REPO_ROOT / "tests" / "runtime" / "expectations" / f"{name}.seed{seed}.json"
    )
    relative = expectation_path.relative_to(REPO_ROOT)
    expected = read_json_file(expectation_path)
    if expected is None:
        result["map_oracle"] = {"status": "skipped", "reason": f"missing {relative}"}
        return
    comparison = compare_map_state(map_state, expected)
    comparison["expectation"] = str(relative)
    result["map_oracle"] = comparison
    if comparison["status"] == "failed":
        result["status"] = "failed"
        result["failure"] = "map-state oracle mismatch"


def classify_poll(
    heartbeat: dict | None,
    heartbeat_age_seconds: float | None,
    no_progress_budget_seconds: float,
    stale_budget_seconds: float = HEARTBEAT_STALE_SECONDS,
    process_age_seconds: float | None = None,
    first_heartbeat_budget_seconds: float = FIRST_HEARTBEAT_SECONDS,
) -> str | None:
    """Classify a still-running game from its latest heartbeat.

    Returns a failure classification when the run should be killed, else None.
    Before the driver's first write only the startup budget applies: a process
    that has been alive longer than first_heartbeat_budget_seconds without a
    single heartbeat is a hung boot.
    """
    if heartbeat is None or heartbeat_age_seconds is None:
        if (
            process_age_seconds is not None
            and process_age_seconds > first_heartbeat_budget_seconds
        ):
            return "heartbeat_stopped"
        return None
    if heartbeat_age_seconds > stale_budget_seconds:
        return "heartbeat_stopped"
    if heartbeat.get("hold"):
        # Held-open debugging session: fresh heartbeats intentionally make no
        # semantic progress; only staleness and the wall deadline apply.
        return None
    elapsed_ms = heartbeat.get("elapsed_ms")
    last_progress_ms = heartbeat.get("last_progress_ms")
    if (
        isinstance(elapsed_ms, int)
        and isinstance(last_progress_ms, int)
        and elapsed_ms - last_progress_ms > no_progress_budget_seconds * 1000.0
    ):
        return "pump_alive_no_semantic_progress"
    return None


def classify_exit(returncode: int, result_exists: bool) -> str | None:
    """Classify a game process that exited on its own."""
    if result_exists:
        return None
    return "crash" if returncode != 0 else "exited_without_result"


def read_json_file(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def no_progress_budget_seconds(phase_timeout_ms: int) -> float:
    """Host-side backstop: the driver should fail a stuck phase itself first."""
    return phase_timeout_ms / 1000.0 * 1.5 + HEARTBEAT_STALE_SECONDS


def populate_wine_prefix(prefix: Path) -> None:
    """wineboot a fresh prefix and seed the game's first-run settings."""
    prefix.mkdir(parents=True, exist_ok=True)
    environment = prefix_environment(prefix)
    subprocess.run(
        ["wineboot", "--init"],
        env=environment,
        check=True,
        capture_output=True,
        timeout=180,
    )
    # First-run settings the game otherwise prompts for: without a saved AutoRes,
    # ShowAutoResolutionDialogIfNeeded (ImperialismApp.cpp) blocks startup on a
    # modal resolution dialog; Language pins deterministic .irg selection.
    settings_key = "HKCU\\Software\\SSI\\Imperialism\\Settings"
    for value_args in (
        ["/v", "AutoRes", "/t", "REG_DWORD", "/d", "0"],
        ["/v", "Language", "/d", "ENGLISH"],
    ):
        subprocess.run(
            ["wine", "reg", "add", settings_key, *value_args, "/f"],
            env=environment,
            check=True,
            capture_output=True,
            timeout=60,
        )
    subprocess.run(
        ["wineserver", "--wait"],
        env=environment,
        check=False,
        capture_output=True,
        timeout=180,
    )


def ensure_template_prefix() -> Path:
    """Build (once per Wine version) the seeded prefix that runs are cloned from.

    wineboot costs ~6-7s while cloning the finished prefix costs well under a
    second, so per-run isolation copies this template instead of booting fresh.
    Concurrent builders race benignly: each boots into its own temp dir and the
    loser of the atomic rename simply discards its copy.
    """
    template = BUILD_DIR / "wineprefix-template"
    stamp = template / ".imperialism-template"
    wine_version = subprocess.run(
        ["wine", "--version"], capture_output=True, text=True, check=True
    ).stdout.strip()
    try:
        if stamp.read_text(encoding="utf-8").strip() == wine_version:
            return template
    except OSError:
        pass
    staging = template.with_name(f"{template.name}.build-{os.getpid()}")
    shutil.rmtree(staging, ignore_errors=True)
    populate_wine_prefix(staging)
    (staging / stamp.name).write_text(wine_version + "\n", encoding="utf-8")
    shutil.rmtree(template, ignore_errors=True)
    try:
        staging.rename(template)
    except OSError:
        # Another run installed the template first; keep theirs.
        shutil.rmtree(staging, ignore_errors=True)
    return template


def initialize_wine_prefix(prefix: Path, environment: dict[str, str]) -> None:
    del environment  # the clone is seeded already; env only matters at boot time
    template = ensure_template_prefix()
    subprocess.run(
        ["cp", "-a", "--reflink=auto", str(template), str(prefix)],
        check=True,
        capture_output=True,
        timeout=180,
    )


def shut_down_wine_prefix(environment: dict[str, str]) -> None:
    subprocess.run(
        ["wineserver", "-k"], env=environment, check=False, capture_output=True
    )
    subprocess.run(
        ["wineserver", "--wait"],
        env=environment,
        check=False,
        capture_output=True,
        timeout=60,
    )


def capture_failure_screenshot(destination: Path) -> None:
    """Best-effort screenshot of the still-running game window."""
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
    """Keep only the newest `keep` run bundles for a test (run-ids sort by time)."""
    runs = sorted(path for path in result_dir.glob(f"{name}-2*") if path.is_dir())
    for stale in runs[:-keep] if keep > 0 else runs:
        shutil.rmtree(stale, ignore_errors=True)


def prefix_environment(prefix: Path) -> dict[str, str]:
    environment = dict(os.environ)
    environment["WINEPREFIX"] = str(prefix)
    environment["WINEDEBUG"] = environment.get("WINEDEBUG", "-all")
    # Skip the Mono/Gecko installers in the fresh per-run prefix.
    environment.setdefault("WINEDLLOVERRIDES", "mscoree,mshtml=")
    return environment


def execute_run(
    name: str,
    run_dir: Path,
    seed: int,
    timeout: float,
    phase_timeout_ms: int,
    winedebug: str | None,
    wine_log_name: str,
    fixture: Path | None = None,
) -> dict:
    """One isolated game run; returns host metadata including classification."""
    executable = BUILD_DIR / "Imperialism.exe"
    if not executable.is_file():
        raise SystemExit(f"Missing {executable}; run `just runtime-test-build` first")

    prefix = run_dir / "prefix"
    result_path = run_dir / "result.json"
    heartbeat_path = run_dir / "heartbeat.json"
    result_path.unlink(missing_ok=True)
    heartbeat_path.unlink(missing_ok=True)

    environment = prefix_environment(prefix)
    if winedebug is not None:
        environment["WINEDEBUG"] = winedebug

    classification: str | None = None
    budget_seconds = no_progress_budget_seconds(phase_timeout_ms)
    pid_path = run_dir / "pid"
    started = time.monotonic()
    try:
        initialize_wine_prefix(prefix, environment)

        environment["IMPERIALISM_RUNTIME_TEST"] = name
        environment["IMPERIALISM_RUNTIME_TEST_RESULT"] = windows_path(
            result_path, environment
        )
        environment["IMPERIALISM_RUNTIME_TEST_HEARTBEAT"] = windows_path(
            heartbeat_path, environment
        )
        environment["IMPERIALISM_RUNTIME_TEST_SEED"] = str(seed)
        environment["IMPERIALISM_RUNTIME_TEST_PHASE_TIMEOUT_MS"] = str(phase_timeout_ms)
        if fixture is not None:
            environment["IMPERIALISM_RUNTIME_TEST_FIXTURE"] = windows_path(
                fixture, environment
            )

        with (run_dir / wine_log_name).open("wb") as wine_log:
            process = subprocess.Popen(
                ["wine", str(executable)],
                cwd=retail_game_dir(),
                env=environment,
                stdout=wine_log,
                stderr=subprocess.STDOUT,
            )
            pid_path.write_text(f"{process.pid}\n", encoding="utf-8")
            while True:
                returncode = process.poll()
                if returncode is not None:
                    classification = classify_exit(returncode, result_path.is_file())
                    break
                heartbeat = read_json_file(heartbeat_path)
                heartbeat_age = None
                if heartbeat is not None:
                    try:
                        heartbeat_age = time.time() - heartbeat_path.stat().st_mtime
                    except OSError:
                        heartbeat = None
                classification = classify_poll(
                    heartbeat,
                    heartbeat_age,
                    budget_seconds,
                    process_age_seconds=time.monotonic() - started,
                )
                if classification is None and time.monotonic() - started > timeout:
                    classification = "action_timeout"
                if classification is not None:
                    capture_failure_screenshot(run_dir / "failure-screenshot.png")
                    process.kill()
                    process.wait(timeout=30)
                    returncode = process.returncode
                    break
                time.sleep(POLL_INTERVAL_SECONDS)
    finally:
        shut_down_wine_prefix(environment)
        pid_path.unlink(missing_ok=True)
        shutil.rmtree(prefix, ignore_errors=True)

    return {
        "classification": classification,
        "wine_exit": returncode,
        "duration_seconds": round(time.monotonic() - started, 3),
    }


def run_test(args: argparse.Namespace) -> int:
    name = args.name
    result_dir = BUILD_DIR / "runtime-results"
    result_dir.mkdir(parents=True, exist_ok=True)

    fixture: Path | None = None
    if name in FIXTURES:
        fixture = fixture_directory() / FIXTURES[name]
        if not fixture.is_file():
            skipped = {
                "format_version": 1,
                "name": name,
                "status": "skipped",
                "failure": (
                    f"missing local save fixture {fixture}; place a retail-derived "
                    "save there (never committed) to enable this test"
                ),
            }
            serialized = json.dumps(skipped, indent=2, sort_keys=True) + "\n"
            (result_dir / f"{name}.json").write_text(serialized, encoding="utf-8")
            print(serialized, end="")
            return 0
    run_id = f"{name}-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{os.getpid()}"
    run_dir = result_dir / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    host = execute_run(
        name=name,
        run_dir=run_dir,
        seed=args.seed,
        timeout=args.timeout,
        phase_timeout_ms=args.phase_timeout_ms,
        winedebug=None,
        wine_log_name="wine.log",
        fixture=fixture,
    )
    host.update(
        {
            "run_id": run_id,
            "run_dir": str(run_dir),
            "seed": args.seed,
            "timeout_seconds": args.timeout,
            "phase_timeout_ms": args.phase_timeout_ms,
        }
    )

    result_path = run_dir / "result.json"
    result = read_json_file(result_path)
    if result is None:
        result = {
            "format_version": 1,
            "name": name,
            "status": "failed",
            "failure": host["classification"] or "missing result file",
        }
    else:
        if result.get("seed") != args.seed:
            raise SystemExit(
                f"driver ran with seed {result.get('seed')}, requested {args.seed}"
            )
        try:
            apply_ui_oracle(result)
        except ValueError as error:
            raise SystemExit(str(error)) from error
        apply_map_oracle(result, name, args.seed)

    failed = result.get("status") != "passed" or host["classification"] is not None
    if failed and args.rerun_seh:
        host["seh_rerun"] = execute_run(
            name=name,
            run_dir=run_dir,
            seed=args.seed,
            timeout=args.timeout,
            phase_timeout_ms=args.phase_timeout_ms,
            winedebug="+seh",
            wine_log_name="wine-seh.log",
            fixture=fixture,
        )

    result["host"] = host
    (run_dir / "run.json").write_text(
        json.dumps(host, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    serialized = json.dumps(result, indent=2, sort_keys=True) + "\n"
    result_path.write_text(serialized, encoding="utf-8")
    # Canonical latest-result location, kept for existing consumers.
    (result_dir / f"{name}.json").write_text(serialized, encoding="utf-8")
    prune_old_run_dirs(result_dir, name)
    print(serialized, end="")
    if host["classification"] is not None:
        print(f"runtime test classified as {host['classification']}", file=sys.stderr)
        return 1
    if host["wine_exit"] != 0:
        print(f"Wine process exited with code {host['wine_exit']}", file=sys.stderr)
        return 1
    return 0 if result.get("status") == "passed" else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("name", nargs="?", default="boot_managers")
    parser.add_argument("--timeout", type=float, default=300)
    parser.add_argument(
        "--seed",
        type=int,
        default=1,
        help="game RNG seed; keep the fixed default for PR runs, rotate nightly in CI",
    )
    parser.add_argument(
        "--phase-timeout-ms",
        type=int,
        default=60000,
        help="driver-side per-phase deadline in milliseconds",
    )
    parser.add_argument(
        "--rerun-seh",
        action="store_true",
        help="on failure, rerun once with WINEDEBUG=+seh into wine-seh.log",
    )
    args = parser.parse_args()
    if args.seed < 1:
        parser.error("--seed must be a positive integer")
    return run_test(args)


if __name__ == "__main__":
    raise SystemExit(main())
