"""Pure map-state comparison used by runtime result processing."""

from __future__ import annotations


def compare_map_state(map_state: dict, expected: dict) -> dict:
    differences = {
        key: {"expected": value, "actual": map_state.get(key)}
        for key, value in expected.items()
        if map_state.get(key) != value
    }
    return {"status": "failed" if differences else "passed", "differences": differences}


from pathlib import Path

from tools.runtime.protocol import read_json_file

REPO_ROOT = Path(__file__).resolve().parents[3]

def apply_map_oracle(result: dict, name: str, seed: int) -> None:
    """Compare map_state against the committed seed-specific expectation.

    Missing expectation files skip explicitly (new tests/seeds); to record one,
    copy the passing run's map_state block into the expectation path.
    """
    map_state = result.get("map_state")
    if not map_state:
        # Say why rather than leaving the key absent. The driver only snapshots map
        # state on a passing finish, so this is the normal shape of a crashed or
        # timed-out run and must not read as an oracle-infrastructure problem.
        result["map_oracle"] = {
            "status": "skipped",
            "reason": "run captured no map_state; the driver snapshots it only on a passing finish",
        }
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
