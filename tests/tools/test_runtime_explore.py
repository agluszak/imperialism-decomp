from pathlib import Path

from tools.runtime.catalog import find_test
from tools.runtime.explore import ExploreAction, ddmin, encode_replay, read_trace


def action(name: str) -> ExploreAction:
    return ExploreAction(name, 10, 20)


def test_explorer_is_registered_but_not_in_gating_suites() -> None:
    spec = find_test("random_control_explorer")

    assert spec is not None
    assert spec.suites == ()
    assert spec.required_oracles == ()


def test_ddmin_removes_irrelevant_actions() -> None:
    actions = [action("a"), action("b"), action("crash"), action("c")]

    minimized = ddmin(actions, lambda candidate: any(item.path == "crash" for item in candidate))

    assert minimized == [action("crash")]


def test_trace_roundtrip(tmp_path: Path) -> None:
    trace = tmp_path / "trace.jsonl"
    trace.write_text(
        '{"path":"00000001#1/00000002#1","local_x":4,"local_y":5,'
        '"tag":"00000002","class":"TButton","event":17}\n',
        encoding="utf-8",
    )

    actions = read_trace(trace)

    assert actions == [
        ExploreAction("00000001#1/00000002#1", 4, 5, "00000002", "TButton", 17)
    ]
    assert encode_replay(actions) == "00000001#1/00000002#1\t4\t5"
