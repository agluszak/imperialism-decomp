from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tools.runtime.catalog import find_test
from tools.runtime.explore import (
    ExploreAction,
    ddmin,
    encode_replay,
    failure_signature,
    read_trace,
    run_explorer,
    same_failure,
)


def action(name: str) -> ExploreAction:
    return ExploreAction(name, 10, 20)


def outcome(
    run_dir: Path,
    *,
    classification: str | None,
    fault_address: str | None = None,
):
    host = SimpleNamespace(
        classification=classification,
        inferior_signal=None,
        debugger_signal="SIGSEGV" if classification == "crash" else None,
        debugger_invariant=None,
    )
    attempt = SimpleNamespace(host=host, run_dir=run_dir)
    faults = []
    if fault_address is not None:
        faults.append({"address": fault_address, "code": "0xc0000005"})
    return SimpleNamespace(
        attempts=(attempt,),
        result={"status": "failed" if classification else "passed", "runtime": {"faults": faults}},
    )


class RuntimeExploreTests(unittest.TestCase):
    def test_explorer_is_registered_but_not_in_gating_suites(self) -> None:
        spec = find_test("random_control_explorer")

        self.assertIsNotNone(spec)
        assert spec is not None
        self.assertEqual(spec.suites, ())
        self.assertEqual(spec.required_oracles, ())

    def test_ddmin_removes_irrelevant_actions(self) -> None:
        actions = [action("a"), action("b"), action("crash"), action("c")]

        minimized = ddmin(
            actions, lambda candidate: any(item.path == "crash" for item in candidate)
        )

        self.assertEqual(minimized, [action("crash")])

    def test_trace_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            trace = Path(directory) / "trace.jsonl"
            trace.write_text(
                '{"path":"00000001#1/00000002#1","local_x":4,"local_y":5,'
                '"tag":"00000002","class":"TButton","event":17}\n',
                encoding="utf-8",
            )

            actions = read_trace(trace)

        self.assertEqual(
            actions,
            [ExploreAction("00000001#1/00000002#1", 4, 5, "00000002", "TButton", 17)],
        )
        self.assertEqual(encode_replay(actions), "00000001#1/00000002#1\t4\t5")

    def test_failure_signature_distinguishes_fault_site_and_control_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "first"
            same = root / "same"
            other_fault = root / "other-fault"
            other_path = root / "other-path"
            other_coordinate = root / "other-coordinate"
            for run_dir, path, local_x in (
                (first, "00000001#1/00000002#1", 4),
                (same, "00000001#1/00000002#1", 4),
                (other_fault, "00000001#1/00000002#1", 4),
                (other_path, "00000001#1/00000003#1", 4),
                (other_coordinate, "00000001#1/00000002#1", 7),
            ):
                run_dir.mkdir()
                (run_dir / "exploration-trace.jsonl").write_text(
                    f'{{"path":"{path}","local_x":{local_x},"local_y":5}}\n',
                    encoding="utf-8",
                )

            expected = failure_signature(
                outcome(first, classification="crash", fault_address="0058B6F8")
            )
            self.assertIsNotNone(expected)
            assert expected is not None
            self.assertTrue(
                same_failure(
                    expected, outcome(same, classification="crash", fault_address="0058B6F8")
                )
            )
            self.assertFalse(
                same_failure(
                    expected,
                    outcome(other_fault, classification="crash", fault_address="00600000"),
                )
            )
            self.assertFalse(
                same_failure(
                    expected,
                    outcome(other_path, classification="crash", fault_address="0058B6F8"),
                )
            )
            self.assertFalse(
                same_failure(
                    expected,
                    outcome(
                        other_coordinate, classification="crash", fault_address="0058B6F8"
                    ),
                )
            )

    def test_one_action_failure_requires_final_replay_verification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = root / "original"
            replay = root / "replay"
            original.mkdir()
            replay.mkdir()
            (original / "exploration-trace.jsonl").write_text(
                '{"path":"00000001#1/00000002#1","local_x":4,"local_y":5}\n',
                encoding="utf-8",
            )
            failed = outcome(original, classification="crash", fault_address="0058B6F8")
            passed = outcome(replay, classification=None)
            args = SimpleNamespace(
                replay=None,
                runs=1,
                seed=1,
                steps=1,
                timeout=10.0,
                phase_timeout_ms=5000,
                settle_ticks=0,
                no_minimize=False,
            )

            with patch("tools.runtime.explore._runner", return_value=(object(), object())):
                with patch("tools.runtime.explore._run_once", side_effect=(failed, passed)) as run:
                    with self.assertRaisesRegex(RuntimeError, "failed final verification"):
                        run_explorer(args, result_dir=root, fixture_dir=root)

            self.assertEqual(run.call_count, 2)
