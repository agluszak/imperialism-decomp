"""Integration tests for agent_task claim CAS semantics and start orchestration.

Real git repositories (a bare origin plus a work clone), no mocked subprocess:
the claim registry bugs this guards against (imperialism-decomp-hozh) were
exactly the kind a mocked `git push` cannot see — updating an existing claim
ref with a parentless commit is always non-fast-forward, so a plain push can
never refresh, take over, or steal a claim.

The orchestration test (imperialism-decomp-7sis) substitutes a fake `just`
executable on PATH and verifies the exact command names/arg order and that a
failed or empty portprep dossier fails agent-start without writing a ready
receipt.
"""

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path

import tools.workflow.agent_task as agent_task


def _git(cwd: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True, check=False
    )


def _init_repos(tmp: Path) -> tuple[Path, Path]:
    """Create a bare origin with a main branch and a work clone on a task branch."""
    origin = tmp / "origin.git"
    seed = tmp / "seed"
    work = tmp / "work"
    subprocess.run(["git", "init", "--bare", "-b", "main", str(origin)],
                   capture_output=True, check=True)
    seed.mkdir()
    _git(seed, "init", "-b", "main")
    _git(seed, "config", "user.email", "test@example.invalid")
    _git(seed, "config", "user.name", "Test")
    (seed / "src").mkdir()
    (seed / "include").mkdir()
    (seed / "src" / ".gitkeep").write_text("")
    (seed / "include" / ".gitkeep").write_text("")
    _git(seed, "add", "-A")
    _git(seed, "commit", "-m", "seed")
    _git(seed, "remote", "add", "origin", str(origin))
    _git(seed, "push", "origin", "main")
    subprocess.run(["git", "clone", str(origin), str(work)],
                   capture_output=True, check=True)
    _git(work, "config", "user.email", "test@example.invalid")
    _git(work, "config", "user.name", "Test")
    _git(work, "checkout", "-b", "task-branch")
    return origin, work


class ClaimRegistryCasTests(unittest.TestCase):
    """_push_claim must be a compare-and-swap against the observed remote claim."""

    ADDR = "0x0055aaff"

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="agent-task-claims-")
        tmp = Path(self._tmp)
        self.origin, self.work = _init_repos(tmp)
        self._saved_root = agent_task.REPO_ROOT
        agent_task.REPO_ROOT = self.work

    def tearDown(self):
        agent_task.REPO_ROOT = self._saved_root
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _remote_claim_sha(self) -> str:
        out = _git(self.work, "ls-remote", "origin",
                   agent_task.CLAIM_REF_PREFIX + self.ADDR).stdout.strip()
        return out.split()[0] if out else ""

    def test_fresh_claim_succeeds_only_on_absent_ref(self):
        self.assertTrue(agent_task._push_claim(self.ADDR, "task-branch", ""))
        first = self._remote_claim_sha()
        self.assertTrue(first)
        # A second "fresh" claim (expects the ref to be absent) must lose.
        self.assertFalse(agent_task._push_claim(self.ADDR, "other-branch", ""))
        self.assertEqual(self._remote_claim_sha(), first)

    def test_refresh_with_current_sha_succeeds_despite_non_fast_forward(self):
        self.assertTrue(agent_task._push_claim(self.ADDR, "task-branch", ""))
        first = self._remote_claim_sha()
        # Own-branch refresh: parentless commit -> non-fast-forward, must still land.
        # (Sleep so the refreshed claim commit differs from the first one; claim
        # payload timestamps have one-second resolution.)
        import time
        time.sleep(1.1)
        self.assertTrue(agent_task._push_claim(self.ADDR, "task-branch", first))
        second = self._remote_claim_sha()
        self.assertTrue(second)
        self.assertNotEqual(first, second)

    def test_takeover_with_stale_expectation_is_refused(self):
        self.assertTrue(agent_task._push_claim(self.ADDR, "task-branch", ""))
        stale = self._remote_claim_sha()
        # Another agent refreshes/steals in between (same CAS path).
        self.assertTrue(agent_task._push_claim(self.ADDR, "rival-branch", stale))
        current = self._remote_claim_sha()
        # Our takeover still expects the stale claim: the remote must reject it.
        self.assertFalse(agent_task._push_claim(self.ADDR, "task-branch", stale))
        self.assertEqual(self._remote_claim_sha(), current)

    def test_racing_agents_cannot_both_win(self):
        self.assertTrue(agent_task._push_claim(self.ADDR, "task-branch", ""))
        observed = self._remote_claim_sha()
        wins = [agent_task._push_claim(self.ADDR, branch, observed)
                for branch in ("racer-a", "racer-b")]
        self.assertEqual(sorted(wins), [False, True])


FAKE_JUST = """#!/usr/bin/env bash
echo "$@" >> "$FAKE_JUST_LOG"
case "$1" in
  tooling-check|func-status) exit 0 ;;
  ghidra)
    if [ "$2" != "portprep" ]; then
      echo "unexpected ghidra subcommand: $2" >&2; exit 3
    fi
    case "$FAKE_PORTPREP" in
      ok) echo "dossier for $3"; exit 0 ;;
      empty) exit 0 ;;
      fail) echo "boom" >&2; exit 1 ;;
    esac ;;
  ghidra-portprep) echo "retired recipe invoked" >&2; exit 2 ;;
  generated-integrity-gate)
    if [ "${FAKE_INTEGRITY:-ok}" = "fail" ]; then
      echo "Generated artifacts must not be committed:" >&2; exit 1
    fi
    exit 0 ;;
  *) exit 0 ;;
esac
"""


class AgentStartOrchestrationTests(unittest.TestCase):
    """cmd_start must call `just ghidra portprep` and hard-fail on a bad dossier."""

    ADDR = "0x0055aaff"

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="agent-task-start-")
        tmp = Path(self._tmp)
        self.origin, self.work = _init_repos(tmp)
        bin_dir = tmp / "bin"
        bin_dir.mkdir()
        just = bin_dir / "just"
        just.write_text(FAKE_JUST)
        just.chmod(0o755)
        self.calls_log = tmp / "calls.log"
        self._saved_env = dict(os.environ)
        os.environ["PATH"] = f"{bin_dir}{os.pathsep}{os.environ['PATH']}"
        os.environ["FAKE_JUST_LOG"] = str(self.calls_log)
        os.environ["GHIDRA_INSTALL_DIR"] = str(tmp)
        self._saved_root = agent_task.REPO_ROOT
        self._saved_tasks_dir = agent_task.TASKS_DIR
        self._saved_legacy = agent_task.LEGACY_TASK_JSON
        agent_task.REPO_ROOT = self.work
        agent_task.TASKS_DIR = self.work / "build-msvc500" / "agent-tasks"
        agent_task.LEGACY_TASK_JSON = self.work / "build-msvc500" / "agent-task.json"

    def tearDown(self):
        agent_task.REPO_ROOT = self._saved_root
        agent_task.TASKS_DIR = self._saved_tasks_dir
        agent_task.LEGACY_TASK_JSON = self._saved_legacy
        os.environ.clear()
        os.environ.update(self._saved_env)
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _args(self, **overrides) -> Namespace:
        base = dict(mode="port", addresses=[self.ADDR], allow_stale_base=False,
                    takeover=False, steal_claim=False, no_claim=True,
                    proceed_unclaimed=False, no_portprep=False, no_compare=True)
        base.update(overrides)
        return Namespace(**base)

    def _calls(self) -> list[str]:
        if not self.calls_log.is_file():
            return []
        return self.calls_log.read_text().splitlines()

    def test_start_invokes_just_ghidra_portprep_and_writes_receipt(self):
        os.environ["FAKE_PORTPREP"] = "ok"
        rc = agent_task.cmd_start(self._args())
        self.assertEqual(rc, 0)
        self.assertIn(f"ghidra portprep {self.ADDR}", self._calls())
        self.assertNotIn(f"ghidra-portprep {self.ADDR}", self._calls())
        receipt = json.loads(agent_task._receipt_path().read_text())
        self.assertIn("dossier for", receipt["targets"][self.ADDR]["portprep"])
        self.assertIn(f"portprep {self.ADDR}", receipt["steps"])

    def test_portprep_failure_fails_start_without_ready_receipt(self):
        os.environ["FAKE_PORTPREP"] = "fail"
        rc = agent_task.cmd_start(self._args())
        self.assertEqual(rc, 2)
        self.assertFalse(agent_task._receipt_path().is_file())

    def test_portprep_empty_dossier_fails_start(self):
        os.environ["FAKE_PORTPREP"] = "empty"
        rc = agent_task.cmd_start(self._args())
        self.assertEqual(rc, 2)
        self.assertFalse(agent_task._receipt_path().is_file())

    def test_multiple_addresses_record_per_address_portprep_steps(self):
        os.environ["FAKE_PORTPREP"] = "ok"
        other = "0x0055ab40"
        rc = agent_task.cmd_start(self._args(addresses=[self.ADDR, other]))
        self.assertEqual(rc, 0)
        calls = self._calls()
        self.assertIn(f"ghidra portprep {self.ADDR}", calls)
        self.assertIn(f"ghidra portprep {other}", calls)
        receipt = json.loads(agent_task._receipt_path().read_text())
        for addr in (self.ADDR, other):
            self.assertIn(f"portprep {addr}", receipt["steps"])
            self.assertTrue(receipt["targets"][addr]["portprep"])

    def test_claim_failure_is_a_hard_stop_without_override(self):
        os.environ["FAKE_PORTPREP"] = "ok"
        # Occupy the claim ref from a rival so the fresh CAS claim must fail.
        rival = agent_task.REPO_ROOT
        self.assertTrue(agent_task._push_claim(self.ADDR, "rival-branch", ""))
        # Make the claim look expired so cmd_start reaches the push path
        # (an unexpired rival claim is refused earlier, which is also correct).
        sha = _git(rival, "ls-remote", "origin",
                   agent_task.CLAIM_REF_PREFIX + self.ADDR).stdout.split()[0]
        # Re-claim with an already-expired TTL by rewriting the commit message.
        payload = json.dumps({
            "address": self.ADDR, "branch": "rival-branch",
            "created_utc": "2000-01-01T00:00:00Z",
            "expires_utc": "2000-01-02T00:00:00Z",
        })
        expired = _git(rival, "commit-tree", agent_task.EMPTY_TREE,
                       "-m", payload).stdout.strip()
        _git(rival, "push", f"--force-with-lease={agent_task.CLAIM_REF_PREFIX}{self.ADDR}:{sha}",
             "origin", f"{expired}:{agent_task.CLAIM_REF_PREFIX}{self.ADDR}")

        # Simulate the takeover race: between inspection and push, the rival
        # refreshes. cmd_start's expectation goes stale -> hard stop.
        original_push = agent_task._push_claim

        def racing_push(addr, branch, expected_sha=""):
            original_push(addr, "rival-branch", expected_sha)  # rival wins first
            return original_push(addr, branch, expected_sha)

        agent_task._push_claim = racing_push
        try:
            rc = agent_task.cmd_start(self._args(no_claim=False))
        finally:
            agent_task._push_claim = original_push
        self.assertEqual(rc, 2)
        self.assertFalse(agent_task._receipt_path().is_file())


class AgentCheckGeneratedIntegrityTests(unittest.TestCase):
    """agent-check must run the generated-integrity gate on precommit's own base.

    imperialism-decomp-uerj: a green receipt used to be followed by a pre-commit
    failure, because only `just precommit` ran the gate.
    """

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="agent-task-check-")
        tmp = Path(self._tmp)
        self.origin, self.work = _init_repos(tmp)
        bin_dir = tmp / "bin"
        bin_dir.mkdir()
        just = bin_dir / "just"
        just.write_text(FAKE_JUST)
        just.chmod(0o755)
        self.calls_log = tmp / "calls.log"
        self._saved_env = dict(os.environ)
        os.environ["PATH"] = f"{bin_dir}{os.pathsep}{os.environ['PATH']}"
        os.environ["FAKE_JUST_LOG"] = str(self.calls_log)
        os.environ.pop("PRECOMMIT_BASE_REF", None)
        self._saved_root = agent_task.REPO_ROOT
        self._saved_tasks_dir = agent_task.TASKS_DIR
        self._saved_legacy = agent_task.LEGACY_TASK_JSON
        agent_task.REPO_ROOT = self.work
        agent_task.TASKS_DIR = self.work / "build-msvc500" / "agent-tasks"
        agent_task.LEGACY_TASK_JSON = self.work / "build-msvc500" / "agent-task.json"
        # One committed change so cmd_check has a diff to verify. No `// FUNCTION:`
        # marker: score extraction would then need a real reccmp report, which is not
        # what these tests are about.
        (self.work / "src" / "TFoo.cpp").write_text("int TFoo::Compute() { return 1; }\n")
        _git(self.work, "add", "-A")
        _git(self.work, "commit", "-m", "work")

    def tearDown(self):
        agent_task.REPO_ROOT = self._saved_root
        agent_task.TASKS_DIR = self._saved_tasks_dir
        agent_task.LEGACY_TASK_JSON = self._saved_legacy
        os.environ.clear()
        os.environ.update(self._saved_env)
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _calls(self) -> list[str]:
        if not self.calls_log.is_file():
            return []
        return self.calls_log.read_text().splitlines()

    def test_check_runs_integrity_gate_on_the_merge_base_and_records_it(self):
        rc = agent_task.cmd_check(Namespace(max_triage=1))
        self.assertEqual(rc, 0)
        expected_base = _git(self.work, "merge-base", "HEAD", "origin/main").stdout.strip()
        self.assertIn(
            f"generated-integrity-gate --base {expected_base}", self._calls()
        )
        receipt = json.loads(agent_task._receipt_path().read_text())
        integrity = receipt["check"]["generated_integrity"]
        self.assertEqual(integrity["base_ref"], "origin/main")
        self.assertEqual(integrity["base"], expected_base)
        self.assertTrue(integrity["ok"])

    def test_integrity_failure_fails_the_check(self):
        os.environ["FAKE_INTEGRITY"] = "fail"
        rc = agent_task.cmd_check(Namespace(max_triage=1))
        self.assertEqual(rc, 1)
        receipt = json.loads(agent_task._receipt_path().read_text())
        self.assertIn("generated-integrity", receipt["check"]["failures"])
        self.assertFalse(receipt["check"]["generated_integrity"]["ok"])

    def test_edited_existing_body_enters_the_touched_set_with_a_reason(self):
        """imperialism-decomp-3gn8: the marker line is unchanged, the body is not."""
        source = self.work / "src" / "TBar.cpp"
        source.write_text(
            "// FUNCTION: IMPERIALISM 0x00500000\n"
            "void TBar::A() {\n"
            "  int x = 1;\n"
            "}\n"
        )
        _git(self.work, "add", "-A")
        _git(self.work, "commit", "-m", "add body")
        source.write_text(
            "// FUNCTION: IMPERIALISM 0x00500000\n"
            "void TBar::A() {\n"
            "  int x = 2;\n"
            "}\n"
        )
        agent_task.cmd_check(Namespace(max_triage=1))
        receipt = json.loads(agent_task._receipt_path().read_text())
        affected = receipt["check"]["affected_functions"]
        self.assertIn("0x00500000", affected)
        self.assertIn("body_edited", affected["0x00500000"]["reasons"])

    def test_explicit_base_ref_is_honoured_like_precommit(self):
        os.environ["PRECOMMIT_BASE_REF"] = "main"
        agent_task.cmd_check(Namespace(max_triage=1))
        receipt = json.loads(agent_task._receipt_path().read_text())
        self.assertEqual(receipt["check"]["generated_integrity"]["base_ref"], "main")


class HunkToMarkerMappingTests(unittest.TestCase):
    """imperialism-decomp-3gn8: an edited existing body must enter the touched set."""

    SOURCE = (
        '#include "game/TFoo.h"\n'
        "\n"
        "// FUNCTION: IMPERIALISM 0x00500000\n"
        "void TFoo::A() {\n"
        "  int x = 1;\n"
        "}\n"
        "\n"
        "// SYNTHETIC: IMPERIALISM 0x00500100\n"
        "void TFoo::B() {\n"
        "  int y = 2;\n"
        "}\n"
    )

    def test_marker_lines_are_located_and_normalized(self):
        self.assertEqual(
            agent_task.marker_lines(self.SOURCE),
            [(3, "0x00500000"), (8, "0x00500100")],
        )

    def test_hunk_headers_expand_to_new_file_line_numbers(self):
        diff = "@@ -5,0 +5,2 @@\n@@ -10,1 +12,0 @@\n"
        self.assertEqual(agent_task.changed_line_numbers(diff), {5, 6, 12})

    def test_changed_body_line_maps_to_its_enclosing_marker(self):
        self.assertEqual(
            agent_task.addresses_for_changed_lines(self.SOURCE, {5}), {"0x00500000"}
        )
        self.assertEqual(
            agent_task.addresses_for_changed_lines(self.SOURCE, {10}), {"0x00500100"}
        )

    def test_lines_before_the_first_marker_touch_no_address(self):
        self.assertEqual(agent_task.addresses_for_changed_lines(self.SOURCE, {1}), set())

    def test_no_markers_or_no_changes_is_empty(self):
        self.assertEqual(agent_task.addresses_for_changed_lines("int main() {}\n", {1}), set())
        self.assertEqual(agent_task.addresses_for_changed_lines(self.SOURCE, set()), set())


class AgentFinishVerificationTests(unittest.TestCase):
    """imperialism-decomp-j201: a PR body is a claim about verification."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="agent-task-finish-")
        tmp = Path(self._tmp)
        self.origin, self.work = _init_repos(tmp)
        self._saved_root = agent_task.REPO_ROOT
        self._saved_tasks_dir = agent_task.TASKS_DIR
        self._saved_legacy = agent_task.LEGACY_TASK_JSON
        agent_task.REPO_ROOT = self.work
        agent_task.TASKS_DIR = self.work / "build-msvc500" / "agent-tasks"
        agent_task.LEGACY_TASK_JSON = self.work / "build-msvc500" / "agent-task.json"

    def tearDown(self):
        agent_task.REPO_ROOT = self._saved_root
        agent_task.TASKS_DIR = self._saved_tasks_dir
        agent_task.LEGACY_TASK_JSON = self._saved_legacy
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _green_receipt(self) -> dict:
        base = _git(self.work, "merge-base", "HEAD", "origin/main").stdout.strip()
        task = {
            "branch": "task-branch",
            "mode": "port",
            "base_commit": base,
            "targets": {},
            "claimed": [],
            "check": {
                "checked_utc": "2026-01-01T00:00:00Z",
                "tree": agent_task._worktree_fingerprint(base),
                "paths": ["src/TFoo.cpp"],
                "scores": {},
                "failures": [],
                "results": {"gates": {"cmd": "just gates", "ok": True, "log": "logs/00-gates.log"}},
            },
        }
        agent_task._save_task(task)
        return task

    def test_receipts_are_per_branch(self):
        self._green_receipt()
        expected = agent_task.TASKS_DIR / "task-branch" / "receipt.json"
        self.assertTrue(expected.is_file())
        self.assertEqual(agent_task._receipt_path("task-branch"), expected)
        # A second branch gets its own directory rather than overwriting the first.
        self.assertNotEqual(
            agent_task._receipt_path("other/branch"), agent_task._receipt_path("task-branch")
        )

    def test_finish_renders_when_the_tree_still_matches(self):
        self._green_receipt()
        rc = agent_task.cmd_finish(Namespace(allow_unverified_draft=False))
        self.assertEqual(rc, 0)
        body = (agent_task.TASKS_DIR / "task-branch" / "pr-body.md").read_text()
        self.assertNotIn("UNVERIFIED DRAFT", body)
        for heading in ("## Summary", "## Verification", "## Score and stub deltas",
                        "## Runtime tests", "## Beads", "## Unresolved risks"):
            self.assertIn(heading, body)

    def test_finish_refuses_a_changed_worktree(self):
        self._green_receipt()
        (self.work / "src" / "New.cpp").write_text("int f() { return 0; }\n")
        rc = agent_task.cmd_finish(Namespace(allow_unverified_draft=False))
        self.assertEqual(rc, 2)

    def test_finish_refuses_a_moved_head(self):
        self._green_receipt()
        (self.work / "src" / "New.cpp").write_text("int f() { return 0; }\n")
        _git(self.work, "add", "-A")
        _git(self.work, "commit", "-m", "later work")
        self.assertEqual(agent_task.cmd_finish(Namespace(allow_unverified_draft=False)), 2)

    def test_finish_refuses_failed_checks(self):
        task = self._green_receipt()
        task["check"]["failures"] = ["gates"]
        agent_task._save_task(task)
        self.assertEqual(agent_task.cmd_finish(Namespace(allow_unverified_draft=False)), 2)

    def test_finish_refuses_when_agent_check_never_ran(self):
        task = self._green_receipt()
        del task["check"]
        agent_task._save_task(task)
        self.assertEqual(agent_task.cmd_finish(Namespace(allow_unverified_draft=False)), 2)

    def test_draft_flag_renders_a_visibly_marked_body(self):
        task = self._green_receipt()
        task["check"]["failures"] = ["gates"]
        agent_task._save_task(task)
        rc = agent_task.cmd_finish(Namespace(allow_unverified_draft=True))
        self.assertEqual(rc, 0)
        body = (agent_task.TASKS_DIR / "task-branch" / "pr-body.md").read_text()
        self.assertIn("UNVERIFIED DRAFT", body)
        self.assertIn("agent-check failed: gates", body)


class StepLoggingTests(unittest.TestCase):
    """imperialism-decomp-j201: keep full command output, not a 12-line tail."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="agent-task-log-")
        tmp = Path(self._tmp)
        self.origin, self.work = _init_repos(tmp)
        self._saved_root = agent_task.REPO_ROOT
        self._saved_tasks_dir = agent_task.TASKS_DIR
        agent_task.REPO_ROOT = self.work
        agent_task.TASKS_DIR = self.work / "build-msvc500" / "agent-tasks"

    def tearDown(self):
        agent_task.REPO_ROOT = self._saved_root
        agent_task.TASKS_DIR = self._saved_tasks_dir
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_full_output_is_kept_on_disk_with_a_structured_summary(self):
        results: dict = {}
        script = "for i in $(seq 1 50); do echo line-$i; done; echo 'error: boom' >&2; exit 3"
        agent_task._step("noisy", ["bash", "-c", script], results, tolerate=True)
        entry = results["noisy"]
        self.assertEqual(entry["returncode"], 3)
        self.assertFalse(entry["ok"])
        self.assertIn("boom", entry["first_error"])
        log = agent_task.REPO_ROOT / entry["log"]
        self.assertTrue(log.is_file())
        text = log.read_text()
        self.assertIn("line-1", text)   # the tail-only receipt used to lose this
        self.assertIn("line-50", text)


if __name__ == "__main__":
    unittest.main()
