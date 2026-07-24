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
        self._saved_task_json = agent_task.TASK_JSON
        agent_task.REPO_ROOT = self.work
        agent_task.TASK_JSON = self.work / "build-msvc500" / "agent-task.json"

    def tearDown(self):
        agent_task.REPO_ROOT = self._saved_root
        agent_task.TASK_JSON = self._saved_task_json
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
        receipt = json.loads(agent_task.TASK_JSON.read_text())
        self.assertIn("dossier for", receipt["targets"][self.ADDR]["portprep"])
        self.assertIn(f"portprep {self.ADDR}", receipt["steps"])

    def test_portprep_failure_fails_start_without_ready_receipt(self):
        os.environ["FAKE_PORTPREP"] = "fail"
        rc = agent_task.cmd_start(self._args())
        self.assertEqual(rc, 2)
        self.assertFalse(agent_task.TASK_JSON.is_file())

    def test_portprep_empty_dossier_fails_start(self):
        os.environ["FAKE_PORTPREP"] = "empty"
        rc = agent_task.cmd_start(self._args())
        self.assertEqual(rc, 2)
        self.assertFalse(agent_task.TASK_JSON.is_file())

    def test_multiple_addresses_record_per_address_portprep_steps(self):
        os.environ["FAKE_PORTPREP"] = "ok"
        other = "0x0055ab40"
        rc = agent_task.cmd_start(self._args(addresses=[self.ADDR, other]))
        self.assertEqual(rc, 0)
        calls = self._calls()
        self.assertIn(f"ghidra portprep {self.ADDR}", calls)
        self.assertIn(f"ghidra portprep {other}", calls)
        receipt = json.loads(agent_task.TASK_JSON.read_text())
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
        self.assertFalse(agent_task.TASK_JSON.is_file())


if __name__ == "__main__":
    unittest.main()
