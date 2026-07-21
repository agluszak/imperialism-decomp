#!/usr/bin/env python3
"""Stateful agent workflow entrypoints: start / check / finish.

The only documented way to begin, verify, and wrap up a porting task. The point is
that an agent should never have to remember the correct process — these commands
execute it:

  just agent-start port 0x5503a0     # investigate + claim-check + write task receipt
  just agent-check                   # diff-aware verification (the right steps, in order)
  just agent-finish                  # machine-derived summary / PR body from the receipt

`agent-start` refuses stale bases and already-implemented targets, then runs
tooling-check, func-status, ghidra-portprep, the initial compare, and (for
library-shaped targets) library-identify, writing everything into
build-msvc500/agent-task.json.

`agent-check` inspects the actual git diff and derives the workflow from it:
build inputs (source index + stubs) are always regenerated (cheap, no committed
churn); generated/config files edited without marker changes -> hard error; touched
C++ -> format-check; then build, detect, batch compare of every touched address,
triage for below-100% functions, gates, tests, stats.

`agent-finish` renders the receipt + diff into a summary suitable for a PR body.
The receipt is guidance for the agent and reviewers — CI recomputes the checks
itself and trusts only its own run.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TASK_JSON = REPO_ROOT / "build-msvc500" / "agent-task.json"
PR_BODY_MD = REPO_ROOT / "build-msvc500" / "pr-body.md"

# Claims registry: one lightweight commit ref per claimed address on the shared
# remote. `refs/agent-claims/0x00XXXXXX` points at a parentless empty-tree commit
# whose message is the claim JSON (owner branch, expiry). Push is atomic per ref,
# so two agents racing for the same address cannot both win. Remotes that refuse
# custom refs degrade to a warning — the registry is best-effort coordination,
# not a lock the workflow depends on.
CLAIM_REF_PREFIX = "refs/agent-claims/"
EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
CLAIM_TTL_HOURS = 24

GENERATED_PREFIXES = (
    "src/autogen/",
    "src/ghidra_autogen/",
    "include/ghidra_autogen/",
)  # legacy paths: kept so a stale checkout's leftovers still trip the integrity check
MANUAL_CPP_PREFIXES = ("src/", "include/")
UI_CODEGEN_INPUTS = frozenset(
    (
        "config/ui_factory_codegen.yml",
        "config/ui_factory_windows_views.yml",
        "tools/ui_codegen.py",
        "tools/workflow/macos_resource_evidence.py",
        "vendor/macos_codewarrior/evidence/resources/ui_views.json",
        "vendor/macos_codewarrior/evidence/resources/strings.csv",
    )
)
MARKER_RE = re.compile(
    r"^[+-].*//\s*(FUNCTION|SYNTHETIC|TEMPLATE|LIBRARY|GLOBAL|VTABLE|NOOP):",
)
SCORE_RE = re.compile(r"(0x[0-9a-fA-F]{6,8})\s+(\d{1,3}\.\d{2})%")


def _run(cmd: list[str], *, check: bool = False, env: dict | None = None) -> subprocess.CompletedProcess:
    merged_env = dict(os.environ)
    merged_env.setdefault("WINEDEBUG", "-all")
    if env:
        merged_env.update(env)
    return subprocess.run(
        cmd, cwd=REPO_ROOT, capture_output=True, text=True, check=check, env=merged_env
    )


def _git(*args: str) -> str:
    return _run(["git", *args]).stdout.strip()


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _norm_addr(raw: str) -> str:
    return f"0x{int(raw, 16):08x}"


def _load_task() -> dict:
    if TASK_JSON.is_file():
        return json.loads(TASK_JSON.read_text(encoding="utf-8"))
    return {}


def _save_task(task: dict) -> None:
    TASK_JSON.parent.mkdir(parents=True, exist_ok=True)
    TASK_JSON.write_text(json.dumps(task, indent=2) + "\n", encoding="utf-8")
    print(f"[agent-task] receipt written: {TASK_JSON.relative_to(REPO_ROOT)}")


def _merge_base() -> str:
    return _git("merge-base", "HEAD", "origin/main")


def _parse_scores(text: str) -> dict[str, float]:
    return {m.group(1).lower(): float(m.group(2)) for m in SCORE_RE.finditer(text)}


def _ownership_row(addr: str, source: str = "") -> dict:
    """Marker-derived ownership for addr (optionally from a git revision's tree).

    Source markers are the only claim authority; for a revision, `git grep` finds
    the marker without checking anything out.
    """
    addr_int = int(addr, 16)
    if source:
        pattern = (r"//[[:space:]]*\(FUNCTION\|STUB\|TEMPLATE\|SYNTHETIC\|LIBRARY\):"
                   r"[[:space:]]*IMPERIALISM[[:space:]]\+\(0x\)\?0*"
                   + format(addr_int, "x"))
        out = _run(["git", "grep", "-i", "-l", "-e", pattern, source, "--",
                    "src", "include"]).stdout.strip()
        if not out:
            return {}
        first = out.splitlines()[0]
        path = first.split(":", 1)[1] if ":" in first else first
        return {"address": format(addr_int, "x"), "target_cpp": path,
                "ownership": "manual", "note": f"marker in {source}"}
    from tools.source_model import ownership_kind, ownership_view

    claim = ownership_view(REPO_ROOT).get(addr_int)
    if claim is None:
        return {}
    return {"address": format(addr_int, "x"), "target_cpp": claim.file,
            "ownership": ownership_kind(claim.kind, claim.origin),
            "note": f"marker {claim.kind} at {claim.file}:{claim.line}"}


# ---------------------------------------------------------------------------
# claims registry (refs/agent-claims/<addr> on origin)
# ---------------------------------------------------------------------------

def _fetch_claims() -> dict[str, str]:
    """Map addr -> remote commit sha for every claim ref on origin.

    Returns {} (with a note) when the remote is unreachable or refuses the
    namespace — the registry is best-effort.
    """
    proc = _run(["git", "ls-remote", "origin", CLAIM_REF_PREFIX + "*"])
    if proc.returncode != 0:
        print("[claims] note: remote unreachable — continuing without the claims registry")
        return {}
    claims: dict[str, str] = {}
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].startswith(CLAIM_REF_PREFIX):
            claims[parts[1][len(CLAIM_REF_PREFIX):]] = parts[0]
    return claims


def _read_claim(addr: str, sha: str) -> dict:
    """Fetch + parse the claim JSON stored in the claim commit's message."""
    ref = CLAIM_REF_PREFIX + addr
    if _run(["git", "cat-file", "-e", sha]).returncode != 0:
        if _run(["git", "fetch", "origin", f"+{ref}:{ref}", "--quiet"]).returncode != 0:
            return {}
    body = _run(["git", "log", "-1", "--format=%B", sha]).stdout.strip()
    try:
        return json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return {"raw": body}


def _claim_expired(claim: dict) -> bool:
    expires = claim.get("expires_utc", "")
    try:
        return datetime.datetime.strptime(expires, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=datetime.timezone.utc) < datetime.datetime.now(datetime.timezone.utc)
    except ValueError:
        return True  # unparsable claims don't block anyone forever


def _push_claim(addr: str, branch: str) -> bool:
    expires = (datetime.datetime.now(datetime.timezone.utc)
               + datetime.timedelta(hours=CLAIM_TTL_HOURS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    payload = json.dumps({
        "address": addr,
        "branch": branch,
        "created_utc": _now(),
        "expires_utc": expires,
    }, indent=2)
    commit = _run(["git", "commit-tree", EMPTY_TREE, "-m", payload])
    if commit.returncode != 0:
        return False
    sha = commit.stdout.strip()
    # Non-forced push: if someone claimed between our ls-remote and now, this
    # fails and the loser sees the refusal on rerun.
    push = _run(["git", "push", "origin", f"{sha}:{CLAIM_REF_PREFIX}{addr}"])
    if push.returncode != 0:
        print(f"[claims] note: could not push claim for {addr} "
              "(remote refused or raced) — continuing unclaimed")
        return False
    print(f"[claims] claimed {addr} for branch {branch!r} (expires {expires})")
    return True


def _drop_claim(addr: str) -> bool:
    proc = _run(["git", "push", "origin", "--delete", CLAIM_REF_PREFIX + addr])
    if proc.returncode == 0:
        print(f"[claims] released {addr}")
        return True
    print(f"[claims] note: could not delete claim for {addr}: "
          + (proc.stderr.strip().splitlines() or ["unknown error"])[-1])
    return False


def _step(name: str, cmd: list[str], results: dict, *, tolerate: bool = False) -> subprocess.CompletedProcess:
    print(f"[agent-task] {name}: {' '.join(cmd)}")
    proc = _run(cmd)
    ok = proc.returncode == 0
    results[name] = {
        "cmd": " ".join(cmd),
        "ok": ok,
        "tail": "\n".join((proc.stdout + proc.stderr).splitlines()[-12:]),
    }
    if not ok and not tolerate:
        print(f"[agent-task] FAILED: {name} (exit {proc.returncode})")
        print(results[name]["tail"])
    return proc


# ---------------------------------------------------------------------------
# start
# ---------------------------------------------------------------------------

def cmd_start(args: argparse.Namespace) -> int:
    addrs = [_norm_addr(a) for a in args.addresses]
    problems: list[str] = []

    # 1. Repository / worktree state.
    branch = _git("rev-parse", "--abbrev-ref", "HEAD")
    dirty = [l for l in _git("status", "--porcelain").splitlines() if l.strip()]
    if branch in ("main", "master"):
        problems.append(
            f"on branch {branch!r} — create a work branch first (never develop on main)"
        )
    if dirty:
        print(f"[agent-start] note: {len(dirty)} dirty path(s) in the worktree "
              "(may belong to a concurrent agent — never revert them; Hard Rule 13)")

    # 2. Stale base refusal.
    _run(["git", "fetch", "origin", "main", "--quiet"])
    base = _merge_base()
    behind = _git("rev-list", "--count", f"{base}..origin/main")
    if behind and int(behind) > 0:
        msg = (f"base is {behind} commit(s) behind origin/main — merge origin/main "
               "into this branch first (see docs/workflows.md)")
        if args.allow_stale_base:
            print(f"[agent-start] WARNING (allowed): {msg}")
        else:
            problems.append(msg + "; override with --allow-stale-base only if you "
                            "are deliberately working from an older base")

    # 3. Target claim / already-implemented refusal.
    targets: dict[str, dict] = {}
    for addr in addrs:
        local_own = _ownership_row(addr)
        main_own = _ownership_row(addr, source="origin/main")
        entry: dict = {"ownership": local_own, "ownership_on_origin_main": main_own}
        owner_file = (local_own.get("target_cpp") or "").strip()
        main_owner_file = (main_own.get("target_cpp") or "").strip()
        manual_here = owner_file and "autogen" not in owner_file
        manual_on_main = main_owner_file and "autogen" not in main_owner_file
        if args.mode == "port" and (manual_here or manual_on_main):
            where = owner_file or main_owner_file
            if args.takeover:
                print(f"[agent-start] WARNING (takeover): {addr} already owned by {where}")
            else:
                problems.append(
                    f"{addr} is already manually implemented ({where}) — this is a "
                    "re-port/fix, not a port; rerun with mode 'fix' or --takeover"
                )
        if main_owner_file != owner_file:
            entry["ownership_drift"] = (
                f"origin/main owner {main_owner_file!r} != local {owner_file!r} — "
                "another agent may have claimed/moved this target after your base"
            )
            print(f"[agent-start] WARNING: {entry['ownership_drift']}")
        targets[addr] = entry

    # 3b. Claims registry: refuse addresses claimed by another live branch.
    remote_claims = _fetch_claims()
    for addr in addrs:
        sha = remote_claims.get(addr)
        if not sha:
            continue
        claim = _read_claim(addr, sha)
        holder = claim.get("branch", "<unknown>")
        if holder == branch:
            print(f"[claims] {addr} already claimed by this branch — refreshing")
        elif _claim_expired(claim):
            print(f"[claims] {addr} has an EXPIRED claim from {holder!r} — taking over")
        elif args.steal_claim:
            print(f"[agent-start] WARNING (steal-claim): {addr} is claimed by "
                  f"{holder!r} until {claim.get('expires_utc', '?')}")
        else:
            problems.append(
                f"{addr} is claimed by branch {holder!r} until "
                f"{claim.get('expires_utc', '?')} — pick another target from "
                "docs/porting_queue.md, or override with --steal-claim only if "
                "that branch is known dead"
            )

    if problems:
        print("[agent-start] REFUSED:")
        for p in problems:
            print(f"  - {p}")
        return 2

    claimed = [a for a in addrs if not args.no_claim and _push_claim(a, branch)]

    results: dict = {}

    # 4. tooling-check.
    if _step("tooling-check", ["just", "tooling-check"], results).returncode != 0:
        return 2

    # 5. func-status.
    proc = _step("func-status", ["just", "func-status", *addrs], results, tolerate=True)
    func_status_text = proc.stdout

    # 6. ghidra-portprep (the front door of every port — not optional).
    portprep: dict[str, str] = {}
    stub_callees: dict[str, list[str]] = {}
    if args.no_portprep:
        print("[agent-start] portprep skipped by flag — you are working blind; "
              "run `just ghidra-portprep ADDR` before editing")
    elif not os.environ.get("GHIDRA_INSTALL_DIR"):
        print("[agent-start] REFUSED: GHIDRA_INSTALL_DIR is not set, so "
              "ghidra-portprep cannot run. Export it (see AGENTS.md environment "
              "notes) or pass --no-portprep to explicitly accept working blind.")
        return 2
    else:
        for addr in addrs:
            proc = _step(f"portprep {addr}", ["just", "ghidra-portprep", addr],
                         results, tolerate=True)
            portprep[addr] = proc.stdout
            stub_callees[addr] = sorted({
                line.strip()
                for line in proc.stdout.splitlines()
                if "generated/stubs" in line
            })

    # 7. Initial compare (score signal — nonzero exit for <100% is expected).
    baseline_scores: dict[str, float] = {}
    if not args.no_compare:
        proc = _step("initial-compare", ["just", "compare", *addrs], results,
                     tolerate=True)
        baseline_scores = _parse_scores(proc.stdout)

    # 8. library-identify for library-range / CRT-shaped targets.
    for addr in addrs:
        provenance = (targets[addr]["ownership"].get("provenance") or "").lower()
        if int(addr, 16) >= 0x5F0000 or "library" in provenance or "rtti" in provenance:
            _step(f"library-identify {addr}", ["just", "library-identify", addr],
                  results, tolerate=True)

    # 9. Receipt.
    for addr in addrs:
        targets[addr].update({
            "baseline_score": baseline_scores.get(addr),
            "stub_owned_callees": stub_callees.get(addr, []),
            "portprep": portprep.get(addr, ""),
        })
    task = {
        "created_utc": _now(),
        "mode": args.mode,
        "branch": branch,
        "base_commit": base,
        "claimed": claimed,
        "targets": targets,
        "func_status": func_status_text,
        "steps": results,
        "active_rules": [
            "AGENTS.md Hard Rules + guardrails (gate-chasing, calling-convention, type-modeling)",
            "load the topical skills matching the target's traits (AGENTS.md routing table)",
            "no function is too complex to port — no TODO/deferred bodies",
            "ILT thunks are never modeled — resolve to the real target",
        ],
        "allowed_generated_mutations": [
            "config/*_baseline.* via their `just *-update` targets only (policy baselines need ALLOW_POLICY_BASELINE_UPDATE=1)",
        ],
    }
    _save_task(task)
    print("[agent-start] ready. Next: port the target, then `just agent-check`.")
    return 0


# ---------------------------------------------------------------------------
# check
# ---------------------------------------------------------------------------

def _diff_paths(base: str) -> list[str]:
    committed = _git("diff", "--name-only", base).splitlines()
    status = [l[3:].strip() for l in _git("status", "--porcelain").splitlines() if l.strip()]
    return sorted({p for p in committed + status if p})


def cmd_check(args: argparse.Namespace) -> int:
    task = _load_task()
    base = task.get("base_commit") or _merge_base()
    paths = _diff_paths(base)
    if not paths:
        print("[agent-check] no changes vs base — nothing to verify")
        return 0
    print(f"[agent-check] {len(paths)} changed path(s) vs {base[:10]}")

    results: dict = {}
    failures: list[str] = []

    # Generated build inputs are disposable — always regenerate (cheap, no
    # committed churn; `just generate` also rejects stale legacy generated trees).
    diff_text = _git("diff", base, "--", "src", "include") + "\n" + _git("diff", "--", "src", "include")
    if _step("generate", ["just", "generate"], results).returncode != 0:
        failures.append("generate")

    # Format check on touched manual C++.
    cpp = [p for p in paths
           if p.endswith((".cpp", ".h"))
           and p.startswith(MANUAL_CPP_PREFIXES)
           and not p.startswith(GENERATED_PREFIXES)
           and (REPO_ROOT / p).is_file()]
    if cpp:
        if _step("format-check", ["just", "format-check", *cpp], results,
                 tolerate=True).returncode != 0:
            failures.append(f"format-check (fix: just format {' '.join(cpp)})")

    # Build + detect.
    if _step("build", ["just", "build"], results).returncode != 0:
        _save_task({**task, "check": {"results": results, "failures": ["build"]}})
        return 2
    if _step("detect", ["just", "detect"], results).returncode != 0:
        failures.append("detect")

    # Batch compare of every touched address.
    addrs = set(task.get("targets", {}))
    if any(
        path in UI_CODEGEN_INPUTS
        for path in paths
    ):
        from tools.ui_codegen import load_recipes

        addrs.update(f"0x{recipe.address:08x}" for recipe in load_recipes(REPO_ROOT))
    for line in diff_text.splitlines():
        if line.startswith("+"):
            m = re.search(r"//\s*(?:FUNCTION|SYNTHETIC|TEMPLATE):\s*\w+\s+(0x[0-9a-fA-F]+)", line)
            if m:
                addrs.add(_norm_addr(m.group(1)))
    scores: dict[str, float] = {}
    if addrs:
        proc = _step("compare-touched", ["just", "compare", *sorted(addrs)], results,
                     tolerate=True)
        scores = _parse_scores(proc.stdout)
        below = [a for a, s in scores.items() if s < 100.0]
        triage_addrs = sorted(below)[: args.max_triage]
        if triage_addrs:
            _step(
                "triage-touched",
                ["just", "triage", *triage_addrs],
                results,
                tolerate=True,
            )

    # Gates, tests, stats.
    if _step("gates", ["just", "gates"], results).returncode != 0:
        failures.append("gates")
    if _step("test", ["just", "test"], results).returncode != 0:
        failures.append("test")
    _step("stats", ["just", "stats"], results, tolerate=True)

    task.setdefault("check", {})
    task["check"] = {
        "checked_utc": _now(),
        "paths": paths,
        "markers_changed": any(MARKER_RE.match(l2) for l2 in diff_text.splitlines()),
        "scores": scores,
        "failures": failures,
        "results": {k: {kk: vv for kk, vv in v.items() if kk != "tail"} | (
            {"tail": v["tail"]} if not v["ok"] else {})
            for k, v in results.items()},
    }
    _save_task(task)

    if failures:
        print(f"[agent-check] FAILED steps: {', '.join(failures)} — fix forward "
              "(never revert real structure to pass a gate; see the gate-chasing "
              "guardrail) and rerun `just agent-check`.")
        return 1
    print("[agent-check] all checks green. Next: `just agent-finish`, review, commit.")
    return 0


# ---------------------------------------------------------------------------
# finish
# ---------------------------------------------------------------------------

def _score_label(value) -> str:
    return f"{value:.2f}%" if isinstance(value, (int, float)) else "stub"


def _pr_title(task: dict) -> str:
    """Generated PR title: mode + targets + score outcome. Never model names."""
    mode = task.get("mode", "port")
    check = task.get("check", {})
    parts = []
    for addr, t in task.get("targets", {}).items():
        before = _score_label(t.get("baseline_score"))
        after = check.get("scores", {}).get(addr)
        outcome = f"{before} -> {_score_label(after)}" if after is not None else before
        parts.append(f"{addr} ({outcome})")
    if not parts:
        return f"{mode.capitalize()}: workflow/infrastructure change"
    return f"{mode.capitalize()} {', '.join(parts[:3])}" + (
        f" +{len(parts) - 3} more" if len(parts) > 3 else "")


def cmd_finish(args: argparse.Namespace) -> int:
    task = _load_task()
    if not task:
        print("[agent-finish] no receipt (build-msvc500/agent-task.json) — run "
              "`just agent-start` / `just agent-check` first", file=sys.stderr)
        return 2
    base = task.get("base_commit") or _merge_base()
    check = task.get("check", {})
    diffstat = _git("diff", "--stat", base)

    lines = ["## Summary", ""]
    for addr, t in task.get("targets", {}).items():
        before = t.get("baseline_score")
        after = check.get("scores", {}).get(addr)
        b = f"{before:.2f}%" if isinstance(before, (int, float)) else "stub/unported"
        a = f"{after:.2f}%" if isinstance(after, (int, float)) else "?"
        lines.append(f"- `{addr}` ({task.get('mode', 'port')}): {b} -> {a}")
    extra = {a: s for a, s in check.get("scores", {}).items()
             if a not in task.get("targets", {})}
    for addr, s in sorted(extra.items()):
        lines.append(f"- `{addr}` (touched): -> {s:.2f}%")
    lines += ["", "## Verification", ""]
    if check:
        failures = check.get("failures", [])
        lines.append(f"- agent-check: {'GREEN' if not failures else 'FAILED: ' + ', '.join(failures)}")
        for name, r in check.get("results", {}).items():
            lines.append(f"- {name}: {'ok' if r.get('ok') else 'FAILED'}")
    else:
        lines.append("- agent-check was NOT run — run `just agent-check` before finishing")
    lines += ["", "## Unresolved risks", ""]
    below = [a for a, s in check.get("scores", {}).items() if s < 100.0]
    if below:
        lines.append("- Below-100% functions (see triage output in the receipt): "
                     + ", ".join(f"`{a}`" for a in sorted(below)))
    else:
        lines.append("- none recorded")
    lines += ["", "## Diffstat", "", "```", diffstat or "(no diff)", "```", "",
              "_Receipt: build-msvc500/agent-task.json — guidance only; CI recomputes",
              "all checks itself._"]
    body = "\n".join(lines)
    PR_BODY_MD.parent.mkdir(parents=True, exist_ok=True)
    PR_BODY_MD.write_text(body + "\n", encoding="utf-8")
    print(f"PR title: {_pr_title(task)}")
    print(f"PR body written to {PR_BODY_MD.relative_to(REPO_ROOT)}")
    print()
    print(body)
    if task.get("claimed"):
        print("\n[agent-finish] claims still held: "
              + ", ".join(task["claimed"])
              + " — run `just agent-release` after the work lands (or expires in "
              f"{CLAIM_TTL_HOURS}h)")
    return 0


# ---------------------------------------------------------------------------
# release
# ---------------------------------------------------------------------------

def cmd_release(args: argparse.Namespace) -> int:
    task = _load_task()
    addrs = [_norm_addr(a) for a in args.addresses] or sorted(
        set(task.get("claimed", [])) | set(task.get("targets", {})))
    if not addrs:
        print("[agent-release] nothing to release — no receipt targets and no "
              "addresses given")
        return 0
    branch = _git("rev-parse", "--abbrev-ref", "HEAD")
    remote_claims = _fetch_claims()
    rc = 0
    for addr in addrs:
        sha = remote_claims.get(addr)
        if not sha:
            print(f"[agent-release] {addr}: no claim on origin — nothing to do")
            continue
        holder = _read_claim(addr, sha).get("branch", "<unknown>")
        if holder != branch and not args.force:
            print(f"[agent-release] {addr}: claimed by {holder!r}, not this branch "
                  "— skipping (use --force to release anyway)")
            rc = 1
            continue
        if not _drop_claim(addr):
            rc = 1
    return rc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_start = sub.add_parser("start", help="investigate + claim-check a target, write the task receipt")
    p_start.add_argument("mode", choices=["port", "fix", "recover", "audit"],
                         help="what kind of task this is")
    p_start.add_argument("addresses", nargs="+", help="target address(es), hex")
    p_start.add_argument("--allow-stale-base", action="store_true")
    p_start.add_argument("--takeover", action="store_true",
                         help="explicitly take over an already-implemented target")
    p_start.add_argument("--steal-claim", action="store_true",
                         help="override another branch's unexpired claim (only when "
                              "that branch is known dead)")
    p_start.add_argument("--no-claim", action="store_true",
                         help="skip pushing claim refs (offline / read-only remote)")
    p_start.add_argument("--no-portprep", action="store_true",
                         help="skip ghidra-portprep (explicitly accept working blind)")
    p_start.add_argument("--no-compare", action="store_true",
                         help="skip the initial compare (no built binary yet)")
    p_start.set_defaults(func=cmd_start)

    p_check = sub.add_parser("check", help="diff-aware verification pipeline")
    p_check.add_argument("--max-triage", type=int, default=6)
    p_check.set_defaults(func=cmd_check)

    p_finish = sub.add_parser("finish", help="machine-derived summary / PR body")
    p_finish.set_defaults(func=cmd_finish)

    p_release = sub.add_parser("release", help="delete claim refs for the receipt "
                               "targets (or explicit addresses)")
    p_release.add_argument("addresses", nargs="*", help="addresses to release "
                           "(default: receipt targets)")
    p_release.add_argument("--force", action="store_true",
                           help="release claims held by a different branch")
    p_release.set_defaults(func=cmd_release)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
