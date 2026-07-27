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
build-msvc500/agent-tasks/<branch>/receipt.json, with full per-command logs beside it.

`agent-check` inspects the actual git diff and derives the workflow from it:
generated/config files edited without marker changes -> hard error; touched C++ ->
format-check; then build (which regenerates its inputs), detect, gates (including
one full progress report), score extraction for every touched address (receipt
targets, added markers, and -- via hunk-to-marker mapping -- edited existing bodies,
each with its reason recorded in check.affected_functions), targeted triage, tests,
and the
generated-artifact integrity gate against the same integration base `just precommit`
uses, so a green receipt cannot be followed by a pre-commit integrity failure.

`agent-finish` renders the receipt + diff into a summary suitable for a PR body, and
REFUSES to render one unless agent-check is green for this exact tree (same HEAD, same
uncommitted diff, claims still held); --allow-unverified-draft renders a body whose first
line says it is unverified. The receipt is guidance for the agent and reviewers —
`just precommit` recomputes the checks and trusts only its own run.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
# One receipt directory per branch (imperialism-decomp-j201). Concurrent agents share a
# checkout, so a single build-msvc500/agent-task.json let one task overwrite another's
# state and let agent-finish describe a tree nobody checked. The branch is the task
# identity here: it is what claims, PRs and the integration base are all keyed by, and it
# needs no pointer file to resolve.
TASKS_DIR = REPO_ROOT / "build-msvc500" / "agent-tasks"
LEGACY_TASK_JSON = REPO_ROOT / "build-msvc500" / "agent-task.json"

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


def _task_id(branch: str | None = None) -> str:
    """Filesystem-safe task id for a branch (the branch IS the task identity)."""
    name = branch or _git("rev-parse", "--abbrev-ref", "HEAD") or "detached"
    return re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-") or "detached"


def _task_dir(branch: str | None = None) -> Path:
    return TASKS_DIR / _task_id(branch)


def _receipt_path(branch: str | None = None) -> Path:
    return _task_dir(branch) / "receipt.json"


def _pr_body_path(branch: str | None = None) -> Path:
    return _task_dir(branch) / "pr-body.md"


def _worktree_fingerprint(base: str) -> dict:
    """Bind a receipt to the exact tree it describes.

    HEAD alone is not enough: the whole point of agent-check is that it verifies the
    worktree, so the uncommitted diff has to be part of the identity too.
    """
    diff = _git("diff", base) + "\n" + _git("diff")
    # The build dir holds this very receipt and every generated artifact, so it can never
    # be part of the tree identity (it is gitignored in a real checkout; filter it anyway
    # so a stray un-ignored build dir cannot make every finish look unverified).
    status = "\n".join(
        line for line in _git("status", "--porcelain").splitlines()
        if "build-msvc500/" not in line
    )
    return {
        "head": _git("rev-parse", "HEAD"),
        "base": base,
        "diff_sha256": hashlib.sha256(diff.encode("utf-8", "replace")).hexdigest(),
        "status_sha256": hashlib.sha256(status.encode("utf-8", "replace")).hexdigest(),
    }


def _artifact_hashes() -> dict:
    """Hash the inputs a verification result depends on, when they are present."""
    out: dict[str, str] = {}
    candidates = {
        "original_binary": os.environ.get("ORIGINAL_BINARY", ""),
        "recompiled_binary": str(REPO_ROOT / "build-msvc500" / "Imperialism.exe"),
        "recompiled_pdb": str(REPO_ROOT / "build-msvc500" / "Imperialism.pdb"),
    }
    for name, raw in candidates.items():
        if not raw:
            continue
        path = Path(raw)
        if not path.is_file():
            continue
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
        out[name] = digest.hexdigest()
    return out


def _load_task(branch: str | None = None) -> dict:
    path = _receipt_path(branch)
    if path.is_file():
        return json.loads(path.read_text(encoding="utf-8"))
    # One-time migration path: a receipt written by the pre-j201 single-file layout.
    if LEGACY_TASK_JSON.is_file():
        legacy = json.loads(LEGACY_TASK_JSON.read_text(encoding="utf-8"))
        if legacy.get("branch") in (None, branch or _git("rev-parse", "--abbrev-ref", "HEAD")):
            return legacy
    return {}


def _save_task(task: dict) -> None:
    path = _receipt_path(task.get("branch"))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(task, indent=2) + "\n", encoding="utf-8")
    print(f"[agent-task] receipt written: {path.relative_to(REPO_ROOT)}")


def _integration_base_ref() -> str:
    """The ref this branch will be integrated into, resolved like `just precommit`.

    PRECOMMIT_BASE_REF wins, then origin/main, then a local main; a single-branch
    checkout with neither falls back to HEAD so the worktree is still inspected.
    Keeping this identical to _precommit-generated-integrity-gate is what makes
    agent-check's verdict mean the same thing as the pre-commit one
    (imperialism-decomp-uerj).
    """
    explicit = os.environ.get("PRECOMMIT_BASE_REF")
    if explicit:
        return explicit
    for ref in ("refs/remotes/origin/main", "refs/heads/main"):
        proc = _run(["git", "rev-parse", "--verify", "--quiet", ref])
        if proc.returncode == 0:
            return "origin/main" if "remotes" in ref else "main"
    return "HEAD"


def _merge_base(base_ref: str | None = None) -> str:
    return _git("merge-base", "HEAD", base_ref or _integration_base_ref())


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


def _push_claim(addr: str, branch: str, expected_sha: str = "") -> bool:
    """Compare-and-swap the claim ref for addr.

    expected_sha is the remote claim commit we observed (empty string = the ref
    must not exist yet). git push --force-with-lease with an explicit expect
    value makes every path atomic: a fresh claim only lands on an absent ref,
    and a refresh / expiry takeover / --steal-claim only lands if the remote
    claim is still exactly the one we based the decision on. A claim that
    changed under us is rejected by the remote, never silently clobbered.
    (Claim commits are parentless, so updating an existing ref is always
    non-fast-forward; a plain push can never succeed here.)
    """
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
    ref = CLAIM_REF_PREFIX + addr
    push = _run(["git", "push",
                 f"--force-with-lease={ref}:{expected_sha}",
                 "origin", f"{sha}:{ref}"])
    if push.returncode != 0:
        print(f"[claims] could not push claim for {addr} "
              "(remote refused, or the claim changed since it was inspected)")
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


FIRST_ERROR_RE = re.compile(
    r"(?im)^.*?\b(error|failed|FAILED|refused|traceback|fatal|violation)\b.*$"
)


def _first_error(text: str) -> str:
    match = FIRST_ERROR_RE.search(text)
    return match.group(0).strip()[:400] if match else ""


def _step(name: str, cmd: list[str], results: dict, *, tolerate: bool = False) -> subprocess.CompletedProcess:
    print(f"[agent-task] {name}: {' '.join(cmd)}")
    started = time.monotonic()
    proc = _run(cmd)
    duration = time.monotonic() - started
    ok = proc.returncode == 0
    output = proc.stdout + proc.stderr
    # Full output goes to the task's log dir; the receipt keeps a structured summary and
    # a pointer. The old 12-line tail discarded portprep dossiers, compiler diagnostics,
    # gate reports and mismatch analysis exactly when they were needed
    # (imperialism-decomp-j201).
    log_path = _task_dir() / "logs" / f"{len(results):02d}-{re.sub(r'[^A-Za-z0-9._-]+', '-', name)}.log"
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(output, encoding="utf-8")
        log_ref = str(log_path.relative_to(REPO_ROOT))
    except OSError as exc:  # pragma: no cover - unwritable build dir
        log_ref = f"<unwritable: {exc}>"
    results[name] = {
        "cmd": " ".join(cmd),
        "ok": ok,
        "returncode": proc.returncode,
        "duration_seconds": round(duration, 3),
        "log": log_ref,
        "first_error": "" if ok else _first_error(output),
        "tail": "\n".join(output.splitlines()[-12:]),
    }
    print(f"[agent-task] {name}: {duration:.2f}s (log: {log_ref})")
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

    # CAS claim push: the expected remote value is what we just inspected in 3b
    # (empty = the ref must not exist). A claim that cannot be pushed is a hard
    # stop unless the agent explicitly accepts running unclaimed.
    claimed: list[str] = []
    if not args.no_claim:
        for addr in addrs:
            if _push_claim(addr, branch, remote_claims.get(addr, "")):
                claimed.append(addr)
            elif args.proceed_unclaimed:
                print(f"[agent-start] WARNING (proceed-unclaimed): {addr} is not "
                      "claimed — another agent may pick it up")
            else:
                print(f"[agent-start] REFUSED: could not claim {addr} — rerun to "
                      "re-inspect the claim, or pass --proceed-unclaimed to "
                      "explicitly run without a claim")
                return 2

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
              "run `just ghidra portprep ADDR` before editing")
    elif not os.environ.get("GHIDRA_INSTALL_DIR"):
        print("[agent-start] REFUSED: GHIDRA_INSTALL_DIR is not set, so "
              "ghidra portprep cannot run. Export it (see AGENTS.md environment "
              "notes) or pass --no-portprep to explicitly accept working blind.")
        return 2
    else:
        for addr in addrs:
            proc = _step(f"portprep {addr}", ["just", "ghidra", "portprep", addr],
                         results)
            if proc.returncode != 0:
                print(f"[agent-start] REFUSED: ghidra portprep failed for {addr} — "
                      "the ground-truth dossier is mandatory (fix the Ghidra "
                      "environment, or pass --no-portprep to explicitly accept "
                      "working blind)")
                return 2
            if not proc.stdout.strip():
                print(f"[agent-start] REFUSED: ghidra portprep produced no output "
                      f"for {addr} — an empty dossier is not a dossier (fix the "
                      "Ghidra environment, or pass --no-portprep to explicitly "
                      "accept working blind)")
                return 2
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

OWNED_MARKER_RE = re.compile(
    r"//\s*(?:FUNCTION|SYNTHETIC|TEMPLATE):\s*\w+\s+(0x[0-9a-fA-F]+)"
)
HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def marker_lines(text: str) -> list[tuple[int, str]]:
    """[(1-based line, normalized address)] for every owned marker in `text`."""
    out: list[tuple[int, str]] = []
    for index, line in enumerate(text.splitlines(), start=1):
        match = OWNED_MARKER_RE.search(line)
        if match:
            out.append((index, _norm_addr(match.group(1))))
    return out


def changed_line_numbers(diff_text: str) -> set[int]:
    """New-file line numbers touched by a `git diff -U0` hunk header.

    A pure deletion (`+c,0`) still anchors at line c: whatever body surrounded the
    removed lines is what changed.
    """
    lines: set[int] = set()
    for line in diff_text.splitlines():
        match = HUNK_RE.match(line)
        if not match:
            continue
        start = int(match.group(1))
        count = 1 if match.group(2) is None else int(match.group(2))
        lines.update(range(start, start + max(count, 1)))
    return lines


def addresses_for_changed_lines(text: str, changed: set[int]) -> set[str]:
    """Addresses whose marked body encloses any changed line.

    A marked function is taken to run from its marker line until the next marker (or
    EOF), which is exactly the ownership rule the marker gates already enforce: one
    owned implementation per address, marker immediately above the declaration. Lines
    before the first marker (includes, file comments) belong to no address.

    The boundary rule deliberately over-includes: a comment block grown above a marker
    attributes to the preceding function as well. An extra address in the compare set
    costs one more triage line; a missing one is the defect this exists to prevent.
    """
    markers = marker_lines(text)
    if not markers or not changed:
        return set()
    hit: set[str] = set()
    for index, (line_no, addr) in enumerate(markers):
        end = markers[index + 1][0] - 1 if index + 1 < len(markers) else None
        for changed_line in changed:
            if changed_line >= line_no and (end is None or changed_line <= end):
                hit.add(addr)
                break
    return hit


def _diff_paths(base: str) -> list[str]:
    committed = _git("diff", "--name-only", base).splitlines()
    status = [l[3:].strip() for l in _git("status", "--porcelain").splitlines() if l.strip()]
    return sorted({p for p in committed + status if p})


def cmd_check(args: argparse.Namespace) -> int:
    task = _load_task()
    branch = _git("rev-parse", "--abbrev-ref", "HEAD")
    receipt_branch = task.get("branch")
    if receipt_branch and receipt_branch != branch:
        print(
            f"[agent-check] ignoring receipt from branch {receipt_branch!r}; "
            f"checking {branch!r} against origin/main"
        )
        task = {
            "created_utc": _now(),
            "mode": "fix",
            "branch": branch,
            "base_commit": _merge_base(),
            "claimed": [],
            "targets": {},
        }
    base = task.get("base_commit") or _merge_base()
    paths = _diff_paths(base)
    if not paths:
        print("[agent-check] no changes vs base — nothing to verify")
        return 0
    print(f"[agent-check] {len(paths)} changed path(s) vs {base[:10]}")

    results: dict = {}
    failures: list[str] = []

    # `just build` regenerates disposable build inputs under the MSVC build lock.
    diff_text = _git("diff", base, "--", "src", "include") + "\n" + _git("diff", "--", "src", "include")

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

    # Batch compare of every touched address, with a recorded reason per address so the
    # touched set is auditable instead of heuristic (imperialism-decomp-3gn8).
    reasons: dict[str, set[str]] = {}

    def _touch(addr: str, reason: str) -> None:
        reasons.setdefault(addr, set()).add(reason)

    for addr in task.get("targets", {}):
        _touch(_norm_addr(addr), "receipt_target")
    if any(
        path in UI_CODEGEN_INPUTS
        for path in paths
    ):
        from tools.ui_codegen import load_recipes

        for recipe in load_recipes(REPO_ROOT):
            _touch(f"0x{recipe.address:08x}", "ui_codegen_input")
    for line in diff_text.splitlines():
        if line.startswith("+"):
            m = OWNED_MARKER_RE.search(line)
            if m:
                _touch(_norm_addr(m.group(1)), "marker_added")
    # An edit to an existing body changes no marker line, so it is invisible to the scan
    # above. Map every changed hunk back to the marked function that encloses it.
    for path in cpp:
        if not path.endswith(".cpp"):
            continue
        text = (REPO_ROOT / path).read_text(encoding="utf-8", errors="replace")
        changed = changed_line_numbers(
            _git("diff", "-U0", base, "--", path)
        ) | changed_line_numbers(_git("diff", "-U0", "--", path))
        for addr in addresses_for_changed_lines(text, changed):
            _touch(addr, "body_edited")
    addrs = set(reasons)
    # Gates create one fresh full-corpus progress report. Reuse its function scores
    # instead of running a second reccmp comparison solely to parse percentages.
    gates_ok = _step("gates", ["just", "gates"], results).returncode == 0
    if not gates_ok:
        failures.append("gates")

    scores: dict[str, float] = {}
    report_path = REPO_ROOT / "build-msvc500" / "reccmp_report.json"
    if addrs and gates_ok and report_path.is_file():
        from tools.reccmp.progress_stats import parse_report_functions

        report = parse_report_functions(report_path)
        scores = {
            addr: float(report[hex(int(addr, 16))]["m"]) * 100.0
            for addr in sorted(addrs)
            if hex(int(addr, 16)) in report
        }
        below = [a for a, s in scores.items() if s < 100.0]
        triage_addrs = sorted(below)[: args.max_triage]
        if triage_addrs:
            _step(
                "triage-touched",
                ["just", "triage", *triage_addrs],
                results,
                tolerate=True,
            )

    if addrs and gates_ok and not report_path.is_file():
        print(f"[agent-check] no reccmp report at {report_path} — scores not extracted")

    if _step("test", ["just", "test"], results).returncode != 0:
        failures.append("test")

    # Same gate, same base semantics as `just precommit` — a green agent-check must not
    # be followed by a pre-commit failure on generated-artifact integrity. No
    # --no-worktree: one diff against the integration base covers both the committed
    # branch and uncommitted generated paths still sitting in the worktree.
    integrity_base_ref = _integration_base_ref()
    integrity_base = _merge_base(integrity_base_ref)
    integrity_ok = _step(
        "generated-integrity",
        ["just", "generated-integrity-gate", "--base", integrity_base],
        results,
    ).returncode == 0
    if not integrity_ok:
        failures.append("generated-integrity")

    task.setdefault("check", {})
    task["check"] = {
        "checked_utc": _now(),
        # The tree this verdict describes. agent-finish refuses to render a PR body for
        # any other tree (imperialism-decomp-j201).
        "tree": _worktree_fingerprint(base),
        "artifacts": _artifact_hashes(),
        "claims_held": sorted(task.get("claimed", [])),
        "paths": paths,
        "markers_changed": any(MARKER_RE.match(l2) for l2 in diff_text.splitlines()),
        "generated_integrity": {
            "base_ref": integrity_base_ref,
            "base": integrity_base,
            "ok": integrity_ok,
        },
        "scores": scores,
        "affected_functions": {
            addr: {"reasons": sorted(reasons[addr])} for addr in sorted(reasons)
        },
        "failures": failures,
        "results": {k: {kk: vv for kk, vv in v.items() if kk != "tail"} | (
            {"tail": v["tail"]} if not v["ok"] else {})
            for k, v in results.items()},
        "task_dir": str(_task_dir().relative_to(REPO_ROOT)),
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


def _finish_blockers(task: dict, base: str) -> list[str]:
    """Why this receipt must not become a PR body.

    A PR body is a claim about verification. Rendering one from a receipt whose checks
    never ran, failed, or described a different tree is how a generic, unverified PR
    ships (imperialism-decomp-j201).
    """
    check = task.get("check", {})
    if not check:
        return ["agent-check has not run for this task (no check block in the receipt)"]

    blockers: list[str] = []
    failures = check.get("failures", [])
    if failures:
        blockers.append(f"agent-check failed: {', '.join(failures)}")

    recorded = check.get("tree")
    if not recorded:
        blockers.append("receipt predates tree binding — re-run `just agent-check`")
    else:
        current = _worktree_fingerprint(recorded.get("base") or base)
        if current["head"] != recorded.get("head"):
            blockers.append(
                f"HEAD moved since the check ({recorded.get('head', '?')[:10]} -> "
                f"{current['head'][:10]})"
            )
        if current["diff_sha256"] != recorded.get("diff_sha256"):
            blockers.append("the worktree changed since the check (uncommitted diff differs)")
        elif current["status_sha256"] != recorded.get("status_sha256"):
            # Untracked files never show up in `git diff`, but a new source file is
            # exactly the kind of unverified change this refusal exists for.
            blockers.append("the worktree changed since the check (untracked files differ)")

    branch = _git("rev-parse", "--abbrev-ref", "HEAD")
    if task.get("branch") and task["branch"] != branch:
        blockers.append(f"receipt belongs to branch {task['branch']!r}, on {branch!r} now")

    lost = _claims_lost_to_other_branches(task, branch)
    if lost:
        blockers.append("claims no longer held by this branch: " + ", ".join(lost))
    return blockers


def _claims_lost_to_other_branches(task: dict, branch: str) -> list[str]:
    claimed = sorted(set(task.get("claimed", [])))
    if not claimed:
        return []
    try:
        remote = _fetch_claims()
    except Exception:  # pragma: no cover - offline remote is not a verification failure
        return []
    lost = []
    for addr in claimed:
        sha = remote.get(addr)
        if not sha:
            continue
        holder = _read_claim(addr, sha).get("branch")
        if holder and holder != branch:
            lost.append(f"{addr} (held by {holder!r})")
    return lost


def cmd_finish(args: argparse.Namespace) -> int:
    task = _load_task()
    if not task:
        print(f"[agent-finish] no receipt ({_receipt_path().relative_to(REPO_ROOT)}) — run "
              "`just agent-start` / `just agent-check` first", file=sys.stderr)
        return 2
    base = task.get("base_commit") or _merge_base()
    check = task.get("check", {})
    diffstat = _git("diff", "--stat", base)

    blockers = _finish_blockers(task, base)
    if blockers and not getattr(args, "allow_unverified_draft", False):
        print("[agent-finish] REFUSED — this receipt does not describe a verified tree:",
              file=sys.stderr)
        for blocker in blockers:
            print(f"  - {blocker}", file=sys.stderr)
        print("Run `just agent-check` on the current tree, or pass "
              "--allow-unverified-draft to render a visibly-marked draft.",
              file=sys.stderr)
        return 2

    lines: list[str] = []
    if blockers:
        lines += [
            "> **UNVERIFIED DRAFT — do not open a PR with this body as-is.**",
            ">",
            *[f"> - {blocker}" for blocker in blockers],
            "",
        ]
    lines += ["## Summary", ""]
    for addr, t in task.get("targets", {}).items():
        before = t.get("baseline_score")
        after = check.get("scores", {}).get(addr)
        b = f"{before:.2f}%" if isinstance(before, (int, float)) else "stub/unported"
        a = f"{after:.2f}%" if isinstance(after, (int, float)) else "?"
        lines.append(f"- `{addr}` ({task.get('mode', 'port')}): {b} -> {a}")
    extra = {a: s for a, s in check.get("scores", {}).items()
             if a not in task.get("targets", {})}
    for addr, s in sorted(extra.items()):
        reasons = check.get("affected_functions", {}).get(addr, {}).get("reasons", [])
        why = f" [{', '.join(reasons)}]" if reasons else ""
        lines.append(f"- `{addr}` (touched){why}: -> {s:.2f}%")
    if not task.get("targets") and not extra:
        lines.append("- workflow/infrastructure change (no address targets)")

    lines += ["", "## Classes and files touched", ""]
    paths = check.get("paths", [])
    manual = [p for p in paths if p.startswith(MANUAL_CPP_PREFIXES) and p.endswith((".cpp", ".h"))]
    for path in manual[:20] or ["(no manual C++ paths)"]:
        lines.append(f"- `{path}`")
    if len(manual) > 20:
        lines.append(f"- ...and {len(manual) - 20} more")

    lines += ["", "## Verification", ""]
    if check:
        failures = check.get("failures", [])
        lines.append(f"- `just agent-check`: {'GREEN' if not failures else 'FAILED: ' + ', '.join(failures)}")
        for name, r in check.get("results", {}).items():
            status = "ok" if r.get("ok") else f"FAILED (exit {r.get('returncode', '?')})"
            log = f" — log `{r['log']}`" if r.get("log") else ""
            lines.append(f"- `{r.get('cmd', name)}`: {status}{log}")
        tree = check.get("tree", {})
        if tree:
            lines.append(
                f"- verified tree: HEAD `{tree.get('head', '?')[:10]}` vs base "
                f"`{str(tree.get('base', '?'))[:10]}`, worktree diff "
                f"`{tree.get('diff_sha256', '?')[:12]}`"
            )
        lines.append("- `just precommit` recomputes all of this and is the authority")
    else:
        lines.append("- agent-check was NOT run — run `just agent-check` before finishing")

    lines += ["", "## Score and stub deltas", ""]
    deltas = task.get("deltas") or {}
    if deltas:
        for key, value in sorted(deltas.items()):
            lines.append(f"- {key}: {value}")
    else:
        lines.append("- fill in from `just stats` vs `config/baselines/reccmp_progress_baseline.json` "
                     "(exact functions, average similarity, stub count)")

    lines += ["", "## Runtime tests", ""]
    runtime = [r for name, r in check.get("results", {}).items() if "runtime" in name]
    if runtime:
        for r in runtime:
            lines.append(f"- `{r.get('cmd')}`: {'ok' if r.get('ok') else 'FAILED'}")
    else:
        lines.append("- not run by agent-check; `just precommit` runs the `pr` suite")

    lines += ["", "## Beads", ""]
    beads = task.get("beads") or {}
    closed = beads.get("closed") or []
    opened = beads.get("opened") or []
    lines.append("- closes: " + (", ".join(f"`{b}`" for b in closed) or "none recorded"))
    lines.append("- opens: " + (", ".join(f"`{b}`" for b in opened) or "none recorded"))

    lines += ["", "## Unresolved risks", ""]
    below = [a for a, s in check.get("scores", {}).items() if s < 100.0]
    if below:
        lines.append("- Below-100% functions (see triage output in the receipt): "
                     + ", ".join(f"`{a}`" for a in sorted(below)))
    else:
        lines.append("- none recorded")
    receipt_ref = _receipt_path(task.get("branch")).relative_to(REPO_ROOT)
    lines += ["", "## Diffstat", "", "```", diffstat or "(no diff)", "```", "",
              f"_Receipt: {receipt_ref} — guidance only; `just precommit`",
              "recomputes all checks itself._"]
    body = "\n".join(lines)
    body_path = _pr_body_path(task.get("branch"))
    body_path.parent.mkdir(parents=True, exist_ok=True)
    body_path.write_text(body + "\n", encoding="utf-8")
    print(f"PR title: {_pr_title(task)}")
    print(f"PR body written to {body_path.relative_to(REPO_ROOT)}")
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
    p_start.add_argument("--proceed-unclaimed", action="store_true",
                         help="continue when a claim push is rejected instead of "
                              "hard-stopping (explicitly accept running unclaimed)")
    p_start.add_argument("--no-portprep", action="store_true",
                         help="skip ghidra-portprep (explicitly accept working blind)")
    p_start.add_argument("--no-compare", action="store_true",
                         help="skip the initial compare (no built binary yet)")
    p_start.set_defaults(func=cmd_start)

    p_check = sub.add_parser("check", help="diff-aware verification pipeline")
    p_check.add_argument("--max-triage", type=int, default=6)
    p_check.set_defaults(func=cmd_check)

    p_finish = sub.add_parser("finish", help="machine-derived summary / PR body")
    p_finish.add_argument(
        "--allow-unverified-draft",
        action="store_true",
        help="render the body even when the receipt is unverified; the draft says so at the top",
    )
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
