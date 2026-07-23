# ---------------------------------------------------------------------------
# agent workflow — the only documented entrypoint for porting tasks.
# Imported by the root justfile (flat namespace: shared variables/recipes work
# across modules). Recipe text is moved verbatim so `just --list` is unchanged.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# agent workflow — the only documented entrypoint for porting tasks.
# ---------------------------------------------------------------------------

# Investigate + claim-check target(s) and write build-msvc500/agent-task.json:
# verifies worktree/base freshness, refuses already-implemented targets, then runs
# tooling-check, func-status, ghidra-portprep, the initial compare, and
# library-identify for library-shaped addresses. `just agent-start port 0xADDR...`.
[doc('Start a porting task: investigate, claim-check, write the task receipt')]
[group('agent')]
agent-start mode +addrs:
  uv run python -m tools.workflow.agent_task start {{mode}} {{addrs}}

# Diff-aware verification: derives the right steps from the actual git diff
# (marker changes always regenerate build inputs; hand-edited generated files -> hard error),
# then format-check on touched C++, build, detect, batch compare + triage of every
# touched address, gates, tests, stats. Reruns are cheap — fix forward and rerun.
[doc('Verify the current diff: regen/format/build/compare/triage/gates/tests/stats')]
[group('agent')]
agent-check *args:
  uv run python -m tools.workflow.agent_task check {{args}}

[doc('Render the task receipt + diff into a PR-ready summary (CI still recomputes)')]
[group('agent')]
agent-finish *args:
  uv run python -m tools.workflow.agent_task finish {{args}}

# Select the 5-10 most relevant active rules from config/agent_rules.yml for a
# target (uses the agent-task receipt's portprep dossier) or the current diff.
[doc('Relevant active rules for a target or the current diff')]
[group('agent')]
advice *args:
  uv run python -m tools.workflow.advice {{args}}

# Strict source codemod for listing-reviewed return-type migrations. Dry-run by
# default; --apply updates the owned definition and its class declaration only
# after every requested address validates without ambiguity.
[doc('MUTATES (--apply): rewrite reviewed method return types by owned address')]
[group('agent')]
rewrite-return-types *args:
  uv run python -m tools.workflow.rewrite_return_types {{args}}

[doc('Release this task: delete the claim refs for the receipt targets')]
[group('agent')]
agent-release *args:
  uv run python -m tools.workflow.agent_task release {{args}}
