# Porting queue

The shared big-target queue: hardest/biggest stubs and known-bad re-ports, roughly
largest-first. Claim a target by porting it — remove the line in the same commit that
lands the port; append new discoveries at the appropriate spot. Keep entries one line
each with the evidence needed to start (address, size, current score if any, blockers).

## Big stubs (never ported)

- `0x5d5d30` (1485B) — TCivToolbar modal interaction body.
- `0x55d200` (1415B)
- `0x502b60` (1285B)
- `0x4eb8b0` (1212B)
- `0x5bc0d0` (1168B)
- TMapMaker phase bodies: `0x526c20` (747B), `0x527730` (1175B), `0x528e50` (940B) —
  partial class recovery already on main.

## Known-bad re-ports (score far below structure)

- `EnsurePortZoneForTile` / `RemovePortZoneByTile` (13% / 24%) — TOcean methods,
  bodies likely mismodeled.
- `0x510210` (28%, 1177B)
- `0x550b60` TShip::ComputeOrderNodeCompositeEconomicScore at 68% — residual is
  scheduling wobble around the inlined /100 and /10 magic divisions; revisit only
  with new evidence.
- TShip.cpp `SignedMod100` user at ~line 232
  (`ComputeNavyOrderPriorityContributionPercentByCategory` family): very likely the
  same mod-vs-div bug 0x550b60 had (original inlines a plain `/ 100`); verify against
  the listing before touching.

## Cluster follow-ups (advisory scoring, commits f67c1e06 + 3e56e3b9)

- `0x4e9060` TGreatPower::ComputeMapActionContextCompositeScoreForNation sits at ~50%
  with verified-correct structure; residual is a register/slot-allocation cascade
  rooted at the entry block. Do not re-litigate without a new allocator insight.
- `0x4e8750` (89%), `0x4e8c50` (87%), `0x4e9a50` (86%) — residuals are dead-arg-slot
  permutations and FP scheduling; acceptable per the wobble policy.

## Workflow-enforcement follow-ups (infrastructure, not ports)

Landed: agent-start/check/finish + portprep-first loop; policy-baseline guard
(local `ALLOW_POLICY_BASELINE_UPDATE=1` + CI `policy-baseline-approved` label);
typedef/redeclaration gates; session-loop just-only output; session memory
untracked; structured rule KB (`config/agent_rules.yml` + `just advice` +
`just agent-rules-gate` + `docs/case-studies/`); claims registry
(`refs/agent-claims/<addr>` refs — agent-start claims with a 24h TTL,
`just agent-release` frees them, degrades to a warning on remotes that refuse
custom refs); generated PR title/body from the receipt (`just agent-finish` →
`build-msvc500/pr-body.md`); CI (`.github/workflows/ci.yml`: tooling tests +
`just source-gates` + generated-integrity vs merge base); `raw_this_offset`
antipattern ratchet.

Still open:

- **Branch protection** (GitHub admin action, not repo code): protect `main`
  against force-pushes and require the CI checks + the `policy-baseline-approved`
  label rule.
- **Semantic gates v3 (true Clang AST)**: today's regex ratchets catch known
  spellings; an AST pass could catch function-pointer casts of known symbols in
  any spelling, raw `this+offset` where a named field already covers the offset,
  and fake factory/helper families by structure. Needs the clang-mingw image in
  CI or a libclang-based tool.
