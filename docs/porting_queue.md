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

Phase 1 landed (agent-start/check/finish, portprep-first loop, policy-baseline
guard, typedef/redeclaration gates, session-loop just-only output, session memory
untracked). Remaining phases, in order:

- **Knowledge-base restructure**: convert topical-skill field notes into structured
  rule entries (id / status / triggers / required_action / forbidden / tools /
  supersedes / examples); expose `just advice 0xADDR` and `just advice --diff`
  (select ~5-10 active rules from portprep output, ownership, triage buckets,
  touched files); move long anecdotes to `docs/case-studies/`; add a KB linter
  (duplicate/out-of-order ids, dangling refs, superseded-active conflicts, raw
  commands where a just target exists, contradictory required/forbidden).
- **Address claiming + PR automation**: a real claims registry (machine-readable
  `address | owner-session | branch | expires`), refusing claimed addresses and
  bodies changed on main after the branch base (agent-start already refuses
  already-implemented targets and warns on ownership drift); generated PR titles
  (targets + outcome, never model names) and bodies from the agent-finish receipt;
  branch protection against force-pushes.
- **Semantic gates v2 (Clang AST)**: function-pointer casts of known symbols in any
  spelling, new raw `this+offset` where the offset already has a named field, fake
  factory/helper families detected by structure, and CI-side enforcement of the
  no-hand-edits-under-generated-dirs rule that agent-check applies locally.
