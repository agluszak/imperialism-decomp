# Porting queue

The shared big-target queue: hardest/biggest stubs and known-bad re-ports, roughly
largest-first. Claim a target by porting it — remove the line in the same commit that
lands the port; append new discoveries at the appropriate spot. Keep entries one line
each with the evidence needed to start (address, size, current score if any, blockers).

## Big stubs (never ported)

- TMapMaker phase bodies: `0x527730` (1175B), `0x528e50` (940B) — still fabricated
  `{}`/stub bodies; not yet attempted (see the class-recovery writeup below first,
  since the same wrong-signature pattern likely applies to their vtable slots too).
  `0x526c20`/`0x527040` (previously flagged in this same bucket) are now landed —
  see below.
- **TMapMaker class recovery (landed 2026-07-18, `0x526c20` 0.83% -> 31.82%,
  `0x527040` 1.09% -> 28.14%)**: confirmed the systemic mismodeling this bucket
  flagged — several vtable slot signatures were templated off TEventHandler/TView's
  real virtuals of the same slot POSITION, not verified against TMapMaker's own call
  sites (`just vtable TMapMaker` was, and still is, 100% the whole time: the
  slot->address ASSIGNMENT was always correct, only the C++ SIGNATURES were wrong).
  Fixed 3 slots by raw-listing evidence (arg count from actual pushes + RET n, not
  the decompile's signature guess, which itself undercounted args here):
  - Slot 12/0x30 (`QueryStepValue() -> TEventHandler*`, 0-arg) was really
    `int AssignRegionClassToCellAndNeighbors(int cellIndex, int mode, int classIndex,
    int retryBudget)` (verified RET 0x10 = 4 stack args, from both the caller's 4
    explicit pushes and the callee's own frame reads at [esp+0x48.. +0x54]).
    Recursively claims a coarse-grid cell and spreads to hex neighbors by
    weighted-random selection (weight +10 per further neighbor already owned by the
    same class), retrying until `retryBudget` assignments land or neighbors run out.
    Renamed and fully ported (0x527040).
  - Slot 13/0x34 (`DispatchQueuedUiCommandAndRelease(void*)`) and slot 16/0x40
    (`DispatchEvent(int,TEventHandler*,TEvent*)`) were really BOTH
    `char Method(int cellIndex, int classIndex)` (verified 2 pushed int args + AL
    return from slot 0x30's own call sites — same 2 args passed to both, slot 0x34
    tried first but ONLY for majors (classIndex<7), slot 0x40 tried as a fallback/for
    everyone). Renamed to `TryMergeRegionGroupWithNeighborsRestrictedToMajors`
    (0x527300) and `TryMergeRegionGroupWithNeighbors` (0x5274d0) — their real bodies
    are a union-find merge of `classIndex`'s region-group id against each hex
    neighbor's assigned group, discovered via this pass: a previously-undiscovered
    `int groupMemberLists1a8[7][3]` field (-1 terminated, up to 3 member class
    indices per group id), used alongside the already-known `cityRegionNextId1fc`/
    `cityRegionIds200`. **Signatures fixed and now added to the header; BODIES NOT
    YET PORTED** (still `return 0`, same as before this pass, so no behavior
    regression) — a dedicated follow-up should port 0x527300 and 0x5274d0 together
    since they share the union-find fields; decompiles already captured this
    session show the full logic (both are ~60-70 lines, tractable).
  - Slot 29/0x74 (`GetAdjacentRegionGridCell`) was re-verified CORRECT as-is
    (2-arg, matches every call site) — Ghidra's own "VTableSlot1D" fallback name for
    it in decompiles of OTHER functions is just an unresolved-symbol artifact, not
    evidence of a problem.
  - Also promoted the previously-undocumented `+0x29c` lone int (queue's old
    "TMapMaker never-ported" note flagged it) to `lastMinorSeedCandidate29c`;
    not yet observed read anywhere, so semantics beyond "reset per attempt" unconfirmed.
  - `0x527730` (`MapGenPassSlot0F`) and `0x528e50` (`vmethod_0017`, the hex-grid
    neighbor-sampling pass over the 6 unnamed `0x697450`-band globals) are NOT YET
    ATTEMPTED — do the same raw-listing signature audit before porting either, since
    both are likely to have the same templated-signature problem on whatever vtable
    slots they call into.

## Known-bad re-ports (score far below structure)

- `0x4eb8b0` TGreatPower::AssignTrackedEntryActionsByProfileToOrdersOrUnits (landed
  2026-07-17, 65.50%, own TU `TGreatPower_AssignTrackedEntryActions.cpp`, structure
  verified — all real call targets pair correctly: CIterator Reset/More/Advance,
  GetNavyPrimaryOrderListHead/nextOlder24 manual walk, every vtable slot dispatch
  (0x2c/0x58/0x5c/0x68/0x6c/0x78/0x7c/0x80/0x84/0x98) against the correct TMission
  slot). Residual is a `this`-pinning register-allocation choice (original keeps
  `this` live in EDI across the whole function; recomp spills it to a stack slot),
  which cascades into a uniformly-shifted 12-byte-larger frame (0x84 vs 0x78) and the
  matching stack-offset/codegen diff buckets — the class of residual the
  `big-functions` skill documents as not source-steerable. Added 4 new address-pinned
  globals (`g_MissionDefaultScore_006545d0`, `g_UnreferencedConstant_006545d4`,
  `g_MissionScoreOneConstant_006545d8`, `g_MissionScoreZeroThreshold_006545f0`) for
  the inline weighted-score computation (mirrors the already-landed
  `CompareMissionOrderEntriesByPriorityScore` idiom, TMission.cpp:276, at a different
  address instance). Don't retry without new evidence on the frame-size residual.
- `0x5bc0d0` TDealBookPicture::RefreshTradeSelectionHeaderAndNationOfferBidLines (landed
  2026-07-17, 47.86%, structure verified — all real call targets pair correctly:
  TTradePageSellView/BuyView delegation, TStaticText label/bounds methods, CaptureLayoutF0,
  SetPictureResourceIdAndRefresh, MessageBoxA/TemporarilyClearAndRestoreUiInvalidationFlag).
  Two open residuals: (1) `field9c`'s type/identity (used as the first of 4 CaptureLayoutF0
  receivers at the tail) is an unconfirmed placeholder — TDealBookPicture.h flags it; (2) the
  header-text CString build (`seasonName + " " + yearText`) doesn't reproduce the original's
  extra copy-ctor/operator=/dtor sequence (CStack_74) — likely a clang-cl vs the real MSVC500
  copy-elision difference for a byval-returning operator+ chain, matching the TNewspaperView
  cluster's `0x55d200`-style residual below. A CopyRect-based two-local RECT copy was tried for
  the three QueryBounds+Invalidate blocks and empirically regressed the score (47.86% ->
  45.00%) — reverted; don't retry without new evidence.
- TNewspaperView advisor cluster (landed 2026-07-17, structure verified; residuals
  documented in docs/case-studies/tnewspaperview-advisor-rows-dossier.md):
  `0x55d200` 62% (uniform +4 frame-slot shift from the original's extra concat/byval
  temp), `0x55df50` 51% (blocked on the TTEView/TDeluxeText inline-ctor color-struct
  recovery: ctors 0x45b080/0x45b0a0 as a 4-byte color type also unifying styleRef6),
  `0x580280` 49% (bracket-scanner branch-shape wobble), `0x4f1760` 73% and
  `0x574720` 73% (scheduling), `0x55d910` 75%, `0x580460` 79%, `0x4e3220` 97%
  (one-past-end table-bound annotation), `0x55da80` 95%, `0x55dcd0` 94%,
  `0x4e3060` 99%.
- TDiplomacyMgr.cpp fabricated empty bodies noticed nearby: `0x4f1570`
  InitializeDiplomacyStandingBaselineRandom and `0x4f1630`
  BuildMajorNationDiplomacyStandingRanking — both `{}` in manual source; read the
  listings before trusting them.

- TScrollBarView.cpp fabricated empty bodies still remaining (the 0x5744b0/0x5746e0/
  0x573ce0/0x574720 batch is fixed): `HandleEvent` 0x5747c0 (~112B),
  `BeginMouseCaptureAndStartRepeatTimer` 0x574830 (~320B), `ApplyRectSlot110`
  0x574970 (~928B), `DispatchPictureResourceCommand` 0x574d10 — all currently `{}` in
  manual source; read the listings before trusting any of them.
- `0x574720` TScrollBarView::NoOpUiLifecycleHook at 73.5% — residual is pure
  instruction-scheduling wobble inside the surface-rect block; structure verified.
- `0x5e50c0` at 77.8% — residual is an ecx/eax naming permutation in the slot-cursor
  idiom; structure verified.

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
