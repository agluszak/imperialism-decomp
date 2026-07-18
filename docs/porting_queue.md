# Porting queue

The shared big-target queue: hardest/biggest stubs and known-bad re-ports, roughly
largest-first. Claim a target by porting it — remove the line in the same commit that
lands the port; append new discoveries at the appropriate spot. Keep entries one line
each with the evidence needed to start (address, size, current score if any, blockers).

## Big stubs (never ported)

- TMapMaker phase bodies: `0x526c20` (747B), `0x527730` (1175B), `0x528e50` (940B) —
  **NOT a quick port; needs a dedicated class-recovery pass first** (investigated
  2026-07-17, no code changed). `TMapMaker.h`'s vtable slot signatures were seemingly
  templated off TEventHandler/TView/TWindow's real virtuals (same slot NAMES:
  QueryStepValue/DispatchEvent/DispatchQueuedUiCommandAndRelease/OwnerPanel/DoIdle/
  ForwardParam/etc.) without verifying TMapMaker actually shares that inheritance
  (header declares `class TMapMaker : public TObject`, not TEventHandler) — this
  looks like a systemic mismodeling, not isolated stub gaps:
  - `0x526c20` (RunMapGenerationAttempt) calls vtable slot 0x30 (`byte offset`,
    ordinal 0xc) twice with **4 int args**, return compared against 8 then 4 —
    completely incompatible with the header's declared `QueryStepValue()` (0-arg,
    returns `TEventHandler*`). symbols.csv already carries a leftover proto hint
    `ExpandCoarseRegionNodeWithNeighborChecks()` for slot 0x30's real implementation
    at `0x527040` (currently faked as `TMapMaker::QueryStepValue() { return 0; }`,
    RET 0x10 in the binary = real 4-word args, confirming the header signature is
    wrong there too).
  - `0x527040` itself calls slot 0x30 AGAIN internally, but with what disassembles
    as a **1-arg** call (`PUSH EAX; CALL [EAX+0x30]`) right after a 5-arg call to
    slot 0xa — inconsistent arg counts for what should be one signature. Slots 0xd
    (`DispatchQueuedUiCommandAndRelease`, header: 1 void* arg) and 0x10
    (`DispatchEvent`, header: 3 args) are ALSO called with only 2 int args and a
    bool return in the raw listing — contradicting their current declarations too.
  - New unmodeled data fields discovered while tracing `0x526c20`: an 84-byte
    `int[7][3]`-shaped table at `TMapMaker+0x1a8` (currently absorbed into
    `pad_1a5`) and a lone `int` at `+0x29c` (currently inside `pad_25c`), both
    initialized to -1 by `RunMapGenerationAttempt`.
  - `0x528e50` (vmethod_0017 / SmoothCityRegionOwnershipByNeighborSampling) is a
    hex-grid neighbor-sampling pass over 6 unnamed lookup-table globals
    (`0x697450/0x697454/0x697468/0x69747c/0x697480/0x697484`, all shown `?` —
    likely per-parity dx/dy hex-direction offset tables) that need naming in
    `global_data_tables` before this one can be ported either.
  - Recommended next step: `class-recovery` skill session dedicated to re-deriving
    TMapMaker's real vtable slot signatures from the raw listings of ALL its
    concrete slot bodies (not just the 3 targets above), since the header's
    existing declarations for at least slots 0xc/0xd/0x10/0x30 (0x30/0x34/0x40 and
    ordinal 0xa) can't be trusted. Don't port these 3 individually without that —
    the shared vtable-slot-0x30 callee needs one correct signature that satisfies
    every call site, or the class model will silently corrupt with each new attempt.

## Known-bad re-ports (score far below structure)

- `0x4f1570` TDiplomacyMgr::InitializeDiplomacyStandingBaselineRandom (landed
  2026-07-17, 75.79%) and `0x4f1630` BuildMajorNationDiplomacyStandingRanking
  (landed 2026-07-17, 71.08%, header signature corrected from a bogus 0-arg void
  to `(int* topNationSlot, int* secondNationSlot)` — verified RET 8, no other
  callers/overrides existed to break). Both structure-verified: real `rand()`
  LIBRARY calls, `g_pGlobalMapState->cityScoreTable`/`comparativePowerRows1824`
  fields, `RecomputeNationComparativePowerMetrics()` call recovered from a
  Ghidra-obscured `func_0x004075ea()` in the decompile (always read the raw
  listing for these, not just the decompile). Residuals in both are pure
  register/induction-variable scheduling (array-index vs pointer-walk choice,
  statement-order-driven store scheduling around a null check) — tried and
  reverted two alternate phrasings that scored worse (65.87%/70.00%); don't
  retry without new evidence. Found nearby but NOT landed: `0x4f0e20`
  RebuildDiplomacyStandingAndInfluenceMatrices (1485B, still fabricated `{}`,
  real signature per func-sig is 2-arg/RET 4 not the header's 0-arg — needs a
  dedicated raw-listing pass, decompile shows lost `unaff_EBX`/`unaff_EBP`
  register tracking).
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
