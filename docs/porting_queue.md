# Porting queue

The shared big-target queue: hardest/biggest stubs and known-bad re-ports, roughly
largest-first. Claim a target by porting it — remove the line in the same commit that
lands the port; append new discoveries at the appropriate spot. Keep entries one line
each with the evidence needed to start (address, size, current score if any, blockers).

## Big stubs (never ported)

- **TMapMaker phase bodies bucket is now fully landed** (all 6 originally-flagged/
  discovered functions ported: `0x526c20`/`0x527040`/`0x527730`/`0x528140`/
  `0x5283c0`/`0x528e50`) — see the class-recovery writeup below. The union-find stub
  pair `0x527300`/`0x5274d0` is now also fully ported (38.05%/37.59%, `just vtable
  TMapMaker` still 100%) — the whole TMapMaker "Big stubs" bucket is closed out.
- **TMapMaker class recovery (landed 2026-07-18, `0x526c20` 0.83% -> 31.82%,
  `0x527040` 1.09% -> 28.14%, `0x527730` ~0% -> 29.58%, `0x528140` ~0% -> 32.95%,
  `0x5283c0` ~0% -> 29.69%, `0x528e50` ~0% -> 15.16%)**: confirmed the systemic
  mismodeling this bucket
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
    neighbor's assigned group, using a previously-undiscovered
    `int groupMemberLists1a8[7][3]` field (-1 terminated, up to 3 member class
    indices per group id), used alongside the already-known `cityRegionNextId1fc`/
    `cityRegionIds200`. **Both bodies now fully ported** (0x527300 38.05%, 0x5274d0
    37.59%; `just vtable TMapMaker` still 100%): 0x527300 (majors-only) tracks
    membership in `groupMemberLists1a8` and fails only on a genuine two-established-
    groups conflict or a full member list; 0x5274d0 (everyone) skips the member-list
    bookkeeping and treats "this class already has a group, neighbor doesn't" as a
    conflict too — a real asymmetry between the two, not a bug.
  - Slot 29/0x74 (`GetAdjacentRegionGridCell`) was re-verified CORRECT as-is
    (2-arg, matches every call site) — Ghidra's own "VTableSlot1D" fallback name for
    it in decompiles of OTHER functions is just an unresolved-symbol artifact, not
    evidence of a problem.
  - Also promoted the previously-undocumented `+0x29c` lone int (queue's old
    "TMapMaker never-ported" note flagged it) to `lastMinorSeedCandidate29c`;
    not yet observed read anywhere, so semantics beyond "reset per attempt" unconfirmed.
  - Slot 18/0x44 (`ForwardParam(int param)`, 1-arg) was really
    `int ForwardParam(int tileIndex, int retryBudget, int featureType)` (verified 3
    stack args from both the caller and Ghidra's own correct 3-param recovery on the
    callee). Recursively lays a linear terrain feature (river/road-shaped): claims
    `tileIndex`, refuses if any hex neighbor is water, randomly perturbs
    `featureType` (0..5, the hex direction), and recurses into that neighbor with
    the ORIGINAL (not perturbed) `featureType` — a real quirk, not a bug, confirmed
    from the raw listing. Renamed conceptually kept as `ForwardParam` (already a
    reasonable name) and fully ported (0x5283c0).
  - Slot 19/0x4c (`DoIdle(int action)`, 1-arg) was really 0-arg (verified: 0 pushes
    at its only call site). Renamed `DoIdle()`.
  - Slot 22/0x58 (`OwnerPanel() -> TView*`, 0-arg) was really
    `int PlaceCityMarkerAndSpreadNeighbors(int tileIndex, int retryBudget, char
    markerVariant)` (verified RET 0xc = 3 stack args, from both Ghidra's own correct
    signature recovery and the self-recursive call inside the callee). Claims
    `tileIndex` (byte 1 + a variant byte at +0x13), refuses if any hex neighbor is
    already a marker (byte 6), spreads to neighbors at 46% each. Renamed and fully
    ported (0x528140).
  - `0x527730` (`MapGenPassSlot0F`) fully ported using the corrected ForwardParam/
    DoIdle/PlaceCityMarkerAndSpreadNeighbors/vmethod_0023 calls: lays mountain-range
    features, spreads hills around them, places city markers, then fills the swamp
    quota (falling back to random-walk placement once the direct-random pass can't
    find room). A shared `ComputeHexAdjacentFullGridTileIndex` static `__inline`
    helper (same hex math as `TMapMgr::ComputeHexNeighborTileIndices` but over
    TMapMaker's own full-resolution 108x60 grid) is used by all of ForwardParam/
    PlaceCityMarkerAndSpreadNeighbors/AssignRegionClassToCellAndNeighbors/
    MapGenPassSlot0F — must stay `__inline` (not plain `static`) or it shows up as
    an unpaired recomp-only symbol under `/Ob1` AND costs ~10pp on every caller
    (confirmed empirically: adding `__inline` raised MapGenPassSlot0F 18.60% ->
    29.58%, OwnerPanel 21.88% -> 32.95%, ForwardParam 27.12% -> 29.69%, with no
    other source change).
  - Slot 17/0x44 (`vmethod_0017(int param)`, 1-arg) was really 0-arg (verified: bare
    `RET` with no operand). Renamed to `SmoothCityRegionOwnershipByNeighborSampling`
    and fully ported (0x528e50, ~0% -> 15.16%): a two-pass ownership-smoothing sweep
    over rows 1..58 of the full-resolution grid — pass 1 erodes tiles with 0-2
    (50%/75% chance) same-owner hex neighbors into a differing neighbor's full
    0x24-byte record when one exists; pass 2 replaces any tile with NO same-owner
    neighbor at all into a uniformly-random neighbor's record. With the union-find
    pair (0x527300/0x5274d0, see above) also landed, the entire "Big stubs" TMapMaker
    bucket is now fully closed out.

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
  retry without new evidence.
- `0x4f0e20` TDiplomacyMgr::RebuildDiplomacyStandingAndInfluenceMatrices (landed
  2026-07-18, 1485B, 0% -> 18.9%). The `unaff_EBX`/`unaff_EBP` that made the
  Ghidra **decompile** look like it depended on an unresolvable hidden calling
  convention were a decompiler artifact, not real: the RAW LISTING shows EBX is
  assigned normally right after the `BuildMajorNationDiplomacyStandingRanking`
  call (topNationSlot, spilled to `[esp+0x14]` and reloaded many times across
  the function — the repeated spill/reload plus an intervening `REP STOSD` is
  what defeated Ghidra's decompiler def-use tracking) and EBP starts zeroed in
  the prologue then gets reassigned mid-function (`LEA EBP,[ESI+0x484]`,
  `&pendingPolicyTierMatrix484[0]`). Real signature is `(char forceOrMode)`,
  verified `RET 4`. Full structure: seed via `InitializeDiplomacyStandingBaselineRandom`/
  `BuildMajorNationDiplomacyStandingRanking`, a per-terrain-descriptor scoring
  loop (`encodedNationSlot` <100 or >199 uses the `relationStandingScoreMatrix79c`
  formula, 100..199 looks up `terrainStateTable[homeRegionIndex].ownerNationTag04`),
  a per-tile (`cityScoreTable`, stride 0xa8) influence-assignment loop using
  `TCountry::IsEncodedNationSlotMinus200Equal` (real vtable slot 0x17, not the
  placeholder "IsDiplomacyTargetClassCode200Match" name) plus a `linkedRegionIds`/
  `secondaryOwnerNationTag18` bonus sub-loop for minor-nation tiles, a random
  fallback-fill pass, and a tail that sets `selectionFlagsA788/B78a/C78c`,
  optionally nudges the losing major nation's AI via
  `g_pSimMgr->IsNationSlotEligibleForEventProcessing` +
  `TGreatPower::SetNationPendingActionStateAndPayload(0xb, -1)`, and — only when
  `g_pSimMgr->field44 == 1` — calls `TMultiplayerMgr::EmitTurnEvent26DiplomacyMatrixSnapshot()`
  (also landed this session, 0x54c480, 8% -> 60.4%: a `TimelyMessageHeader`-based
  packet build+`Send`, reusing the `TurnEvent26DiplomacyMatrixPacket` struct
  already modeled for the receive side at TMultiplayerMgr.cpp:680). Residual on
  the main function is register-allocation/frame-layout noise (`this` pinned in
  ESI vs EBP at different points, stack-slot ordering) — don't chase further
  without new evidence; the two rand-modulo "constant" triage hits (0xf vs 0x32)
  are a pairing-algorithm artifact from two structurally-similar `rand()%N+M`
  call sites, not an actual swapped constant (verified the source has 50 in the
  loop1 fallback paths and 15 in the loop3 fill, matching the raw listing).
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

- TScrollBarView.cpp fabricated empty bodies: `HandleEvent` 0x5747c0,
  `RefreshCityDialogScrollableViewportWithQuickDrawContext` 0x5740a0, and
  `TScrollView::AdjustCityDialogScrollRangeByDeltaAndClamp` 0x573f60 landed
  2026-07-18 (0% -> 84.75% / 100% / 56.79%). The key discovery: `ownerView84`
  (TScrollBarView's cached `ownerContext`) is genuinely a **`TScrollView*`**, not a
  plain `TView*` — confirmed because `TScrollView`'s OWN header already declares
  `TView* contentView60; // 0x60` and `TScrollBarView* scrollBar64; // 0x64`
  (`TScrollView::NoOpUiLifecycleHook` is the only `new TScrollBarView()` call site
  and passes `this` as the `panel`/ownerContext argument) — an exact match for the
  two object-pointer fields `AdjustCityDialogScrollRangeByDeltaAndClamp` reads at
  those offsets. Retyped `ownerView84` and `ConstructTScrollBarViewBaseState`'s
  `panel` parameter to `TScrollView*` (was `TView*`), added a `static_cast` at the
  two `ownerView84 = ownerContext;` assignment sites.
  `AdjustCityDialogScrollRangeByDeltaAndClamp`'s real params are `short` (not
  `int` — confirmed by `movsx word` reads of the stack args), which alone improved
  it 53.42% -> 55.56%. Residual on that one (56.79%) is a branchless
  `max(x,0)`-via-`setl/dec/and` idiom the clean `if(x<0)x=0;` doesn't reproduce,
  plus general register scheduling — tried restructuring the tail clamp to match
  the original's two-early-return/two-epilogue shape exactly and it **regressed
  56.79% -> 35.22%, reverted twice** (with both `int` and `short` param types); the
  clean single-epilogue if/else-if form is empirically better despite looking less
  "structurally faithful" — don't retry that specific restructure without new
  evidence. `HandleEvent`'s residual (84.75%) is a receiver-vs-args
  evaluation-order register choice (tried caching `ownerView84` in a local first,
  no effect, reverted) — not source-steerable.
  `BeginMouseCaptureAndStartRepeatTimer` (0x574830) also landed 2026-07-18 (0% ->
  67.95%): thumb-click passes through to the base `TControl` handler
  (`PtInRect` against `RECT{0, word8c, frameWidth34, word8c+0x12}`); a click above
  or below the thumb plays sound 0x1b58 (`g_pSfxPlaybackSystem->PlaySoundEffect`)
  and pages the content by `±ownerView84->frameHeight38` via
  `AdjustCityDialogScrollRangeByDeltaAndClamp`. Residual is pure register/field-read
  scheduling (tried caching `point->y` in a local to match the original's
  single-read-reused-three-times shape — no measurable effect, compiler already
  CSEs it; kept the cleaner form).
  `DispatchPictureResourceCommand` (0x574d10) also landed 2026-07-18 (0% -> 86.18%
  on the first attempt): reads a `short` at `eventDataB+4` (event type 1 or 2 only)
  and clamps it into `[word88, word8a]`; if it changed, updates `word8c` and calls
  `RefreshCityDialogScrollableViewportWithQuickDrawContext()`; for event type 2 it
  additionally re-derives `contentView60`'s new Y origin from the fraction
  `(word8c-word88)*1024/(word8a-word88)*heightDiff/1024` (same
  `contentView60`/`ownerView84->frameHeight38` heightDiff shape as
  `AdjustCityDialogScrollRangeByDeltaAndClamp`) and calls `CaptureLayoutF0` — the
  vtable slot 0x3c dispatch confirmed to be `contentView60->CaptureLayoutF0`, not a
  new receiver. Residual is a read-order swap (content's vtable-ptr vs
  `ownerLocalX` fetch order) plus an extra short-width truncate/sign-extend our
  codegen adds that the original doesn't — tried extracting the scaled value into
  its own local, no effect, reverted to the simpler inline form.
  `RenderStrategicMapViewportBandsAndBlit_Impl` (0x575080, its callee) landed
  2026-07-18 (0% -> 100%): a trivial 13-byte thiscall — real name/owner is
  **`CDib::GetAbsoluteHeight()`** (`if (biHeight <= 0) biHeight = -biHeight; return
  biHeight;` — the original uses a `test/jg/neg` branch, NOT the `abs()` intrinsic's
  branchless `cdq/xor/sub` idiom; using `abs()` scored only 50%, the explicit branch
  hit 100%). Moved from the autogen stub to `CDib.cpp`/`CDib.h`.
  `ApplyRectSlot110` itself (0x574970, 724B) landed 2026-07-18 (0% -> 22.37%) using
  `just ghidra-decompile 0x574970` to resolve the stack-slot ambiguity the raw
  listing alone left open — the decompile showed there are only TWO local `RECT`s
  (`srcRect`/`dstRect`), reused and re-mutated across all three "band" blocks, not
  three separate pairs as the listing's overlapping-looking offsets suggested.
  Confirmed the function draws the up/down-arrow and thumb bitmaps from a shared
  atlas (`g_pStrategicMapViewSystem->atlas694[5]`, a `TQuickDrawSurfaceContext*`)
  onto `this->surfaceContext90`, via the already-declared
  `TQuickDrawSurfaceContext::GetBlitSurface()` accessor; a final fourth block
  copies the incoming `rectBuffer` parameter into a local `RECT` and blits it
  verbatim between `surfaceContext90` and `g_pActiveQuickDrawSurfaceContext`.
  Magic constants: `0x12c`/`0x13e` (300/318, an 18px-tall sprite row in the atlas),
  `0xfffffd96` (-618) and `-300` as `OffsetRect` deltas, `299` in the thumb band's
  `srcRect.top` formula. Residual (22.37%) is a genuine register-allocation
  difference: the original keeps FOUR values live across the whole function
  (`push ebx/ebp/esi/edi`), ours only needs three (`ebx/esi/edi`) — tried (1)
  literal raw-disassembly field-write order instead of the decompile's presented
  order for the first band's rect init (regressed 22.37%->21.46%, reverted), and
  (2) hoisting `g_pStrategicMapViewSystem->atlas694[5]` into a local `atlas`
  pointer per-band and function-wide (both regressed to 14.78%/15.49%, reverted —
  the original genuinely re-reads the global+field chain at every use, confirmed
  against the decompile's literal re-expansion). Don't retry either without new
  evidence; this is the same "optimizer register-pressure choice you can't force
  from a source tweak" class of residual documented in the codegen-shapes skill.
- `0x574720` TScrollBarView::NoOpUiLifecycleHook at 73.5% — residual is pure
  instruction-scheduling wobble inside the surface-rect block; structure verified.
- `0x5e50c0` at 77.8% — residual is an ecx/eax naming permutation in the slot-cursor
  idiom; structure verified.

- `0x5635e0` TOcean::EnsurePortZoneForTile (landed 2026-07-18, 13.42% -> 30.08%) —
  full re-port from the raw listing (portprep thunk-chase resolved every callee).
  Fixed: (1) the "already exists" check now inlines the GetFirstPortZone/
  GetNextPortZone+field0c/field20/field48 match walk directly (same pattern as
  `RemovePortZoneByTile`), replacing a fictional `TZone::FindPortZoneByTile` call;
  (2) construction now uses real `new TPortZone()` — the EH prologue the original
  has is just the compiler's standard `new`-expression scaffolding (per the
  `ctors-dtors-eh` skill's trivial-ctor-factory note), no special modeling needed
  once `TPortZone::TPortZone()` was moved header-inline to match the original's
  inlining-at-call-site (it was previously out-of-line in the .cpp with no marker,
  forcing a real CALL the original doesn't have); (3) inlined the hex-neighbor
  sea-tile-finding scan and the port/nation-context linking directly, deleting the
  two now-unused free-function abstractions (`FindSeaTileForPortZoneCreation`,
  `LinkPortZoneToContextIfMissing` in TMapMgr.cpp) that had invented a shared
  helper the original never factored out at this call site; (4) added the missing
  `FailNilPointerWithAssert` null-check block (new global
  `s_SourcePathUOcean_006984CC`); (5) fixed a wrong vtable slot at the tail —
  was calling `GetActiveNationSlotTile` (slot 0x14), original calls
  `FindNearestActiveSeaContextTileFromOffset216` (slot 0x13). Residual is
  terrainStateTable-pointer caching strategy (tried removing the local cache
  entirely — regressed to 26.95%; tried widening nationSeed to short to match a
  word-sized cached compare — regressed to 27.73%; both reverted) plus general
  register-allocation noise on a function with 3 nested hex-direction scans.
  Don't retry those two specific changes without new evidence.
- `0x564240` TOcean::RemovePortZoneByTile (landed 2026-07-17, 24.24% -> 61.36%) —
  fixed by inlining the `GetFirstPortZone`/`GetNextPortZone` walk+`IsKindOf`
  filter directly (matching the original, which does NOT call those two real
  methods at this call site despite them existing and being used elsewhere) —
  a same-shape-different-callsite inlining choice, not a modeling error. Residual
  is a minor eax/esi register-copy scheduling difference at the `Free()` call
  tail; tried introducing a named local there and it scored identically, reverted
  to the simpler form.
- `0x510210` TMapMgr::UpdateMapTileAdjacencyMasksAndVariantForTile (28.05%, 1177B) —
  investigated 2026-07-18, no net code change (one experiment tried and reverted).
  Two distinct residual sources found:
  1. The three `for (d=0;d<6;++d)` neighbor-scan loops (adjacencyMaskA0a/B0b
     accumulation) use a SEPARATE down-counting trip register in the original
     (`edi=6; ...; dec edi; jne`) independent of the ascending offset register used
     for indexing (`edx`, +2/iter) — our index-based loop collapses both into one
     register. Tried splitting into an explicit `for (remaining=6;...) {...; ++d;}`
     trip-counter form — **regressed 28.05% -> 24.35%, reverted**; matches the
     codegen-shapes skill's caution that this induction-variable split is often not
     source-steerable. Don't retry that specific rewrite without new evidence.
  2. The `terrainStateTable[tileIndex].gateFlag == 0xb` "gate ring" tag-assignment
     block (source ~line 891-926, disasm 0x510343-0x510419) — **fully instruction-
     traced 2026-07-18** against the raw listing (every CMP/JZ/JNZ from 0x510346 to
     0x510419 walked by hand). Confirmed truth table:
     `prevTag==0xb && nextTag==0xb -> 1`, `prevTag==0xb && nextTag!=0xb -> 2`,
     `prevTag!=0xb && nextTag==0xb -> 3`, else `0`, reached through a genuinely
     tangled shared-label CFG with real dead/redundant re-tests (confirmed dead:
     they can never take the non-fallthrough edge given the branch that reaches
     them). One concrete, previously-wrong detail fixed: the redundant re-test at
     disasm 0x5103e1 compares `neighbors[next]'s gateFlag` against **the `prevTag`
     register (`BL`)**, not the literal constant `0xb` — the old source compared
     against `0xb`, a real (behaviorally-inert, since `prevTag==0xb` is guaranteed
     there, but encoding-different) mismatch. Rewrote the block with `goto`
     labels mirroring the disasm's shared blocks 1:1 (`check_prevb`/`check_pb_nb`/
     `check_pb2`/`check_next3`) including the corrected register-vs-immediate
     compare. **Result: 28.05% -> 27.94%, a wash** — build+compare shows the
     compiler fully reschedules/merges the four `spriteVariantIndex01 = N; continue`
     stores into one cluster regardless of source block order (goto-label order vs
     if/else order made no difference in a quick check), so this specific residual
     really is compiler block-layout scheduling, not source-steerable, confirming
     the original session's caution. Kept the `goto` rewrite anyway since it's a
     strictly more accurate model of the real semantics (proven by the disasm
     trace) at no cost. Don't re-attempt this specific block without new evidence
     beyond "reorder the same logic" — point 1's trip-counter register split is a
     more promising unexplored angle for this function if revisited.
- `0x550b60` TShip::ComputeOrderNodeCompositeEconomicScore at 68% — residual is
  scheduling wobble around the inlined /100 and /10 magic divisions; revisit only
  with new evidence.
- `0x54ff00` TShip::ComputeNavyOrderPriorityContributionPercentByCategory (landed
  2026-07-18, 46.61% -> 69.95%): the `SignedMod100`/`SignedDiv10` helpers were
  hand-rolled `__int64` reimplementations of the magic-number division sequences —
  the original computes both `field30/100` and `quantityTerm/10` as plain **native
  32-bit** `IMUL`+shift (no `__allmul`/`__allshr` calls); the `__int64` casts forced
  genuine 64-bit multiply-helper calls that don't exist in the original, cascading
  into a completely different register allocation for the whole function (divisor
  landed in EBP/EBX instead of EDI). Fixed by replacing both helpers with plain
  `value / 100` / `value / 10` and letting the compiler re-derive the magic
  constants natively. Also fixed `descriptor.resolveWeight * 10`: the original reads
  that field as a **full raw dword** (`resolveWeight`+`pad02` combined, pad is
  always 0 in the static table so the value matches, but the codegen needs the wide
  read) via `*reinterpret_cast<const int*>(&descriptor.resolveWeight)`, the same
  idiom already used in `TNavyMgr::InitializeNavyOrderPriorityTables` — plain
  `descriptor.resolveWeight` compiles to a narrower `movsx` load and mismatches.
  Residual (69.95%) is the *36-stride pointer arithmetic: original computes the
  table pointer once via `LEA+SHL` in one register reused for both field reads;
  our compiler folds the `*4` into each load's SIB addressing mode separately —
  a compiler-internal choice, not source-steerable (tried caching `weight`
  variable removal and reordering `stockLevel1c` read — no measurable effect,
  reverted to the cleaner form). Same underlying `resolveWeight`-as-dword bug also
  found and fixed in the sibling `TTaskForce::CalculateMissionOrderPriorityScore`
  (0x5501b0, 45.58% -> 54.21%) — that one's residual is a whole-function
  register-allocation cascade from whether `this` gets cached across the loop;
  tried moving the per-case `desc` lookup inside each switch case to match the
  original's per-case re-derivation (matching the raw listing exactly) and it
  **regressed to 40.37%** — reverted, don't retry without new evidence.

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
