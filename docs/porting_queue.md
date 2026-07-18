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
  RebuildDiplomacyStandingAndInfluenceMatrices (1485B, still fabricated `{}`).
  **Partial raw-listing decode done 2026-07-18 (no code changed — too large/risky
  to freehand the rest without an interactive disasm/debug loop):**
  - Real signature is **`(char forceOrMode)`, RET 4** — ONE stack byte arg, not
    the previously-guessed 2-arg/RET 4 (that guess was wrong; RET 4 = exactly one
    stack dword slot, and the entry reads a single byte at `[esp+0x100]`).
    `forceOrMode == 2` means "do a full clear": skip on other values.
  - Opening shape (confirmed, verified against symbols.csv slot numbers):
    if `relationCodeMatrix04[0] == 0`, call `this->InitializeDiplomacyStandingBaselineRandom()`
    (slot 0xf/0x3c). If `forceOrMode == 2`, `memset(relationCodeMatrix04, 0,
    sizeof(relationCodeMatrix04))` (0xc0 dwords = exactly `sizeof(short[384])`).
    Then call `this->BuildMajorNationDiplomacyStandingRanking(&topNationSlot,
    &secondNationSlot)` (slot 0x10/0x40, already-correct signature), store the two
    outputs into `selectedSourceNationSlot784`/`selectedTargetNationSlot786`, and
    cache `comparativePowerRows1824[topNationSlot][1]` /
    `comparativePowerRows1824[secondNationSlot][1]` (the "avgRelation" column).
  - First major loop: `for (nationSlot = 0; nationSlot < kNationSlotCount; ++nationSlot)`
    over two stack-local `int[23]` arrays (esp+0x48 and esp+0xa4 — confirmed
    23-entry by the second array ending exactly at esp+0x100, where the byte arg
    starts). Per slot: if `g_apTerrainTypeDescriptorTable[nationSlot] == nullptr`,
    both arrays get `rand() % 50 + 50`. Otherwise branches on the descriptor's
    `short` field at `+0xe` vs 100/200 into (at least) two sub-cases; the
    `bandValue < 100` sub-case is **fully decoded and clean**:
    `arrayA[nationSlot] = (relationStandingScoreMatrix79c[topNationSlot * kNationSlotCount +
    nationSlot] * 100 / 255 + topPower) / 2;` and the mirror for
    `secondNationSlot`/`secondPower` into arrayB — write the plain `/255`, `/2`
    and let MSVC regenerate the `0x80808081` magic-multiply, do NOT hand-roll it.
    The `100 <= bandValue < 200` sub-case reads the descriptor's `+0x88` short as
    a **tile index** into `g_pGlobalMapState`'s terrainStateTable (`+0xc` field,
    36-byte stride confirmed) and compares `.ownerNationTag04` against
    top/secondNationSlot — decode stalled here (index arithmetic got tangled
    between this sub-case and the *outer* per-tile cursor loop reused at
    `[esp+0x24]`; needs a fresh pass with `just ghidra-decompile` cross-checked
    line-by-line against the listing, ideally with the pyghidra decompiler's own
    variable splitting rather than hand-tracking every register).
  - Second major loop (0x4f0f28-0x4f118d, confirmed present but NOT decoded): walks
    a per-tile cursor `[esp+0x24]` in steps of 0xa8 (168 bytes — a DIFFERENT,
    not-yet-identified stride than terrainStateTable's 36; possibly a City or
    Province record) up to 0xfc00 (=384*0xa8), nested inside the `nationSlot`
    loop, writing into `pendingPolicyCodeMatrix304`/`pendingPolicyTierMatrix484`.
  - Third loop (0x4f1193-0x4f11cf): a flat 0x180 (384) -entry short-array walk
    over `pendingPolicyTierMatrix484` doing `rand() % 15`-based fallback fills.
  - Tail (0x4f11cf-end): computes `selectionFlagsA788/B78a/C78c` from
    accumulated counters, conditionally calls two more diplomacy-standing-tier
    vtable slots (0x17/0x2e — `ValidateDiplomacyActionTypeAgainstTargetAndSetRejectCode`
    and `PropagateRelationSideEffectSlot80`, confirmed against the header's slot
    table), sets `lastProcessedNationSlot78e`, and finally — only if
    `g_pSimMgr->field44 == 1` — calls `EmitTurnEvent26DiplomacyMatrixSnapshot()`
    (still a STUB, `src/autogen/stubs/stubs_part016.cpp:472`).
  - **`just ghidra-decompile` cross-check done 2026-07-18 (no code changed — new,
    more serious blocker found, not just density):** the decompile shows
    `topNationSlot`/`secondNationSlot` (Ghidra's `unaff_EBX` and `uStack_f0`) are
    used **throughout the entire ~1000-byte body with no assignment anywhere in
    the function** — Ghidra can't find where EBX gets its value, and `uStack_f0`
    is built via `CONCAT13(param_1 == 2, (undefined3)uStack_f0)`, i.e. it only
    overwrites the TOP byte of a stack slot whose low 3 bytes are read
    unconditionally from *whatever was already there* on entry. A companion
    `undefined4 unaff_EBP` is later reused the same way (`(char)((uint)unaff_EBP
    >> 0x18)`, a flag byte read out of the frame-pointer register). None of this
    is standard `__thiscall` (only ECX is implicit); it means either (a) this
    function is genuinely entered with caller-established EBX/EBP state as a
    hidden custom convention MSVC5 chose for this specific call site, or (b)
    Ghidra's function-boundary/register-parameter recovery is wrong here and the
    real entry point / real signature differs from what's listed. Either way,
    freehand-porting this as a normal `(char forceOrMode)` method would silently
    fabricate a calling convention (exactly what the calling-conventions guardrail
    forbids) — this is not a "too complex, defer" call, it's a "ground truth is
    still unresolved" call.
  - **Recommendation for the next attempt**: before writing any C++, resolve the
    EBX/EBP provenance from the RAW LISTING at the actual call site(s) that reach
    0x4f0e20 (`just ghidra-xrefs 0x4f0e20` for callers, then read the raw
    instructions immediately before each `call` to see what sets ebx/ebp and
    whether it's reloaded from a `this`-relative field right before the call —
    if so, the real fix is likely just adding those two as real parameters/reads
    from member fields rather than mystery registers). Budget a dedicated
    session; the opening ~200 bytes and the `bandValue<100` sub-case above are
    still solid and can
    be reused verbatim.
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
