# Imperialism Decomp Control Plane

Last updated: 2026-03-03

## Purpose
This file is the single source of truth for:
1. Current matching strategy.
2. Current baseline metrics.
3. Exact commands that define the pipeline.
4. Active scope filters (what we are intentionally ignoring).

## Current Strategy
1. Keep Ghidra as source of truth for symbols/types/comments.
2. Export full snapshots to repo (`symbols`, decomp bodies, type headers).
3. Build with old MSVC toolchain in Docker/Wine.
4. Track two metric views:
   1. Full compare (all functions).
   2. Focused compare (runtime/library-heavy symbols ignored in `report.ignore_functions`).
5. For promoted thunk windows, prefer build-safe incremental ownership:
   1. compile-safe direct body for one function,
   2. targeted `just compare 0xADDR`,
   3. move on if score stays `0%`.

Latest incremental checkpoint (`2026-03-03 11:24 UTC`):
1. Introduced typed vcall facade workflow for `TGreatPower`:
   1. new slot registry: `config/vtable_slots.csv`,
   2. new runtime cast-isolation helper: `include/game/vcall_runtime.h`,
   3. new generated wrappers: `include/game/generated/vcall_facades.h`,
   4. new generator: `tools/workflow/generate_vcall_facades.py`,
   5. new command: `just gen-vcall-facades`.
2. Refactored high-density helper region in `src/game/TGreatPower.cpp` from local typedef/cast vtable blocks to generated vcall wrappers + runtime helpers.
3. Pattern count in `src/game/TGreatPower.cpp`:
   1. `typedef .*Fn|reinterpret_cast<.*Fn|vftable[` reduced from `281` to `150`.
4. Verification:
   1. `just build`: success,
   2. `just detect`: success,
   3. `just stats`: aligned `92`, average similarity `2.88%`.
5. Touched-address spot checks:
   1. `0x00406FE1`: `0.00%`
   2. `0x004DBD20`: `12.40%`
   3. `0x004DC540`: `42.18%`

Latest incremental checkpoint (`2026-03-03 11:43 UTC`):
1. Second vcall-facade reduction batch in `src/game/TGreatPower.cpp`:
   1. migrated additional class slot calls (`0x21`, `0x6C`, `0x66`, `0x45`, `0x64`, `0x5F`, `0x69`,
      `0x6A`, `0x1D`, delete slot `1`) to generated wrappers,
   2. removed the corresponding local `TGreatPower` vtable typedef blocks/casts in affected methods.
2. Registry/generator updates:
   1. `config/vtable_slots.csv` expanded and regenerated (`just gen-vcall-facades`) to `65` wrappers.
3. Pattern count in `src/game/TGreatPower.cpp`:
   1. `typedef .*Fn|reinterpret_cast<.*Fn|vftable[` reduced from `150` to `123`.
4. Verification:
   1. `just build`: success,
   2. `just detect`: success,
   3. `just stats`: aligned `92`, average similarity `2.88%`.
5. Touched-address spot checks:
   1. `0x00406FE1`: `0.00%`
   2. `0x004DBD20`: `14.01%` (up from `12.40%`)
   3. `0x004DC540`: `42.18%`

Latest incremental checkpoint (`2026-03-03 11:52 UTC`):
1. Third vcall-facade cleanup slice:
   1. replaced raw vtable calls in:
      1. `DispatchTurnEvent2103WithNationFromRecord` (`ui slot 0x4C/4`),
      2. `QueueDiplomacyProposalCodeWithAllianceGuards` (`diplomacy slot 0x60/4`).
   2. added/regen wrappers:
      1. `VCall_UiRuntime_DispatchEventSlot4C`,
      2. `VCall_Diplomacy_HasAllianceGuardSlot60`.
2. Pattern count in `src/game/TGreatPower.cpp`:
   1. `typedef .*Fn|reinterpret_cast<.*Fn|vftable[` reduced from `123` to `119`.
3. Verification:
   1. `just build`: success,
   2. `just detect`: success,
   3. `just stats`: aligned `92`, average similarity `2.88%`.
4. Touched-address checks:
   1. `0x004DF5C0`: `20.69%`
   2. `0x004E7B50`: `25.97%`

Latest incremental checkpoint (`2026-03-03 03:57 UTC`):
1. `TGreatPower` shape pass for low performers:
   1. `0x005C2940` (`InitializeCivWorkOrderState`) moved from `0%` to `90.91%` by restoring register-and-clear flow (`+0x24/+0x26`) and owner-manager registration call shape.
   2. `0x00601F1D` (`CPtrList`) remains `0%`; current mismatch indicates calling-convention/register ordering is still off relative to original.
2. Promoted and landed three non-trivial quarterly status dispatch bodies:
   1. `0x004E00D0` (`12.12%`)
   2. `0x004E0140` (`12.12%`)
   3. `0x004E01B0` (`9.23%`)
3. Descriptor getter shape improved:
   1. `0x004D89D0` now at `50.00%`.
4. Stability anchor held:
   1. `0x004EA470`: `100%`.
5. Snapshot (`just stats`, `2026-03-03T03:56:57Z`):
   1. aligned functions: `93`
   2. not aligned vs original: `12880`
   3. average similarity: `2.91%`

Latest incremental checkpoint (`2026-03-03 04:22 UTC`):
1. Existing-code readability and typing pass in `TGreatPower`:
   1. replaced remaining local `pad` accesses with typed fields (`field8b7_scenarioInitFlag`, `field8d4_expansionEventGate`),
   2. introduced reusable typed helpers for list/object/relation-manager/secondary-state virtual slots,
   3. applied helper cleanup across existing functions only (no new ownership promotions),
   4. moved turn-summary queue path (`0x004E2B70`) to shared helpers and typed localization tick accessor.
2. Score guardrail applied:
   1. a readability variant of `0x004DBD20` regressed, so the loop/data shape was restored to recover the previous score.
3. Key targeted snapshot after cleanup:
   1. `0x004DC9F0`: `48.98%`
   2. `0x004DCD10`: `25.21%`
   3. `0x004E22B0`: `18.18%`
   4. `0x004E2500`: `24.16%`
   5. `0x004DBD20`: `17.12%`
   6. `0x004DD310`: `82.76%`
   7. `0x004E2B70`: `14.04%`
4. Snapshot (`just stats`, `2026-03-03T04:22:00Z`):
   1. aligned functions: `92`
   2. not aligned vs original: `12881`
   3. average similarity: `2.90%`

Latest incremental checkpoint (`2026-03-03 04:49 UTC`):
1. Landed subsystem adapter refactor batches in `TGreatPower.cpp` (cpp-only):
   1. added generic object/stream/list/global-map adapters to remove repeated vtable boilerplate,
   2. rewired priority large functions to use those adapters while preserving function ownership and marker placement.
2. Priority-function impact:
   1. `0x004D92E0` improved to `29.96%` (from low-20s baseline before this batch),
   2. `0x004DBF00` improved to `29.14%`,
   3. `0x004DE860` improved to `26.83%`,
   4. `0x004D9160` moved down to `31.19%` (accepted for this readability/adapter consolidation pass),
   5. `0x004E8540`, `0x004D8CC0`, `0x004DDFC0`, `0x004DF010` remained stable.
3. Adjacent cleanup landed:
   1. shared-ref triplet helpers for proposal paths,
   2. queue push/write paths switched to shared adapters,
   3. terrain/list accessor normalization via shared pointer helpers.
4. Snapshot (`just stats`, `2026-03-03T04:49:00Z`):
   1. aligned functions: `92`
   2. not aligned vs original: `12881`
   3. average similarity: `2.90%`

Latest incremental checkpoint (`2026-03-03 04:03 UTC`):
1. Existing-code cleanup (no new promoted addresses):
   1. replaced repeated cast-heavy slot calls with reusable typed helper wrappers (`A1`, `2E`, `84`, `85`, `A8`, `A9`, `B3`),
   2. exposed localization quarter-gate tick as typed field (`quarterGateTick2c`) in `TLocalizationRuntimeView`.
2. Key note:
   1. `__forceinline` is not accepted by this VC5 setup in this file; keep helper wrappers on `static __inline`.
3. Targeted function scores in the cleaned region:
   1. `0x004E22B0`: `17.86%`
   2. `0x004E2330`: `33.49%`
   3. `0x004E27B0`: `25.81%`
   4. `0x004E7C50`: `50.00%`
   5. `0x004E9ED0`: `76.47%`
   6. `0x004EA150`: `65.31%`
4. Snapshot (`just stats`, `2026-03-03T04:02:34Z`):
   1. aligned functions: `91`
   2. not aligned vs original: `12882`
   3. average similarity: `2.94%`

Latest incremental checkpoint (`2026-03-03 04:04 UTC`):
1. Existing-code typing pass in `ApplyNationResourceNeedTargetsToOrderState`:
   1. introduced `TRelationManagerNeedRefreshView`,
   2. replaced raw `+0xE0/+0xE2` relation-manager writes with typed fields.
2. Targeted check:
   1. `0x004DCD10`: `38.33%` (still mismatch-heavy but cleaner structure).
3. Snapshot (`just stats`, `2026-03-03T04:04:16Z`):
   1. aligned functions: `93` (recovered from `91`)
   2. not aligned vs original: `12880`
   3. average similarity: `2.91%`

Latest incremental checkpoint (`2026-03-03 04:06 UTC`):
1. Existing-code typed-view cleanup:
   1. replaced `+4` list-sentinel arithmetic with `TRefCountedListOwnerView::listSentinel`,
   2. replaced terrain descriptor `+0x90` access with `TTerrainDescriptorLinkedNodesView::linkedNodeList`.
2. Snapshot (`just stats`, `2026-03-03T04:05:51Z`):
   1. aligned functions: `93`
   2. not aligned vs original: `12880`
   3. average similarity: `2.91%`

Latest incremental checkpoint (`2026-03-02 19:06 UTC`):
1. `TGreatPower` large-body ownership pass:
   1. `0x004D8CC0` `InitializeNationStateRuntimeSubsystems`: first-pass real body landed at `32.14%`.
   2. `0x004D9160` `ReleaseOwnedGreatPowerObjectsAndDeleteSelf`: first-pass real body landed at `37.38%`.
2. Wrapper stability:
   1. `0x00405DE4` stayed at `100.00%` after redirecting through the newly owned `0x004D9160` method.
3. Control loop reminder:
   1. after adding a new manual `// FUNCTION` address, run `just sync-ownership && just regen-stubs` before compare to avoid duplicate-address diffing against stubs.
4. Current anchor snapshot in this class:
   1. `0x004D8CC0`: `32.14%`
   2. `0x004D9160`: `37.38%`
   3. `0x004DE860`: `26.16%`
   4. `0x004DF5F0`: `9.49%`
   5. `0x00405DE4`: `100.00%`
5. Aggregate metrics (`just stats`):
   1. aligned functions: `90`
   2. average similarity: `2.73%`
   3. status: stalled globally, but local class ownership and non-zero body coverage increased.

Latest incremental checkpoint (`2026-03-03 03:15 UTC`):
1. `TGreatPower` ownership expansion (6 addresses):
   1. `0x004D8950` `CreateTGreatPowerInstance` (`25.00%`)
   2. `0x004D89D0` `GetTGreatPowerClassNamePointer` (`0.00%`)
   3. `0x004DAF30` `CompileGreatPowerRelationshipDeltaLinesAndDispatchMessage` (`13.86%`)
   4. `0x004DB380` `UpdateGreatPowerPressureStateAndDispatchEscalationMessage` (`12.24%`)
   5. `0x004DCF10` `IsNationResourceNeedCurrentSumExceedingCapA6` (`43.90%`)
   6. `0x004E2B70` `BuildGreatPowerTurnMessageSummaryAndDispatch` (`13.45%`)
2. Added the required legacy global helper body for `GetTGreatPowerClassNamePointer` to keep older call-throughs linkable after stub ownership transfer.
3. Loop guardrail confirmed:
   1. always run `just sync-ownership && just regen-stubs` after manual marker updates to avoid duplicate-address compare drift.
4. Snapshot (`just stats`, `2026-03-03T00:37:37Z`):
   1. aligned functions: `93`
   2. not aligned vs original: `12880`
   3. average similarity: `2.86%`

Latest incremental checkpoint (`2026-03-03 03:40 UTC`):
1. `TGreatPower` ownership expansion (additional 6 addresses):
   1. `0x004E72C0` `InitializeMapActionCandidateStateAndQueueMission` (`17.95%`)
   2. `0x004E9A50` `SelectAndQueueAdvisoryMapMissionsCase16` (`14.75%`)
   3. `0x004EA300` `MarkNationPortZoneAndLinkedTilesForActionFlag` (`20.69%`)
   4. `0x00540AC0` `QueueDiplomacyProposalCodeForTargetNationAndDispatchTurnEvent16` (`26.09%`)
   5. `0x005416B0` `ApplyClientGreatPowerCommand69AndEmitTurnEvent1E` (`11.11%`)
   6. `0x0055F140` `ComputeMapActionContextNodeValueAverage` (`20.45%`)
2. `0x004EA470` remained stable at `100%` after this promotion batch.
3. Snapshot (`just stats`, `2026-03-03T03:40:13Z`):
   1. aligned functions: `93`
   2. not aligned vs original: `12880`
   3. average similarity: `2.87%`

Latest incremental checkpoint (`2026-03-02 22:40 UTC`):
1. `TGreatPower` grant-path ownership expansion:
   1. `0x004DE5E0` (`RevokeDiplomacyGrantForTargetAndAdjustInfluence`) promoted and converted to compile-safe member body (`32.35%`).
   2. `0x004DE700` (`CanAffordDiplomacyGrantEntryForTarget`) promoted and converted (`47.46%`).
   3. `0x004DE790` (`CanAffordAdditionalDiplomacyCostAfterCommitments`) promoted and converted (`65.12%`).
2. Regression anchors held after promotion pass:
   1. `0x004DF5F0`: `30.15%`
   2. `0x004DF010`: `12.79%`
   3. `0x004DDFC0`: `19.94%`
3. Required workflow ordering remains:
   1. after each `just promote`, run `just sync-ownership && just regen-stubs && just build` before compare.
4. Global signal from `just stats`:
   1. aligned functions `90` (unchanged),
   2. average similarity `2.76%` (`+0.01pp`).

Latest incremental checkpoint (`2026-03-02 22:44 UTC`):
1. Existing-code tuning pass (no new promotions):
   1. `0x004DE700` improved from `47.46%` to `59.74%` using closer arithmetic/cast shape.
   2. `0x004DE790` bitmask-clamp probe regressed (`65.12%` -> `61.22%`) and was reverted to keep `65.12%`.
2. Adjacent anchors stayed stable:
   1. `0x004DE5E0`: `32.35%`
   2. `0x004DF5F0`: `30.15%`
3. Loop guidance reinforced:
   1. keep probing one function at a time,
   2. keep regressions only when there is a net gain or readability benefit,
   3. otherwise revert immediately and move on.

Latest incremental checkpoint (`2026-03-02 22:47 UTC`):
1. Existing-function cleanup pass:
   1. `0x004DE5E0` improved from `32.35%` to `33.00%` by removing non-original null guards and using signed `<= 0` gate on masked grant value.
   2. `0x004DE700` remained at `59.74%`.
   3. `0x004DE790` remained at `65.12%`.
2. No local regressions observed on checked anchor:
   1. `0x004DF5F0`: `30.15%`.

## Current Baseline
From latest fresh import + rebuild + reccmp run:

1. Inventory:
   1. Functions in `config/symbols.csv`: `12230`.
   2. Globals in `config/symbols.csv`: `4935`.
   3. Decompiled bodies: `12230` functions in `455` files.
   4. Exported type headers: `17` headers, `595` types.
2. Build:
   1. Recompiled functions discovered: `12288`.
   2. Paired with original: `12229` (100% coverage).
3. Similarity:
   1. Full compare avg similarity: `1.13%`.
   2. Focused compare avg similarity (with ignores): `1.32%`.
   3. 100% aligned functions: `42`.

Latest `progress_stats` snapshot (`2026-02-24T15:08:48Z`):
1. Paired functions: `12228` (coverage `100%`).
2. Recompiled functions discovered: `12511`.
3. 100% aligned functions: `60`.
4. Average similarity (current compare set): `2.56%`.
5. Paired globals (`dat/lab/str/flo/wid`): `272 / 5065` (coverage `5.37%`).
6. Non-function coverage including imports: `5.77%`.

Latest `progress_stats` snapshot (`2026-02-24T20:41:48Z`):
1. Paired functions: `12228` (coverage `100%`).
2. Recompiled functions discovered: `12514`.
3. 100% aligned functions: `60`.
4. Average similarity (current compare set): `2.56%`.
5. Paired globals (`dat/lab/str/flo/wid`): `272 / 5065` (coverage `5.37%`).
6. Non-function coverage including imports: `5.78%`.

Latest `progress_stats` snapshot (`2026-02-24T20:58:45Z`):
1. Paired functions: `12228` (coverage `100%`).
2. Recompiled functions discovered: `12520`.
3. 100% aligned functions: `60`.
4. Average similarity (current compare set): `2.57%`.
5. Paired globals (`dat/lab/str/flo/wid`): `272 / 5065` (coverage `5.37%`).
6. Non-function coverage including imports: `5.78%`.

Latest incremental checkpoint (`2026-03-02`):
1. `TGreatPower` promoted thunk window pass in `src/game/TGreatPower.cpp`:
   1. retained direct typed first-pass bodies for:
      1. `0x00405DE4`
      2. `0x00406B2C`
      3. `0x00406C49`
      4. `0x00406C9E`
   2. kept remaining promoted wrappers compile-safe placeholders in this iteration.
2. Build loop status:
   1. `just build` succeeded after removing unresolved call-through targets.
   2. `just detect` succeeded.
3. Targeted results in this pass:
   1. `0x00405DE4`: `0.00%`
   2. `0x00406B2C`: `0.00%`
   3. `0x00406C49`: `0.00%`
   4. `0x00406C9E`: `0.00%`
4. Anchors remained stable:
   1. `0x004DDA90`: `26.67%`
   2. `0x004DDBB0`: `37.89%`
   3. `0x004E8540`: `42.86%`
   4. `0x004E8750`: `34.25%`

Latest incremental checkpoint (`2026-03-02`, zero-cleanup):
1. `TGreatPower` thunk-cluster zero pass in `src/game/TGreatPower.cpp`:
   1. `0x00404A9D` `ReplyToDiplomacyOffers`: `100%`
   2. `0x00405DE4` `TGreatPower_VtblSlot07`: `100%`
   3. `0x00406B2C` `thunk_RemoveRegionIdAndRunTrackedObjectCleanup_At00406b2c`: `100%`
   4. `0x00406C49` `thunk_ClearFieldBlock1c6_At00406c49`: `100%`
   5. `0x00406C9E` `thunk_ResetNationDiplomacySlotsAndMarkRelatedNations_At00406c9e`: `100%`
2. Key implementation note:
   1. thunk wrappers needed direct symbol calls with stub-compatible return signatures (`undefined4`) to keep MSVC decorated names/link resolution aligned.
3. Stability checks after the pass:
   1. `0x004DDA90`: `26.67%`
   2. `0x004DDBB0`: `37.89%`
   3. `0x004E8540`: `42.86%`
   4. `0x004E8750`: `34.25%`

Latest incremental checkpoint (`2026-03-02 18:20 UTC`):
1. `TGreatPower` dual-address side-effects pass:
   1. `0x0040862A` kept as thunk entrypoint (`thunk_ApplyImmediateDiplomacyPolicySideEffects_At0040862a`).
   2. `0x004DEDF0` now owns the first-pass real body (`ApplyImmediateDiplomacyPolicySideEffects`).
2. `0x004E9060` shape/data pass retained:
   1. advisory-factor thunk now forwarded with 4 args including selected-candidate slot,
   2. relationship-list init + `+0x2c` call shape corrected to current best scoring form.
3. Current targeted scores:
   1. `0x004E9060`: `30.99%`
   2. `0x004DEDF0`: `19.93%`
   3. `0x004E7B50`: `29.73%`
   4. `0x004E7C50`: `50.00%`
   5. `0x004DEFD0`: `29.63%`
   6. `0x004083F5`: `100%`
   7. `0x0040862A`: `0.00%`
   8. `0x004DDFC0`: `25.77%`
   9. `0x004DC9F0`: `100%`
4. Required guardrail in this flow:
   1. run `just sync-ownership && just regen-stubs` immediately after adding new manual `// FUNCTION` markers to avoid dropped-duplicate-address compare errors.

Latest `progress_stats` snapshot (`2026-03-02T18:28:51Z`):
1. Paired functions: `12973` (coverage `100%`).
2. Recompiled functions discovered: `13064`.
3. 100% aligned functions: `88`.
4. Average similarity (current compare set): `2.70%`.
5. Paired globals (`dat/lab/str/flo/wid`): `280 / 5073` (coverage `5.52%`).
6. Non-function coverage including imports: `5.91%`.

Latest `progress_stats` snapshot (`2026-02-25T00:14:43Z`):
1. Paired functions: `12228` (coverage `100%`).
2. Recompiled functions discovered: `12520`.
3. 100% aligned functions: `60`.
4. Average similarity (current compare set): `2.58%`.
5. Paired globals (`dat/lab/str/flo/wid`): `272 / 5067` (coverage `5.37%`).
6. Non-function coverage including imports: `5.78%`.

Latest incremental checkpoint (`2026-02-24 21:25 UTC`):
1. `0x0058F3C0` `UpdateCivilianOrderTargetTileCountsForOwnerNation`: `24.88% -> 30.77%`.
2. Retained shape change:
   1. inner 5-slot loop switched to decrement-counter form (`remainingSlots`), which matched original `dec/jne` loop shape better.
3. Reverted probes in same pass:
   1. `/Oy`-style build probe (`/Oy,/Ob1`) regressed this function.
   2. local-pressure rewrite removing `mapState`/`tableBase` regressed this function.

Latest incremental checkpoint (`2026-02-24 21:45 UTC`):
1. `0x0058F3C0` `UpdateCivilianOrderTargetTileCountsForOwnerNation`: improved to `97.98%`.
2. High-impact retained changes:
   1. function-local `#pragma optimize("y", on)` around this function.
   2. province gate shape `if (provinceCount < provinceOrdinal) return;` with `provinceOrdinal = 1`.
   3. cast/sign-extension alignment for tile index/profile (`(short)` -> `(int)(short)` chain, signed-byte profile to `short`).
3. Notes:
   1. a C-linkage symbol probe for table globals regressed this function (`97.98% -> 96.97%`) and was reverted.

Latest incremental checkpoint (`2026-02-25 00:09 UTC`):
1. `0x0058F550` `RefreshCivilianTargetLegendBySelectedClass`: `16.11% -> 18.34%`.
   1. retained forwarded payload shape into slots `+0x1A0/+0x1A4/+0x1A8`,
   2. retained early shared-string init and pointer-driven legend reset loop.
2. `0x0058F1A0` `DestructTCivDescriptionAndMaybeFree`: `17.14% -> 18.50%`.
   1. retained virtual `GetCount/GetByOrdinal` province collection calls,
   2. retained pointer-driven outer legend-counter walk.
3. Stability checks:
   1. `0x0058F3C0`: still `97.98%`.
   2. `0x0058F110`: still `69.39%`.
   3. direct-access rewrite probe on `0x0058F110` regressed to `53.06%` and was reverted.
4. Remaining low-score owned functions in this cluster:
   1. `0x0058F7B0`: `0.00%`.
   2. `0x0058FEC0`: `0.00%`.

Latest incremental checkpoint (`2026-02-25 00:14 UTC`):
1. `0x0058F7B0` `RenderCivilianTargetLegendVariantA`: `0.00% -> 25.25%`.
2. `0x0058FEC0` `RenderCivilianTargetLegendVariantB`: `0.00% -> 16.81%`.
3. Stability checks:
   1. `0x0058F3C0`: still `97.98%`.
   2. `0x0058F550`: still `18.34%`.
4. Current owned legend-cluster stack:
   1. `0x0058F3C0`: `97.98%`
   2. `0x0058F110`: `69.39%`
   3. `0x0058F7B0`: `25.25%`
   4. `0x0058F550`: `18.34%`
   5. `0x0058F1A0`: `18.50%`
   6. `0x0058FEC0`: `16.81%`

Latest incremental checkpoint (`2026-02-25 01:53 UTC`):
1. `0x0058F1A0` `DestructTCivDescriptionAndMaybeFree`: `20.87% -> 22.22%`.
   1. retained virtual province collection call shape and pointer-based legend-counter walk.
   2. removed outer-loop `candidateOrdinal++` on slot-advance path.
2. `0x0058F3C0`: retained `97.98%`.
   1. restored `CivilianClassCacheContext` typed target-count slots and `#pragma optimize("y", on)` around this function.
3. `0x0058F550`: currently `16.11%` in this branch state.

Latest incremental checkpoint (`2026-02-24 20:56 UTC`):
1. Promoted and owned `TCivDescription` legend block addresses:
   1. `0x0058F550` `RefreshCivilianTargetLegendBySelectedClass` (`0.00%`, first-pass thunk bridge).
   2. `0x0058F7B0` `RenderCivilianTargetLegendVariantA` (`0.00%`, first-pass thunk bridge).
   3. `0x0058FEC0` `RenderCivilianTargetLegendVariantB` (`0.00%`, first-pass thunk bridge).
2. Kept compile stability by converting raw class-scoped promoted bodies to compile-safe wrapper form and flipping stub markers to `MANUAL_OVERRIDE_ADDR`.

Latest incremental checkpoint (`2026-02-24 20:58 UTC`):
1. Promoted and owned `0x00590CB0` `BuildCivReportNationEntryDetailTextBlock` in `src/game/TCivReport.cpp`.
2. First-pass compile-safe bridge result: `16.67%` (`just compare 0x00590cb0`).
3. Stub marker at `src/autogen/stubs/stubs_part018.cpp` flipped to `MANUAL_OVERRIDE_ADDR`.

Latest incremental checkpoint (`2026-02-24 21:07 UTC`):
1. `0x0058F550` `RefreshCivilianTargetLegendBySelectedClass`: `0.00% -> 16.11%` after replacing thunk-forward body with real legend reset + class dispatch + localized text draw path.
2. Adjacent `TCivDescription` checks stayed stable in the same pass:
   1. `0x0058F1A0`: `17.14%`
   2. `0x0058F3C0`: `24.88%`
3. Reverted one regressing variant on `0x58F550` (`16.11% -> 15.53%`) and kept the higher-scoring shape.

Latest incremental checkpoint (`2026-02-24 20:38 UTC`):
1. `0x0058F3C0` `UpdateCivilianOrderTargetTileCountsForOwnerNation`: `24.88%` after direct fixed-address global/vtable-slot shape pass in `src/game/TCivDescription.cpp`.
2. `0x0058F1A0` `DestructTCivDescriptionAndMaybeFree`: `17.14%` first-pass ownership in `src/game/TCivDescription.cpp`.
3. `0x0058F110` `UpdateCivilianOrderClassAndRefreshTargetCounts`: retained `69.39%` (short-width class-id shape restored).

Latest incremental checkpoint (`2026-02-24 15:08 UTC`):
1. `0x0058E1C0` `HandleMapContextActionArmyRatioAndModeCommands`: `24.60%` first-pass ownership in `src/game/TArmyToolbar.cpp`.
2. `0x0058EED0` `HandleCivilianMapCommandPanelAction`: `44.98%` first-pass ownership in `src/game/TCivToolbar.cpp`.
3. `0x0058F050` `CreateTCivDescriptionInstance`: `42.86%` first-pass ownership in new `src/game/TCivDescription.cpp`.
4. `0x0058F0F0` `GetTCivDescriptionClassNamePointer`: `50.00%` first-pass ownership in new `src/game/TCivDescription.cpp`.
5. `0x0058F110` `UpdateCivilianOrderClassAndRefreshTargetCounts`: `69.39%` after short-width class-id shape pass in `src/game/TCivDescription.cpp`.
6. `0x0058E440` `OrphanTiny_SetDwordEcxOffset_60_0058e440`: `33.33%` first-pass ownership in `src/game/ui_widget_wrappers.cpp` (prologue-shape tuning deferred).

Latest incremental checkpoint (`2026-02-24 14:09 UTC`):
1. `0x00587130` `InitializeTradeSellControlState`: `41.52%` after restoring explicit stack-seed forwarding (`ret 4` shape).
2. `0x0058BC60` `PlacardState::RenderPlacardValueTextWithShadow`: `55.62%` after replacing placeholder body with full shared-string + themed two-pass text draw flow.
3. `0x00588B70` `SyncTradeCommoditySelectionWithActiveNationAndInitControls`: `42.50%` current retained shape.

Latest incremental checkpoint (`2026-02-24 14:35 UTC`):
1. `0x005873E0` `HandleTradeSellControlCommand`: restored to `23.68%` baseline shape after reverting a regressing gate/default experiment.
2. `0x00587DD0` `SetTradeOfferControlBitmapState`: improved to `52.21%` by caching resolver slot `+0x94` and preserving call-order/layout capture shape.
3. `0x00588030` `SetTradeOfferSecondaryBitmapState`: improved to `42.31%` with `{0xA3,0}` layout capture and enabled/state ordering, while keeping direct `ResolveControlByTag` lookups.

## Active Ignore Scope
Generated by `python -m tools.reccmp.generate_ignore_functions` and applied to `reccmp-project.yml`:

1. `report.ignore_functions`: `2606` function names.
2. Source buckets used:
   1. `crt_likely`
   2. `mfc_likely`
   3. `directx_audio_net_likely`

Notes:
1. `report.ignore_functions` is name-based.
2. `ghidra.ignore_functions` is address-based and is currently not auto-applied in project config.

## Canonical Commands
### 1) Full Ghidra sync
```bash
just sync-ghidra
```

### 2) Sync function ownership map
```bash
just sync-ownership
```

### 3) Regenerate stubs
```bash
just regen-stubs
```

### 4) Annotate globals from symbols
```bash
just annotate-globals
```

### 5) Annotate vtables from symbols
```bash
just annotate-vtables
```

### 6) Normalize marker formatting
```bash
just normalize-markers
```

### 7) Rebuild (Docker rootless-safe mode)
```bash
just build
```

### 8) Detect + compare
```bash
just detect
just compare
```

### 9) Progress summary
```bash
just stats
```
This summary tracks both function metrics and non-function roadmap coverage (globals/data/labels/strings/floats/wide strings/imports).

### 10) Inventory and ignore generation
```bash
uv run python -m tools.reccmp.library_inventory --json-out build-msvc500/library_inventory.json
uv run python -m tools.reccmp.generate_ignore_functions --target IMPERIALISM --apply
```

### 10) Session queue generation
```bash
uv run python -m tools.reccmp.session_loop --target IMPERIALISM --pick 8 --top 50 --min-size 1
```

### 11) Range-based promotion
```bash
just promote-range src/game/trade_screen.cpp 0x00585f70 0x00586150
```

## Known Pitfalls
1. Ghidra decompiler output is generated on-demand; full sync re-decompiles functions.
2. Single huge `stubs.cpp` breaks old MSVC linker/debug limits; use chunked stubs in `src/autogen/stubs/`.
3. Rootless Docker networking may fail with bridge mode; use `--network none` for `docker run`.
4. Two unresolved thunk callees are currently handled by local placeholders in `src/game/thunks.cpp`.
5. Match-flag plumbing accepts both old slash format (`/Oy-/Ob1`) and CSV format (`/Oy-,/Ob1`); use CSV in commands for clarity.
6. Keep reccmp marker syntax exact (`// TYPE: MODULE 0x...` lowercase hex) and keep pseudo markers non-reccmp (`// MANUAL_OVERRIDE_ADDR ...`, `// PROMOTED_FUNCTION ...`) to avoid parser noise.
7. Run `just compare` and `just stats` sequentially; parallel runs can trigger Wine `winedbg`/`cvdump` contention and produce false temporary regressions.

## Current Priorities
1. Keep focused ignore list stable and review weekly.
2. Move from wrapper/thunk/no-op wins into medium-sized game functions.
3. Improve type/prototype fidelity in hotspots before deep body work.
4. Continue `TCivDescription` shape/data passes around `0x0058F7B0` and `0x0058FEC0` (now de-thunked), then return to `0x0058F550`/`0x0058F1A0` for control-flow and call-shape tuning.

## Latest Non-Trade Checkpoint
1. `0x0055FC40` `InputState::HandleKeyDown`: `25.69%` (from `20.42%` after direct-thunk-call shape pass in `src/game/input_state.cpp`).

## Active Class Focus: `trade_screen.cpp`

Current loop policy for this class:
1. `shape pass` first (branch/call order/assert paths).
2. `data pass` second (type widths, clamp order, float/int math).
3. Rebuild + targeted `reccmp --verbose` per touched address.
4. No regressions allowed on adjacent trade-screen functions.
5. Promotion can be mixed by contiguous trade-screen address clusters (not only class-by-class); normalize promoted raw class output immediately after import.

File layout note:
1. `src/game/trade_screen.cpp` contains shared scaffolding/helpers and global/non-class trade-screen functions.
2. Class-owned wrappers now live in class files (`src/game/<ClassName>.cpp`), including:
   1. `TCivilianButton`, `THQButton`, `TPlacard`, `TArmyPlacard`, `TNumberedArrowButton`, `TCombatReportView`
   2. `TArmyToolbar`, `TStratReportView`, `TCivToolbar`, `TCivDescription`, `TArmyInfoView`
   3. `TCivReport`, `TTransportPicture`
3. `src/game/ui_widget_wrappers.cpp` is reserved for global/non-class wrappers.
4. Trade-screen class methods are in flat class files under `src/game/` and included by `src/game/trade_screen.cpp`:
   1. `TAmtBar.cpp`
   2. `TIndustryCluster.cpp`
   3. `TIndustryAmtBar.cpp`
   4. `TRailCluster.cpp`
   5. `TRailAmtBar.cpp`
   6. `TShipyardCluster.cpp`
   7. `TShipAmtBar.cpp`
   8. `TTraderAmtBar.cpp`
5. New extractions should be promoted into class files when symbol ownership is class-scoped.

### Trade Screen Checkpoint (latest)

Targeted similarities from current `build-msvc500`:
1. `0x00587AA0` `SetTradeBidSecondaryBitmapState`: `77.86%`
2. `0x00587BB0` `SetTradeBidControlBitmapState`: `61.89%`
3. `0x00587DD0` `SetTradeOfferControlBitmapState`: `52.21%`
4. `0x00587130` `InitializeTradeSellControlState`: `41.52%`
5. `0x00588030` `SetTradeOfferSecondaryBitmapState`: `42.31%`
6. `0x005882F0` `UpdateTradeSellControlAndBarFromNationMetric`: `22.41%`
7. `0x00588630` `OrphanCallChain_C2_I15_00588630`: `62.86%`
8. `0x00588670` `OrphanCallChain_C1_I03_00588670`: `46.15%`
9. `0x00588610` `WrapperFor_thunk_NoOpUiLifecycleHook_At00588610`: `40.00%`
10. `0x00588950` `ClampAndApplyTradeMoveValue`: `33.03%`
11. `0x00588C30` `OrphanCallChain_C1_I06_00588c30`: `55.56%`
12. `0x00588F60` `UpdateTradeBarFromSelectedMetricRatio_B`: `53.73%`
13. `0x00588FF0` `HandleTradeMoveStepCommand`: `28.57%`
14. `0x005899C0` `OrphanCallChain_C1_I06_005899c0`: `55.56%`
15. `0x00589D10` `UpdateTradeBarFromSelectedMetricRatio_A`: `53.73%`
16. `0x00589260` `InitializeTradeBarsFromSelectedCommodityControl`: `37.25%`
17. `0x00589660` `CreateTradeMoveScaledControlPanel`: `37.50%`
18. `0x00588C60` `UpdateTradeMoveControlsFromDrag`: `25.53%`
19. `0x005899F0` `UpdateTradeMoveControlsFromScaledDrag`: `31.62%`
20. `0x00586C40` `CreateTradeMoveControlPanelBasic`: `34.78%`
21. `0x00586CC0` `GetTAmtBarClusterClassNamePointer`: `50.00%`
22. `0x00586CE0` `ConstructTradeMoveControlPanelBasic`: `71.43%`
23. `0x00586D10` `DestructTAmtBarClusterMaybeFree`: `66.67%`
24. `0x00586D60` `InitializeTradeMoveAndBarControls`: `53.12%`
25. `0x00586E70` `HandleTradeMoveControlAdjustment`: `26.23%`
26. `0x005873E0` `HandleTradeSellControlCommand`: `23.68%`
27. `0x00586A60` `OrphanTiny_SetWordEcxOffset_8c_00586a60`: `40.00%`
28. `0x00586A80` `OrphanLeaf_NoCall_Ins05_00586a80`: `40.00%`
29. `0x00586AB0` `OrphanTiny_SetWordEcxOffset_8e_00586ab0`: `40.00%`
30. `0x00586E50` `OrphanLeaf_NoCall_Ins02_00586e50`: `0.00%`
31. `0x00586FF0` `OrphanRetStub_00586ff0`: `0.00%`
32. `0x00586660` `DestructTCityBarClusterAndMaybeFree`: `66.67%`
33. `0x00586840` `CreateTProductionClusterInstance`: `42.86%`
34. `0x00586900` `GetTProductionClusterClassNamePointer`: `50.00%`
35. `0x00586920` `ConstructTProductionClusterBaseState`: `84.62%`
36. `0x00586970` `DestructTProductionClusterAndMaybeFree`: `66.67%`
37. `0x005869C0` `HandleProductionClusterValuePanelSplitArrowCommand64or65AndForward`: `35.56%`
38. `0x00586AD0` `CreateTClosePictureInstance`: `34.78%`
39. `0x00586B50` `GetTClosePictureClassNamePointer`: `50.00%`
40. `0x00586B70` `ConstructTClosePictureBaseState`: `85.71%`
41. `0x00586BA0` `DestructTClosePictureAndMaybeFree`: `66.67%`
42. `0x00586BF0` `WrapperFor_DispatchUiMouseEventToChildrenOrSelf_At00586bf0`: `65.31%`
43. `0x00588690` `RenderPrimarySurfaceOverlayPanelWithClipCache`: `20.69%`
44. `0x00589340` `RenderQuickDrawControlWithHitRegionClip_A`: `18.87%`
45. `0x00589540` `RenderQuickDrawOverlayWithHitRegion_00589540`: `17.24%`
46. `0x00589DA0` `TradeMoveStepCluster::HandleTradeMovePageStepCommand`: `25.37%`
47. `0x0058A610` `TradeMoveStepCluster::SelectTradeSpecialCommodityAndInitializeControls`: `48.89%`
48. `0x0058A940` `TradeMoveStepCluster::HandleTradeMoveArrowControlEvent`: `29.87%`
49. `0x0058A690` `TradeMoveStepCluster::RefreshTradeMoveBarAndTurnControl`: `15.45%`
50. `0x0058AF80` `TradeAmountBarLayout::UpdateNationStateGaugeValuesFromScenarioRecordCode`: `20.14%`
51. `0x0058B070` `WrapperFor_GetActiveNationId_At0058b070`: `49.18%`
52. `0x0058BC60` `PlacardState::RenderPlacardValueTextWithShadow`: `55.62%`
53. `0x0058BAB0` `PlacardState::WrapperFor_thunk_NoOpUiLifecycleHook_At0058bab0`: `43.48%`
54. `0x0058BB50` `PlacardState::WrapperFor_thunk_InvalidateCityDialogRectRegion_At0058bb50`: `44.04%`
55. `0x005866B0` `UpdateTradeSummaryMetricControlsFromRecord`: `34.91%`
56. `0x00588B70` `SyncTradeCommoditySelectionWithActiveNationAndInitControls`: `42.50%`
57. `0x005897B0` `SelectTradeCommodityPresetBySummaryTagAndInitControls`: `34.39%`

Immediate objective:
1. Trade-screen batch mapping for `0x586000-0x58A000` is now fully owned (`stubs_part018.cpp` has zero remaining `FUNCTION` entries in that window).
2. Run targeted shape pass on lowest trade-screen cluster scores first: `0x005873E0`, `0x00586E70`, `0x00588690`, `0x00589340`, `0x00589540`.
3. Fix tiny-signature calling-convention mismatches (`0x00586E50`, `0x00586FF0`) after current batch-stabilization.
4. Remaining unmapped (`FUNCTION`) in `0x586000-0x58C000`: `10` addresses.

Latest focused shape-pass checkpoints:
1. `0x00589DA0`: `25.37%`
2. `0x0058A610`: `54.55%`
3. `0x0058A940`: `41.03%`
4. `0x00588FF0`: `28.57%`
5. `0x005866B0`: `34.91%`
6. `0x00586E70`: `26.23%`

Latest wrapper batch checkpoints:
1. `0x00585F70` `CreateTUnitToolbarClusterInstance`: `34.78%`
2. `0x00585FF0` `GetTUnitToolbarClusterClassNamePointer`: `50.00%`
3. `0x00586010` `ConstructTUnitToolbarClusterBaseState`: `71.43%`
4. `0x00586040` `DestructTUnitToolbarClusterAndMaybeFree`: `66.67%`
5. `0x00586090` `WrapperFor_thunk_DispatchPanelControlEvent_At00586090`: `35.96%`
6. `0x00586150` `OrphanVtableAssignStub_00586150`: `100.00%`
7. `0x0058DE40` `CreateTArmyToolbarInstance`: `34.78%`
8. `0x0058DEC0` `GetTArmyToolbarClassNamePointer`: `50.00%`
9. `0x0058DEE0` `ConstructTArmyToolbarBaseState`: `71.43%`
10. `0x0058DF10` `DestructTArmyToolbarAndMaybeFree`: `66.67%`
11. `0x0058E330` `CreateTStratReportViewInstance`: `34.78%`
12. `0x0058E3A0` `GetTStratReportViewClassNamePointer`: `50.00%`
13. `0x0058E3C0` `ConstructTStratReportViewBaseState`: `85.71%`
14. `0x0058E3F0` `DestructTStratReportViewAndMaybeFree`: `66.67%`
15. `0x0058EA00` `CreateTCivToolbarInstance`: `34.78%`
16. `0x0058EA80` `GetTCivToolbarClassNamePointer`: `50.00%`
17. `0x0058EAA0` `ConstructTCivToolbarBaseState`: `85.71%`
18. `0x0058EAD0` `DestructTCivToolbarAndMaybeFree`: `66.67%`
19. `0x00591500` `CreateTArmyInfoViewInstance`: `34.78%`
20. `0x00591580` `GetTArmyInfoViewClassNamePointer`: `50.00%`
21. `0x005915A0` `ConstructTArmyInfoViewBaseState`: `85.71%`
22. `0x005915D0` `DestructTArmyInfoViewAndMaybeFree`: `66.67%`

## 2026-02-24 09:59 UTC checkpoint - trade-screen wrapper deepening

Focused addresses in `0x58A1B0-0x58BFE0` after latest shape/data pass:
1. `0x0058A1B0` `RenderQuickDrawControlWithHitRegionClip_B`: `30.06%` (from `0.00%`)
2. `0x0058A3B0` `RenderQuickDrawOverlayWithHitRegion_0058a3b0`: `23.76%` (from `16.67%`)
3. `0x0058AC80` `RenderQuickDrawControlWithHitRegionClip_C`: `27.03%` (from `0.00%`)
4. `0x0058B0F0` `RenderControlWithTemporaryRectClipRegionAndChildren`: `16.44%` (from `0.00%`)
5. `0x0058B460` `OrphanCallChain_C4_I34_0058b460`: `64.37%` (from `59.38%`)
6. `0x0058B4F0` `BlitHintOverlayRectWithCtrlModifierPalette`: `20.93%` (from `0.00%`)
7. `0x0058B750` `OrphanCallChain_C3_I43_0058b750`: `33.33%` (from `15.69%`)
8. `0x0058B890` `OrphanCallChain_C2_I16_0058b890`: `50.00%` (unchanged)
9. `0x0058B8D0` `OrphanCallChain_C2_I37_0058b8d0`: `47.22%` (from `24.49%`)
10. `0x0058BFE0` `RenderRightAlignedNumericOverlayWithShadow`: `19.61%` (from `0.00%`)

Global metric delta:
1. average similarity: `2.46%` (was `2.42%` at this checkpoint window start)
2. aligned functions: `49` (unchanged)
3. paired coverage: `100.00%` (unchanged)

Tiny-orphan call-shape update (`2026-02-24 10:03 UTC`):
1. `0x00586E50` lifted to `20.00%` by matching `ret 8` stack-pop signature shape (`__stdcall` + explicit unused arg).
2. `0x00586FF0` remains `0.00%` (original appears as zero-byte/no-body mapping; current emitted `ret` still mismatches).

Quickdraw base-pair update (`2026-02-24 10:06 UTC`):
1. `0x00589340` `RenderQuickDrawControlWithHitRegionClip_A`: `30.06%` (was `18.87%`).
2. `0x00589540` `RenderQuickDrawOverlayWithHitRegion_00589540`: `22.45%` (was `17.24%`).

## 2026-02-24 11:45 UTC checkpoint - trade command/preset shape pass

1. `0x005873E0` `HandleTradeSellControlCommand`: `15.50%` (from `11.94%` in this track).
2. `0x005897B0` `SelectTradeCommodityPresetBySummaryTagAndInitControls`: `19.13%` (from `16.95%` session baseline).

Applied shape changes:
1. Added missing `0x67/0x68` propagation branches with 17-tag row fan-out loop (`0sr..6sr`, `0am..5am`, `0dg..3dg`) in `0x005873E0`.
2. Preserved `0x005873E0` as free fastcall wrapper after testing; member-method conversion regressed this function in current type/layout state, then restored `ret 0xc` stack-pop shape with an explicit unused stack argument.
3. For `0x005897B0`, aligned call-shape toward original by:
   1. explicit stack-arg signature (`ret 4` behavior),
   2. casted thunk bridge call to `thunk_InitializeTradeMoveAndBarControls`,
   3. post-init slot `+0x1D4` dispatch on `this` instead of owner fallback.

Global metrics remained stable:
1. aligned functions: `60`
2. average similarity: `2.50%`
3. paired coverage: `100.00%`.

## 2026-02-24 11:55 UTC checkpoint - trade summary/move-adjust shape pass

1. `0x005866B0` `UpdateTradeSummaryMetricControlsFromRecord`: `34.91%` (from `8.62%` in this track).
2. `0x00586E70` `HandleTradeMoveControlAdjustment`: `26.23%` (from `17.39%`).
3. `0x005873E0` `HandleTradeSellControlCommand`: `15.50%` (unchanged guard check).
4. `0x005882F0` `UpdateTradeSellControlAndBarFromNationMetric`: `22.41%` (attempted rewrite regressed to `17.57%`, reverted).

Applied shape changes:
1. `0x005866B0`:
   1. switched to `thiscall` wrapper shape (`__fastcall(this, unusedEdx, stackArg)`),
   2. replaced loop/arrays with explicit per-tag sequence (`aert`, `rtnu`, `iart`, `forp`),
   3. matched `USmallViews` assert line ids on nil paths (`0x67d`, `0x682`, `0x687`),
   4. aligned first setter arg to dword path (`[record+0xac]+0x10`) and remaining to short offsets (`+4/+6/+8`).
2. `0x00586E70`:
   1. moved to normalized command branch shape (`commandId - 100` => `0/1`),
   2. preserved fail-and-continue behavior after nil asserts (no extra early returns).

Global snapshot (`2026-02-24T11:55:01Z`):
1. aligned functions: `60`
2. average similarity: `2.51%`
3. paired coverage: `100.00%`
4. failed-to-match lines: `0`.

## 2026-02-24 12:13 UTC checkpoint - trade sell-command layout pass

1. `0x005873E0` `HandleTradeSellControlCommand`: `23.68%` (from `15.50%` in prior checkpoint).
2. `0x005897B0` `SelectTradeCommodityPresetBySummaryTagAndInitControls`: `27.87%` (unchanged this pass).
3. `0x0055FC40` `InputState::HandleKeyDown`: `25.69%` (probe changes reverted; no net delta).

Applied shape changes:
1. Converted `0x005873E0` to a real member implementation (`__thiscall` shape, `ret 0xc`), with command switch layout and explicit cases `100/0x65/0x67/0x68/0x69/0x6A`.
2. Restored case-`100` gating/flow pieces (`slot +0x1dc` check, `Sell` + `mCap` lookups, `0x816`/`0x81d` assert paths) and preserved fan-out loops for `0x67/0x68`.
3. Split `0x005873E0` onto a dedicated TAmtBarCluster-shaped context (`field +0x88` metric slot) instead of `TradeMovePanelContext`; this removed offset drift in emitted code but did not move similarity beyond `23.68%`.
4. Validated build stability after the `InputState` call-shape probe and restored baseline when no improvement held.

Current constraint to resolve next:
1. `0x005873E0` still diverges on prologue/register allocation and nil-path assert sequence (`0x82f/0x85a/0x874/0x896` pathing), even after layout split.

Global snapshot (`2026-02-24T12:13:54Z`):
1. aligned functions: `60`
2. average similarity: `2.52%`
3. paired coverage: `100.00%`
4. failed-to-match lines: `0`.

## 2026-02-25 22:37 UTC checkpoint - trade-screen micro-shape wins

Focused trade-screen updates:
1. `0x00583BD0` `HandleTradeArrowAutoRepeatTickAndDispatch`: `58.18% -> 67.77%`.
2. `0x00586A60` `OrphanTiny_SetWordEcxOffset_8c_00586a60`: `40.00% -> 100.00%`.
3. `0x00586A80` `OrphanLeaf_NoCall_Ins05_00586a80`: `40.00% -> 100.00%`.
4. `0x00586AB0` `OrphanTiny_SetWordEcxOffset_8e_00586ab0`: `40.00% -> 100.00%`.

What changed:
1. Restored `thiscall` stack-arg shape in `0x00583BD0` for both dispatch thunk call and slot `+0x40` calls (dummy `edx` fastcall bridge).
2. Rewired nil-pointer assert helper to call `thunk_DestructTShipAndFreeIfOwned(file, line)` cast instead of the previous incorrect cast target.
3. Applied local `#pragma optimize("y", on)` bracket for the three tiny `0x586A*` leaf wrappers to remove frame-prologue drift.

Project snapshot (`just stats`):
1. paired functions: `12229`
2. aligned functions: `63`
3. average similarity: `2.60%`
4. paired coverage: `100.00%`

## 2026-03-03 00:08 UTC checkpoint - current `TGreatPower` cleanup strategy

Current focus:
1. Keep `TGreatPower` as the active cleanup/matching surface.
2. Prefer typed field/view promotion and cast removal that does not regress current anchor scores.
3. Only keep local readability changes in target bodies when `just compare` confirms no meaningful drop.

Current anchors:
1. `0x004EA470`: `100%`
2. `0x004DDD50`: `59.09%`
3. `0x004DD0C0`: `20.00%`
4. `0x004DBD20`: `17.12%`

Current project metrics (`just stats`):
1. aligned functions: `92 / 12973`
2. average similarity: `2.82%`
3. signal: `STALLED`

Next moves:
1. Keep `0x004DDD50` body shape as-is (recent simplification regressed it).
2. Continue cast-reduction in helpers and typed views around `0x004DBD20` paths first, then retest.
3. Defer deep prologue/epilogue tuning for `0x004DD0C0` until more adjacent layout/type certainty is available.

## 2026-03-03 00:16 UTC checkpoint - new promoted `TGreatPower` bodies integrated

Promoted and owned in `src/game/TGreatPower.cpp`:
1. `0x004E22B0`
2. `0x004E2330`
3. `0x004E2500`
4. `0x004E27B0`

Current anchor/target snapshot:
1. `0x004EA470`: `100%`
2. `0x004E2330`: `33.49%`
3. `0x004E27B0`: `25.81%`
4. `0x004E22B0`: `17.86%`
5. `0x004E2500`: `17.22%`

Current metrics (`just stats`):
1. aligned functions: `92 / 12973`
2. average similarity: `2.83%`
3. signal: `GOOD`

Next immediate loop:
1. Promote next batch of unmoved `TGreatPower` addresses (prefer larger bodies with real logic).
2. Keep compile-safe first, then do a cleanup pass for casts/field typing.

## 2026-03-03 00:25 UTC checkpoint - 8 more `TGreatPower` addresses owned

Newly owned this cycle:
1. `0x004DC540`
2. `0x004DC660`
3. `0x004DC840`
4. `0x004DCD10`
5. `0x00541080`
6. `0x005410F0`
7. `0x0055C970`
8. `0x0055CBD0`

Current anchors:
1. `0x004EA470`: `100%`
2. `0x004DCD10`: `38.33%`
3. `0x0055C970`: `25.45%`

Current metrics (`just stats`):
1. aligned functions: `92 / 12973`
2. average similarity: `2.85%`
3. signal: `STALLED` (no aligned count movement, slight similarity gain)

Next immediate loop:
1. Cleanup pass in newly promoted methods:
   1. remove avoidable cast-heavy access,
   2. tighten call shapes where easy (`slot` call ordering and branch shape).
2. Promote another 2-4 medium `TGreatPower` methods from remaining backlog.

## 2026-03-02 19:37 UTC checkpoint - `TGreatPower` field-layout extraction

Focused update:
1. Introduced a typed in-class layout for `TGreatPower` (offsets through `+0x960`) and migrated major methods away from raw `self + offset` reads/writes.

What changed:
1. Added typed members + padding gaps directly in `src/game/TGreatPower.cpp` class definition.
2. Converted the largest active bodies in this class to typed field access:
   1. `0x004D9160`
   2. `0x004D92E0`
   3. `0x004DB380`
   4. `0x004DBF00`
3. Kept compare markers and ownership intact; no inline asm.

Validation:
1. `just build`: pass
2. `just detect`: pass
3. `just compare 0x004D92E0`: `3.12%` (stable)
4. `just compare 0x004DB380`: unresolved pairing (`Failed to find a match at address`)
5. `just compare 0x004DBF00`: unresolved pairing (`Failed to find a match at address`)

Next action:
1. Fix pair/reachability for `0x004DB380` and `0x004DBF00` first.
2. Continue field extraction on neighboring methods (`0x004D8CC0`, `0x004DBD20`) once those addresses are visible in compare again.

## 2026-03-02 19:52 UTC checkpoint - pairing fix landed

Focused update:
1. Re-enabled reccmp pairing for `0x004DB380` and `0x004DBF00` by correcting marker placement.

What changed:
1. Removed intervening descriptive comment lines between `// FUNCTION:` and method signatures for:
   1. `TGreatPower::UpdateGreatPowerPressureStateAndDispatchEscalationMessage`
   2. `TGreatPower::AdvanceOwnedRegionDevelopmentCountersAndDispatchEvents`
2. Kept description comments above markers so reccmp sees signature immediately after marker.

Validation:
1. `just build`: pass
2. `just detect`: pass
3. `just compare 0x004DB380`: `14.47%`
4. `just compare 0x004DBF00`: `27.79%`

Current next action:
1. Continue field extraction and shape/data passes on these now-paired methods.

## 2026-03-02 18:38 UTC checkpoint - `TGreatPower` incremental port batch

Focused update:
1. Ported additional `TGreatPower` methods and replaced several no-op thunks with owned code.

What changed:
1. Added/normalized real method bodies:
   1. `0x004DD470` `ResetDiplomacyNeedSlots7012AndRefreshIfModeGateMatches`.
   2. `0x004DF5C0` `DispatchTurnEvent2103WithNationFromRecord`.
   3. `0x004E73F0` `WrapperFor_HandleCityDialogHintClusterUpdate_At004e73f0` (first-pass body).
2. Wired thunk addresses to real methods:
   1. `0x00408017 -> 0x004DD470`.
   2. `0x00408076 -> 0x004DF5C0`.
3. Added first-pass non-no-op body for `0x00406FE1`.
4. Ran ownership and stub sync after each marker update (`just sync-ownership && just regen-stubs`).

Validation:
1. `just build`: pass
2. `just detect`: pass
3. Per-address:
   1. `0x00408017`: `100.00%`
   2. `0x00408076`: `100.00%`
4. Global (`just stats`):
   1. aligned functions: `90` (`+2`)
   2. not aligned vs original: `12883` (`-2`)
   3. average similarity: `2.72%` (`+0.03 pp`)

Immediate next loop:
1. Tune `0x004DD470` prologue/register shape (`field00` load/call form) using targeted `just compare`.
2. Tune `0x004DF5C0` call ABI (`push this->field0c` and slot `+0x4C` call form).
3. Keep `0x004E73F0` as ownership anchor and tune message-slot ABI/payload width in small diffs.

## 2026-03-02 18:47 UTC checkpoint - big-body first pass on `TGreatPower`

Focused update:
1. Ported two substantial runtime methods from Ghidra into manual code and kept build loop stable.

What changed:
1. Added real bodies:
   1. `0x004DE860` `ApplyJoinEmpireMode0GlobalDiplomacyReset`.
   2. `0x004DF5F0` `ProcessPendingDiplomacyProposalQueue`.
2. Rewired thin thunks:
   1. `0x00401CBC` -> member `ProcessPendingDiplomacyProposalQueue`.
   2. `0x004097FA` -> member `ApplyJoinEmpireMode0GlobalDiplomacyReset`.
3. Synced ownership + stubs after marker changes.

Validation:
1. `just build`: pass
2. `just detect`: pass
3. Targeted compares:
   1. `0x004DE860`: `26.16%`
   2. `0x004DF5F0`: `9.49%`
   3. `0x00401CBC`: `100.00%`
4. Global (`just stats`):
   1. aligned functions: `90`
   2. average similarity: `2.73%`

Next loop:
1. Keep prioritizing large real bodies over thunk polish.
2. Candidate next body: `0x00406CA3` (`BuildGreatPowerRelationshipDeltaSummaryAndDispatchMessage`) or `0x004D8CC0` (`InitializeNationStateRuntimeSubsystems`) as compile-safe first pass.

## 2026-03-02 18:50 UTC checkpoint - extra large-body attempt (`0x00406CA3`)

Focused update:
1. Landed a compile-safe first-pass implementation for `0x00406CA3` (relation-scan summary path) to remove no-op ownership.

Validation:
1. `just build`: pass
2. `just detect`: pass
3. `just compare 0x00406CA3`: still `0.00%`

Interpretation:
1. This address appears dominated by original SEH + string-lifetime scaffolding; simplified pass is not enough for non-zero similarity.
2. Keep this function owned in manual code, but treat it as a deep-tuning lane.

Immediate plan:
1. Continue large-function throughput on easier non-zero candidates (for example `0x004D8CC0`) while leaving `0x00406CA3` for later SEH-shape work.

## 2026-03-02 18:02 UTC checkpoint - `TGreatPower` real-body expansion

Focused update:
1. Shifted four `TGreatPower` addresses from zero/stub state to real C++ bodies in `src/game/TGreatPower.cpp` while keeping build loop green.

What changed:
1. Added non-zero real bodies:
   1. `0x004DDFC0` (`ApplyDiplomacyPolicyStateForTargetWithCostChecks`)
   2. `0x004E9060` (`ComputeMapActionContextCompositeScoreForNation`)
   3. `0x004DC9F0` (`RefreshGreatPowerRelationPanelsAndDispatchDeltaSummary`)
   4. `0x004DBD20` (`RebuildNationResourceYieldCountersAndDevelopmentTargets`)
2. Kept thunk entrypoints wired to those real bodies:
   1. `0x00406915`
   2. `0x004070E5`
   3. `0x00407DB0`
   4. `0x004097FF`
3. Stabilized ownership flow:
   1. after manual marker edits, run `just sync-ownership && just regen-stubs` before compare to avoid stale stub shadowing.

Validation:
1. `just build`: pass
2. `just detect`: pass
3. targeted compares:
   1. `0x004DC9F0`: `57.63%`
   2. `0x004DDFC0`: `25.77%`
   3. `0x004DBD20`: `13.74%`
   4. `0x004E9060`: `9.52%`
4. global snapshot (`just stats`):
   1. aligned functions: `86` (`+7`)
   2. average similarity: `2.67%` (`+0.08 pp`)

Next high-impact targets:
1. `0x004DBD20` data-pass cleanup:
   1. reduce extra locals/stack temps,
   2. tighten global-map call shape (`+0xC4`) and loop-carried pointer math.
2. `0x004E9060` shape pass:
   1. add missing zero-candidate branch behavior from Ghidra flow,
   2. align SEH/prologue expectations only after the above branch parity.

## 2026-03-02 17:11 UTC checkpoint - `TGreatPower` focused gains

Focused update:
1. Ran a constrained shape-first pass only on `TGreatPower` real-address bodies with strict rollback on regressions.

What changed:
1. `0x004E8540` (`QueueMapActionMissionFromCandidateAndMarkState`):
   1. removed mission-queue null guard branch,
   2. restored nil-pointer assert flow (`MessageBoxA` + invalidation helper call) without early return,
   3. kept state-byte writes in original order.
2. `0x004DDA90` (`QueueInterNationEventType0FForNationPairContext`):
   1. removed queue-manager null branch,
   2. reduced to direct thunk dispatch with fixed-address queue manager read.
3. `0x004E8750`:
   1. rejected broader case-expansion attempt after measured regression,
   2. retained prior tighter baseline.
4. `0x004DDBB0`:
   1. attempted arg-shape rewrite was rolled back after regression,
   2. current guarded baseline preserved.

Validation:
1. `just build`: pass
2. `just detect`: pass
3. targeted compare snapshot:
   1. `0x004DDBB0`: `37.89%`
   2. `0x004DDA90`: `26.67%`
   3. `0x004E8540`: `44.16%`
   4. `0x004E8750`: `34.25%`

Next high-impact target:
1. Keep `0x004E8540` and `0x004E8750` stable and move to `0x004E1D50` with the same rollback rule (single-function edits, compare immediately, revert regressions).

## 2026-03-01 20:09 UTC checkpoint - `TGreatPower` first owned batch

Focused update:
1. Added manual `TGreatPower` surface (`src/game/TGreatPower.cpp`) and promoted 23 addresses as compile-safe wrappers.

What changed:
1. `just promote` used to claim ownership for the first 23 `TGreatPower` addresses.
2. Raw promoted bodies were normalized into wrapper-style methods/functions to keep build stability:
   1. class member wrappers for `thunk_*` entries,
   2. free wrappers for cdecl/stdcall-style entries.
3. Build wiring updated in `CMakeLists.txt` (`src/game/TGreatPower.cpp` added).
4. Ownership/stubs refreshed via `just sync-ownership` + `just regen-stubs`.

Per-address spot-check:
1. `0x00401172`: `100.00%`
2. `0x004014A6`: `0.00%`
3. `0x00401AD2`: `0.00%`
4. `0x00403C15`: `0.00%`
5. `0x00404CE1`: `0.00%`
6. `0x00405AC9`: `0.00%`

Current interpretation:
1. Ownership/import pipeline for `TGreatPower` is healthy (compile+detect pass).
2. Wrapper-only forwarding gave one exact thunk match and multiple `0%` entries; next step is argument/call-shape-preserving wrappers for this class.

Project snapshot (`2026-03-01T20:09:37Z`):
1. paired functions: `12229`
2. aligned functions: `79`
3. average similarity: `2.57%`
4. paired coverage: `100.00%`

## 2026-03-01 20:17 UTC checkpoint - `TGreatPower` class-routing enforcement

Focused update:
1. Enforced class routing for selected `TGreatPower` thunk wrappers: thunk methods now call class member methods directly.

What changed:
1. Introduced class-owned methods for key thunk targets (`QueueMapActionMission...`, `ComputeAdvisoryMapNodeScore...`, `ExecuteAdvisoryPrompt...`, `TryDispatchNationAction...`, `QueueInterNationEventType0F...`).
2. Moved bridge casts out of thunk bodies and into those class methods.

Validation:
1. `just build`: pass
2. `just detect`: pass
3. compares:
   1. `0x00401172`: `100.00%`
   2. `0x004014A6`: `0.00%`
   3. `0x00401AD2`: `0.00%`
   4. `0x00403C15`: `0.00%` (regressed from `66.67%`)
   5. `0x00404CE1`: `0.00%`
   6. `0x00405AC9`: `0.00%`

Next action in this class:
1. Replace bridge-style methods with class-owned first-pass bodies for the `0%` addresses, starting with `0x00403C15` to recover the regression.

## 2026-03-01 21:50 UTC checkpoint - `TGreatPower` class-owned body pass (no-gain)

Focused update:
1. Added class-owned first-pass bodies for `0x00403C15` and `0x00404CE1` in `src/game/TGreatPower.cpp`, while keeping the remaining selected `0%` entries as class thunks.

What changed:
1. Switched new body logic to fixed-address global reads (`0x6A21BC`, `0x6A4280`, `0x6A43D0`) to avoid type-mangled extern link failures.
2. Kept function ownership entirely in class methods (no free-function fallback for these addresses).
3. Recovered build stability after intermediate linker/type errors.

Validation:
1. `just build`: pass
2. `just detect`: pass
3. compares:
   1. `0x00401172`: `100.00%`
   2. `0x004014A6`: `0.00%`
   3. `0x00401AD2`: `0.00%`
   4. `0x00403C15`: `0.00%`
   5. `0x00404CE1`: `0.00%`
   6. `0x00405AC9`: `0.00%`
4. stats:
   1. aligned functions: `79 / 12973`
   2. average similarity: `2.57%`

Conclusion:
1. This iteration met structural/class goals and kept the pipeline green, but did not lift targeted similarity.
2. Next high-value move is to use exact branch/arg shape from autogen for a single address (`0x00403C15`) with minimal normalization, then compare before touching neighbors.

## 2026-03-01 22:05 UTC checkpoint - dual-address ownership (`thunk` + `real`)

Focused update:
1. Established explicit dual-address mapping for selected `TGreatPower` flows:
   1. thunk entrypoints keep thunk addresses,
   2. corresponding real implementation addresses are now also represented in manual source with `// FUNCTION` markers.

What changed:
1. Thunk addresses retained:
   1. `0x00403C15`
   2. `0x00404CE1`
   3. `0x00405AC9`
2. Real addresses added:
   1. `0x004E1D50`
   2. `0x004DDBB0`
   3. `0x004DDA90`
   4. `0x004E8540`
   5. `0x004E8750`
3. Replaced typed extern global references in this file with fixed-address reads for known symbol addresses to avoid mangled-data linker failures.

Validation:
1. `just build`: pass
2. `just detect`: pass
3. Compare snapshot:
   1. `0x00403C15`: `66.67%`
   2. `0x00404CE1`: `0.00%`
   3. `0x00405AC9`: `0.00%`
   4. `0x004E1D50`: `20.32%`
   5. `0x004DDBB0`: `35.42%`
   6. `0x004DDA90`: `0.00%`
   7. `0x004E8540`: `25.00%`
   8. `0x004E8750`: `0.00%`
4. Global metric:
   1. average similarity: `2.59%`.

Next high-impact target:
1. `0x00404CE1` and `0x004DDA90` are good candidates for immediate branch-shape passes because they are class-adjacent and still pinned at `0%`.

## 2026-03-01 20:00 UTC checkpoint - class-member conversion for `TCapacityOrder`

Focused update:
1. Moved the promoted `TCapacityOrder` block to real class member methods in `src/game/TCapacityOrder.cpp` (no free-wrapper fallback for these addresses).

What changed:
1. Kept thunk wrappers as member methods dispatching to member implementations.
2. Removed explicit `__thiscall` spellings on member declarations/definitions due MSVC500 `C4234` parser rejection; ABI remains member-call `thiscall`.
3. Rebuilt and re-ran only the seven promoted addresses for this class.

Per-address status:
1. `0x00401c0d`: `100.00%`
2. `0x00404093`: `0.00%`
3. `0x00405ab5`: `100.00%`
4. `0x004b8b80`: `30.89%`
5. `0x004b8cc0`: `100.00%`
6. `0x004b8d00`: `74.07%`
7. `0x004b8d30`: `100.00%`

Next immediate tuning targets in this class:
1. `0x00404093` (currently `0.00%`, likely thin thunk/jump shape issue).
2. `0x004b8b80` (`30.89%`, body/data-shape pass).
3. `0x004b8d00` (`74.07%`, ctor/dtor wrapper shape pass).

## 2026-02-25 22:58 UTC checkpoint - trade arrow dispatch typed-slot pass

Focused trade-screen update:
1. `0x00583BD0` `HandleTradeArrowAutoRepeatTickAndDispatch`: `67.77% -> 82.35%`.

What changed:
1. Typed virtual slots in `include/game/ui_widget_shared.h` for this path:
   1. `CtrlSlot16(int commandId, void* eventArg, int eventExtra)` (`+0x40`),
   2. `CtrlSlot91(void* dispatchArg)` (`+0x16c`).
2. Replaced raw vtable casts in `0x00583BD0` with those typed virtual calls, preserving the existing stack-shaped dispatch and repeat-deadline logic.
3. Kept local `#pragma optimize("y", on/off)` for this function; it still helps avoid extra frame-prologue drift under `/Oy-` baseline flags.

Current constraints:
1. `0x00583BD0` still carries extra `xor edx` before several calls (dispatch thunk and slot calls); likely tied to fastcall bridge usage and worth a dedicated callconv pass.
2. `0x00586E70` remains unstable to tune in this compiler mode because `__thiscall` free-function pointer casts fail (`C4234`), so tuning there should prefer typed class/member surfaces over raw casts.

Project snapshot (`just stats`):
1. paired functions: `12229`
2. aligned functions: `63`
3. average similarity: `2.60%`
4. paired coverage: `100.00%`

## 2026-03-03 09:57 UTC mini-checkpoint (`TGreatPower`)

1. Keep active focus on medium-size class-owned bodies with low-but-movable similarity (`0x004DD4E0`, `0x004DC660`, `0x004DC840`).
2. Latest high-impact gain came from shape-first restoration of list/slot/random loops from Ghidra in `0x004DD4E0`.
3. Current quick canaries:
   1. `0x004DD4E0`: `29.94%`
   2. `0x004DC540`: `43.06%`
   3. `0x004DC660`: `19.18%`
   4. `0x004DC840`: `13.14%`
