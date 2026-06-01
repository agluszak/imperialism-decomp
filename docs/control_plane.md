# Imperialism Decomp Control Plane

Last updated: 2026-06-01

## Purpose

This file tracks:

1. Current working strategy.
2. Baseline metrics/checkpoints.
3. Canonical command loop.

## Strategy (Current)

1. Keep Ghidra export artifacts as the source of truth for addresses/names.
2. Keep manual code in `src/game/`; keep generated code in autogen paths only.
3. Prioritize conversion of high-impact non-trivial function bodies (not tiny thunk wrappers).
4. Preserve marker/ownership hygiene every iteration:
   1. `just sync-ownership`
   2. `just regen-stubs`
5. Use canary compares to catch local regressions before broad tuning.
6. Track globals and non-function entities in stats (not only functions).
7. Keep vcall facades generated as direct slot-call wrappers (avoid extra runtime-helper call layers in hot paths).
8. Use read-only class discovery (`just class-discovery`) to rank class ownership/vtable candidates before attach/rename writes.
9. Use local slice discovery (`just slice-discovery <Class> 0xADDR`) before vertical-slice edits to list anchors, actual vcall wrappers, global/helper calls, `this` fields, and the conservative `ClassCandidate` evidence object.
10. Treat class-discovery candidate queue as "new work only": exclude manual-owned addresses by default and prioritize queue rows (`P0/P1/P2`) from lane score+density.
11. For subsystem pushes (e.g. shared-string helpers), use targeted `just compare 0xADDR` as the acceptance gate for touched functions; treat aggregate `just stats` as macro trend only.
12. Use persistent Mac CodeWarrior evidence from `/home/agluszak/code/decomp/imperialism_knowledge/macos_codewarrior` as a class-name and signature oracle, while keeping Windows Ghidra/vptr/reccmp evidence authoritative.

## Canonical Commands

Environment/bootstrap:

1. `just tooling-check`
2. `just docker-build` (when image needs rebuild)
3. `just sync-ghidra`

Iteration loop:

1. `just promote ...`
2. Compile-fix only for the promoted body.
3. `just sync-ownership`
4. `just regen-stubs`
5. `just build`
6. `just detect`
7. `just compare 0xADDR`
8. `just compare-canaries`
9. `just stats`

Maintenance:

1. `just inventory`
2. `just generate-ignores`
3. `just normalize-markers`
4. `just vtable-gate`
5. `just class-discovery`
6. `just mac-evidence`
7. `just mac-evidence-check`
8. `just slice-discovery TGreatPower 0x004dc540`
9. `jq . tmp_decomp/slice_discovery/tgreatpower_004dc540/class_candidate.json`
## Baseline Snapshot

1. Aligned functions: `100`
2. Average similarity: `3.05%`
3. Focus area: QuickDraw/EH-RAII rendering architecture across amount-bar, map-overlay, and scoped render-context paths.
4. Current sub-focus: promote remaining QuickDraw guard/scoped-context users, grow shared QuickDraw helper vocabulary, and keep amount-bar `DrawAmt` methods as canaries rather than single-function tuning targets.

## Latest Checkpoint

1. Aligned functions: `102`
2. Average similarity: `3.17%`
3. New matched primitive: `SetQuickDrawFillColor(int)` (`0x00495000`) at **100%**.
4. New architecture slice: `RenderWrappedMapQuickDrawOverlayFromStridedRecords` (`0x00596100`) promoted from stub to **24.44%**, with `QuickDrawSurfaceGuard` and generated map-overlay vcall facades.
5. New class slice: `TTransFocusAnimation::BlitTransientSurfaceToPrimaryRenderContextWithClip` (`0x004a05c0`) promoted from stub to **29.85%** and `TTransFocusAnimation::RenderFocusAnimationFrameWithScopedQuickDraw` (`0x004a0770`) promoted from stub to **71.19%**, with provisional scoped-context and render/update vcall facades.
6. Scoped-context sweep: moved `ScopedMapQuickDrawContextGuard` to shared UI scaffolding, promoted `TFocusAnimation::DestructTFocusAnimationAndMaybeFree` (`0x004a0190`) to **81.69%**, promoted `TOneTimeAnimation::DestructTOneTimeAnimationAndMaybeFree` (`0x0049fde0`) to **75.86%**, and improved `0x004a0770` to **84.75%** with the 24-byte guard layout.
7. Slider/control slice: promoted Mac-guided `TTwoPicSlider` draw/track methods: `0x0056e370` to **46.84%** and `0x0056e640` to **45.63%**, confirming shared RECT/blit/text/scoped-context patterns and a `ret 0x0c` hidden-stack-arg input shape.
8. Temporary primary-surface slice: promoted `TCityProductionViewLayout::RenderViewIntoPrimaryRenderContextWithTemporaryClip(int,int)` (`0x004bc9b0`) to **41.67%**, confirming the same `QuickDrawSurfaceGuard` / active-context swap / slot `0x12c`+`0x110` pattern as a real method with hidden stack args.
9. Diplomacy-map legend slice: promoted `TDiplomacyMapViewLayout::RenderDiplomacyLegendSurfaceAndPresent` (`0x004f6170`) to **45.06%**, `RebuildDiplomacyLegendPaletteMode4AndBlit` (`0x004f64c0`) improved to **37.74%**, `RebuildDiplomacyLegendPaletteMode1AndBlit` (`0x004f6840`) improved to **35.53%**, and provisional subobject method `DiplomacyMaskBufferRun::BlitMonochromeMaskBytePatternToSurface` (`0x004f66c0`) to **15.02%**. This established `this+0x98`, `this+0x524`, mask runs at `this+0x1eac`, packed-color runs at `this+0x2078`, and corrected vcall signatures for slots `0x1e0`, `0x34`, and `0x98`.
10. City-production header date slice: promoted `TCityProductionViewLayout::RenderNationHeaderDateLabelWithPeriodicRefresh` (`0x004badd0`) to **72.55%** by using branchless ternary conditional assignments to match MSVC compiler optimization choices and resolving missing extern global variables.
11. Diplomacy event-palette mask blit: promoted `TDiplomacyMapViewLayout::BlitDiplomacyMapEventPaletteMaskToSurface` (`0x004f6bd0`) from a `0%` stub to **25.30%**. This is the BMP-sourced single-index sibling of the mask-run blit family and established two new types: `ModuleLibraryCacheState` (global `g_pModuleLibraryCacheState` `0x6a134c`, with thiscall `LoadBmpResourceById`/`ReleaseRecordByHandle`) and the `DiplomacyPackedColorRun` subobject (`0x30` stride, thiscall `AppendPackedColorDword`). Residual gap is a `context+4`/`this` esi/edi register swap in the pixel loop.
12. Diplomacy turn-event mask-run render: promoted `TDiplomacyMapViewLayout::BuildTurnEventMonochromeMaskBuffers` (`0x004f6b10`) from a `0%` stub to **43.04%**. Standalone single-run sibling of the mode-1/mode-4 inner loop; validates the producer side of the mask-run/packed-color layout and resolved helper arities (`MapTurnEventCodeToPaletteIndex` `__cdecl(short)`; `SetUiResourceContextTagWord` `__thiscall(int* slot, value)` that fills `BlitMonochrome`'s `paletteByte` stack slot). Next deeper unlock: model the tag-slot helper as a typed struct to lift mode-1/mode-4 too.
13. Diplomacy combined terrain-region clip build: promoted `TDiplomacyMapViewLayout::BuildCombinedTerrainTypeRegionMaskAndDispatch` (`0x004f6440`) from a `0%` stub to **38.10%**. Added `VCall_DiplomacyMapView_ApplyClipRegionSlotC4` (slot `0xc4`) and the clip-region wrapper lifecycle (`CreateClipStateRegionWrapperObject` / `CombineTwoRegionsIntoDestinationAndUpdateBox` / `DestroyClipStateRegionWrapperObject`). Confirms strategic-map slot `0x98` is single-arg in this path too.
14. Diplomacy pending-policy icon/frame renderer: promoted `TDiplomacyMapViewLayout::RenderDiplomacyPendingPolicyIconsAndFrames` (`0x004f71a0`) from a `0%` stub to **31.97%**. Added `VCall_GlobalMapState_QueryIconStripXSlot110` (slot `0x110`, global `g_pGlobalMapState` `0x6a43d4`) and the line-draw helper vocabulary. New layout: icon RECT array at `this+0x6ac`, policy enable flags at `this+0x52c`, selected tier at `this+0x528`; turn-state manager (`0x6a43d0`) byte array at `+0x304` and short array at `+0x484`. MSVC500 FPO ICE on the three parallel induction cursors required a single-index rewrite (see INSTRUCTIONS #54).
15. Diplomacy click hit-test / action resolve (interaction sub-slice): promoted `TDiplomacyMapViewLayout::ResolveDiplomacyActionFromClickAndUpdateTarget(Point32*)` (`0x004f5e00`, thiscall `ret 4`) from a `0%` stub to **43.27%**. Exposes the diplomacy view's interaction state: `+0x90` selected target, `+0x94` mode, `+0xbc` action code, `+0xc2` hovered target. Added `VCall_DiplomacyMapView_TransformPointToLocalSlot148` (slot `0x148`) and `VCall_StrategicMap_HitTestPointSlot90` (slot `0x90`). Ghidra's `TCountry` class assignment for this address is wrong — the `this` is the view. This begins the interaction sub-slice (next: `0x4f5fb0` hover-cursor update).

## Active Constraints

1. No inline assembly.
2. No raw address+offset call sites in gameplay code.
3. No comment/blank line between `// FUNCTION` marker and declaration.
4. Use generated vcall facades instead of local vtable typedef/cast blocks.
5. Prefer reusable tooling over one-off scripts; wire it through `just` when stable.
6. Keep strict layout asserts only on proven-stable `TGreatPower` core offsets; keep tail offsets as non-fatal probes until tail stabilization.
7. During class reconstruction, assert failures are often expected drift signals while size/structure are still in flux; treat them as investigation cues, not automatic regressions.
8. Follow `docs/class_recovery.md`: MSVC ABI first, evidence object first, no base edge or class membership from naming alone.
9. Mac CodeWarrior method names can guide renames and signatures, but cannot directly assign Windows addresses, vtable slots, calling conventions, or inheritance.
