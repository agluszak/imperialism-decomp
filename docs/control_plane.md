# Imperialism Decomp Control Plane

Last updated: 2026-06-02

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

1. Aligned functions: `138`
2. Average similarity: `9.60%`
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
16. Diplomacy hover-cursor update (closes the interaction pair): promoted `TDiplomacyMapViewLayout::UpdateDiplomacyMapHoverCursorFromActionSelection(Point32*, void*)` (`0x004f5fb0`, thiscall `ret 8`) from a `0%` stub to **40.59%**. Calls `0x4f5e00` to resolve the action, validates `(selected, hovered, action)` via turn-state slot `0x5c` (`VCall_DiplomacyTurnState_ValidateActionSlot5C`), maps action -> cursor id via a 16-entry table (`+0xc0` adjust for actions 7/8/9), sets the cursor, and forwards to `TControl::HandleCursorHoverSelectionByChildHitTestAndFallback`. Added `+0xc0` (cursor adjust) and `+0x52a` (current cursor id) to the view layout; cursor handle table at `g_pUiRuntimeContext - 0xf8c + id*4`.

17. Diplomacy backend seed: added `src/game/diplomacy_state.cpp` and promoted `DiplomacyTurnStateManager` constructor/query/enqueue anchors: `0x004ef540` to **75.47%**, `0x004ef600` to **37.33%**, `0x004ef650` to **37.33%**, and `0x004f09c0` to **77.78%**. This establishes manager-as-`ecx` method signatures, vtable `0x00654d90`, queue pointer `this+0x18d4`, and constructor fields around `0x78e..0x798`; constructor `0x004ee6c0` is owned but still a register-order mismatch at **0.00%**.
18. Diplomacy queued-war processor: promoted `DiplomacyTurnStateManager::ProcessQueuedWarTransitions` (`0x004f0a10`) to **41.82%** as a first shape pass, plus the dispatch chain `0x00406aaf` and `0x004f0db0` at **100%** each. This proves the pending-war queue slots `0x30`/`0x34`, nation-state war propagation slots `0x27c`/`0x280`, global manager wrapper `0x6a43d0`, and the `NeXT` turn-event packet enqueue path.
19. Diplomacy manager shape pass: moved the default initializer into `DiplomacyTurnStateManager` (`0x004ee7a0` to **23.16%**, thunk `0x00403837` **100%**, constructor thunk `0x00409944` **100%**) and promoted key getter/gate slots: `0x004f19c0` **100%**, `0x004f1b10` **53.33%**, `0x004f1f50` **66.67%**. Current manager field map includes matrices at `+0x04`, `+0x304`, `+0x484`, `+0x79c`, `+0xbbe`, `+0xfe0`, `+0x1402`, and queue pointer `+0x18d4`.
20. Diplomacy relation-transition slot pass: promoted slot `0x48` (`0x004ef590`) to **58.33%** and slot `0x74` (`0x004f1b70`) to **9.31%** as a broad shape pass. This confirms relation stamps at `+0xfe0`, symmetric relation-code writes at `+0xbbe`, side-effect writes at `+0x1402`, and connected nation/terrain notification slots (`0x2a8`, `0x214`, `0x290`, terrain `0x48`, manager `0x28`/`0x80`). Next high-yield backend target is slot `0x5c` (`0x004ef700`) because the diplomacy-map UI already calls it through `VCall_DiplomacyTurnState_ValidateActionSlot5C`.
21. Diplomacy action validator: promoted slot `0x5c` (`0x004ef700`) to **55.42%** and moved the `VCall_DiplomacyTurnState_ValidateActionSlot5C` facade row to `diplomacy_state.cpp`. This closes the click/hover UI validation gate: failures write `proposalArrayMode18d8` reject codes and return `AL=0`; the shared valid exit returns `AL=1`. Next high-yield backend target is slot `0x60` (`0x004efc30`) because it is the next validator/helper used by broader diplomacy transition and UI paths.
22. TPtrList cleanup pass: added `src/game/TPtrList.cpp` to the build, replaced the bogus Ghidra `TArmyStack::AddHead` wrappers with a real `TPtrList`/embedded `CPtrListSentinelView` layout, and promoted `0x00488510` to **100.00%** with `0x004885d0`/`0x004885f0` now at **80.00%** each. The remaining gap is call-target pairing (`<OFFSET1>` vs current helper symbol), not wrapper body shape.
23. Array-backed pointer-list slice: added proper headers for `TPtrList` and `TSortedPtrList`, promoted the `CPtrArray`-style helper cluster into `src/game/TSortedPtrList.cpp`, and established that `0x00488110`/`0x00488160` are generic array-list helpers (`entries@+0x04`, `count@+0x08`) rather than part of the linked-list `TPtrList` family. Current results: `0x00407da6` **100.00%**, `0x00488110` **100.00%**, `0x00488160` **100.00%**; `0x00409868` remains a pure tail-thunk mismatch at **0.00%**.
24. Broader list-class cleanup: promoted `TIndexAndRankList` into its own header/translation unit, renamed `TPtrList`'s embedded `CPtrListSentinelView` fields to the real MFC-style list state (`headNode`, `tailNode`, `nodeCount`, `freeNodeList`, `blockChain`, `blockSize`), added `TSortedList` / `TSortedPtrList` classdesc+factory methods in their own files, and updated downstream callsites to use the typed array base instead of the old free `CPtrArray` bridge. New matches: `0x004883e0` **100.00%**, `0x00487b10` **100.00%**. Current broad-batch partials: `0x00601bc1` **81.82%**, `0x00488400` **52.63%**, `0x00487a90` **51.16%**, `0x00601baa` **13.33%**.
25. Diplomacy alliance-guard slot: promoted `DiplomacyTurnStateManager::HasAllianceGuardSlot60(int,int)` (`0x004efc30`) to **86.02%** and moved the `VCall_Diplomacy_HasAllianceGuardSlot60` facade row to `diplomacy_state.cpp`. This proves the old `TSortedByRelationshipList` label is misleading for this body: `ECX` is the manager, stack cleanup is `ret 8`, and the first guard is a virtual call through manager slot `0x4c` (`HasAnyWarRelationForNation(int)`). Next high-yield diplomacy targets are the still-provisional class-shape slots around the relation backend (`0x28`, `0x80`, `0x94`, `0x98`) and the broad setter `0x004f1b70`, not local tuning of the already-good `0x004efc30` branch layout.
26. Diplomacy relationship-list selectors: promoted manager slots `0x88` (`0x004f1f70`) to **64.15%**, `0x98` (`0x004f2100`) to **73.77%**, and `0x94` (`0x004f21f0`) to **30.06%** as a first broad shape pass. This adds `TSortedByRelationshipList` vtable `0x00654d38`, list slots `0x24`/`0x2c`/`0x38`, and proves slot `0x94` is side-effect target selection rather than a relation-code setter. `ProcessQueuedWarTransitions` (`0x004f0a10`) consequently improved to **89.85%**. Next high-yield targets remain manager slot `0x28` (standing score setter) and slot `0x80` (side-effect propagation), because they feed the relation setter and the selector matrix at `+0x1402`.
27. Diplomacy standing-score setter: promoted manager slot `0x28` (`0x004efcb0`) to **34.55%** as a broad shape pass. This proves standing-score clamps, symmetric `+0x79c` writes, manager slot `0x2c` minor-standing propagation, and terrain descriptor slot `0x5c` minor-link checks. The relation setter (`0x004f1b70`) is now **24.84%** with slot `0x28` resolved. Next high-yield backend target is slot `0x80` / the `0x004eff40` propagation cluster, with Ghidra function-boundary care because the current project does not expose `0x004eff40` as a direct function start.
28. Diplomacy standing matrix copy: promoted manager slot `0x2c` (`0x004efe30`) to **36.07%**, correcting the prior generic minor-propagation label. It copies both row and column in the `+0x79c` standing-score matrix and is the slot called by `0x004efcb0` after terrain slot `0x5c` identifies linked minor standing updates. Next high-yield target remains slot `0x80` (`0x004eff40`) after resolving the stale Ghidra boundary/decompile mismatch.
29. Foundation port (stream hierarchy): ported TFileStream / TCountingStream / THandleStream wrappers (class-name accessor, base-state constructor returning `this`, scalar-deleting destructor, CObject vtable-reset `_Impl`) into `src/game/stream.cpp`. 9 functions at **100%**, the two ILT-routed destructors at **90.91%** (call-pairing residual). Teardowns reset the vptr to the shared CObject runtime vtable `0x0066fec4`. These wrappers are favor-speed, unlike the favor-size collection engines.
30. Diplomacy side-effect propagation: promoted manager slot `0x80` (`0x004eff40`) to **27.33%** as a first broad shape pass. This locks in the relation-side-effect path from slot `0x74` through slot `0x80`, manager slot `0x84`, terrain slot `0x90`, and standing-score slot `0x28`. Do not micro-tune this function yet; the next high-yield diplomacy moves are the adjacent relation-event helpers around `0x004efeb0`/`0x004f01e0` and any remaining slot signatures that clarify the manager vtable.
31. Diplomacy relation/alliance slot cleanup: promoted manager slot `0x78` (`0x004f1b40`) and slot `0x8c` (`0x004f2050`) to **100.00%**, and promoted slot `0x90` (`0x004f2090`) to **35.71%** as a signature-correct first pass. This confirms the manager relation-code final wrapper and the major-alliance count/Nth-allied-major selectors used by AI/economy callers. Next high-yield diplomacy work should migrate raw/provisional callers of slots `0x78`/`0x8c`/`0x90` in `TGreatPower`/`TCountry` where they are already in manual source, then move to the remaining relation-event helper `0x004efeb0` or the broader turn application path.
32. Diplomacy relation-code-4 wrapper: promoted manager slot `0x7c` (`0x004efeb0`) to **92.31%**, proving it is a three-arg `ret 0xc` method despite the stale two-arg Ghidra prototype. The slot delegates to `0x78` with relation code `4`, optionally calls `0x80`, then notifies target terrain slot `0x94` and queues event `0x18`. The mid-range manager vtable is now shaped through `0x98` except the older anonymous/non-diplomacy-looking slots below `0x44` and `0x64`/`0x68`/`0x6c`; next high-yield work can either migrate manual `TGreatPower`/`TCountry` callers to the confirmed facades or start the broad `0x004f01e0` turn-application pass with its adjacent nation-state slots.

26. Foundation engine port (CPtrList + CObArray, favor-size lever): ported the full MFC `CPtrList` linked-list (`NewNode`/`FreeNode`/`AddHead`/`AddTail`/`RemoveHead`/`RemoveTail`/`InsertBefore`/`InsertAfter`/`RemoveAt`/`Find`/`RemoveAll` + `CPlex` block helpers) and the `CObArray` engine (`SetSize`/`SetAtGrow`/`InsertAt`/`RemoveAt`) as real methods. **15 functions at 100%** plus the two list/array destructors lifted 81.82%→**100%**. The lever: MFC foundation code is favor-size — `#pragma optimize("ys", on)` (FPO + favor-size) on the engine regions; outer wrappers stay favor-speed (`"yt"`). `SetSize` 72.17% / `InsertAt` 47.62% retain compiler-internal residuals. See INSTRUCTIONS notes 65–67.

25. List ctor/factory matching pass (EH-`new` + RefCountedObjectBase): closed the recurring MFC ctor and `new T()` factory shapes. Constructor return-`this` + vtable-as-data-symbol took `CPtrArray` (`0x00601baa`) and `CPtrList` (`0x00601f1d`) to **100%** (also corrected the embedded list vtable to the real `0x672eec`). The inline-`operator new`/`operator delete`/ctor + `return new T()` recipe reproduces the MSVC EH cleanup frame (`push -1; push __ehhandler`) that was the project-wide ~52% factory ceiling: `0x00488400` → **94.12%** (residual one C++ vptr write from `TIndexAndRankList` virtuals, kept so slot-dispatch sibling `0x00488110` stays 100%). Modeling `RefCountedObjectBase` as a real base of `TPtrList` (inline vtable-installing ctor + non-trivial dtor, matching `InitializeRefCountedObjectBaseVtable` `0x00484970`) added the post-base EH-state transition and took `TSortedList::CreateTSortedListInstance` (`0x00487a90`) to **100%**. See INSTRUCTIONS notes 61-64.

27. TSortedByRelationshipList and TSortByPriceList alignment: Fully matched TSortedByRelationshipList constructor-inlining and factory creation (`0x004ee4b0`) and qualified constructor-base initialization (`0x004ee540`) at **100.00%**. Integrated `TSortByPriceList` (`0x00659ef0` vtable) and aligned all 6 methods (including `AllocateAndConstruct`, `Construct`, `GetClassName`, `Destruct`, and `Compare`) at **100.00%** (or **90.91%** for thunk-routed destructors).

28. Diplomacy list-struct migration: replaced the two misnamed local raw structs in `diplomacy_state.cpp` with the real foundation classes — the queue (`slot 0x18d4`) is a `TSortedPtrList` (vtable `0x00649068`) and the relationship-candidate lists are the real `TSortedByRelationshipList` (vtable `0x00654d38`). Removed `ConstructTPtrListObject`, `kVtableTPtrList`, and the manual vtable writes. `InitializeDiplomacyTurnStateManagerDefaults` (`0x004ee7a0`) rose **67.72% -> 69.29%**, all neighbors held, aligned count steady at **141**. See worklog + INSTRUCTIONS note 74.

29. Diplomacy turn-application reconstruction: promoted `ApplyDiplomacyInterNationStatesForTurn` (`0x004f01e0`, 739 bytes) from a 0% stub to **47.62%** as a `DiplomacyTurnStateManager` method (correcting Ghidra's stale `TSortedByRelationshipList` bucket), thunk `0x004020b8` to **100%** (aligned count 141 -> 142). Recovered the localization-phase gate, the `0x1c8`/`0x1cc`/`0x1e0` per-nation passes, the 7×23 relation loop with `relationSideEffectMatrix1402` symmetric flag writes + `0x12`/`0x14` event queueing, and the four-`StringShared` EH-RAII scratch frame. Residuals are loop-induction register allocation and the EH-state encoding. See worklog + INSTRUCTIONS note 76.

Session totals (2026-06-02): Cleaned up MFC foundational class substrate and mapped TSortedByRelationshipList and TSortByPriceList subclasses. Total aligned function count increased to 138 (+8 delta).

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
