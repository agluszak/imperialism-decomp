# TODO

Living backlog. Keep entries actionable with addresses; move durable design notes to
`docs/reference/`. See also `docs/reference/initinstance-port-plan.md`.

## QuickDraw text-engine recovery (follow-up to the 2026-07 thunk retirement)

The cached text-style engine behind the remaining `quickdraw_rendering.h` typed
wrappers is unrecovered. Recovering it retires four Hard-Rule-9 casts and ports the
whole text-draw path:
- Singletons: `0x6a1da0` / `0x6a1d9c` (cached text-style context objects; vtable
  dispatch at `+0x04`, `+0x30`), lazy font handle `0x6a1d48`, dirty flag `0x6a1d56`.
- Bodies to port once the class exists: `DrawTextWithCachedQuickDrawStyleState`
  @ `0x494a90` (262b), `MeasureTextExtentWithCachedQuickDrawStyle` @ `0x494e00`
  (393b), `SetQuickDrawTextOriginWithContextOffset` @ `0x497c80` (102b, needs the
  `0x489a70` DC getter), `DrawCenteredGuideLineOnMapDc` @ `0x497d10` (376b).
- Style-descriptor family in the same TU: `BuildUiTextStyleDescriptor` @ `0x5c3e80`,
  `ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor` @ `0x5c4470` (3 args),
  `InitializeUiTextStyleDescriptorAndApplyQuickDraw` @ `0x5c4500` (4 args),
  `InitializeUiTextStyleDescriptor`.

## RenderTerrainAndMinorNationLegendLabels @ 0x4f4a30 (920b)

Really `__thiscall TDiplomacyMapView::RenderTerrainAndMinorNationLegendLabels(RECT*)`
(ecx=this, one stack arg = present rect; callee-clean). Two callsites in
`TDiplomacyMapView.cpp` still bridge it via a zero-arg `__fastcall` cast so the
rebuilt stack stays balanced against the no-arg stub. Porting needs:
- label-rect arrays at `this+0x234` (terrain) / `this+0x2a4` (minor nations),
  16-byte records, probed by `ProbeRectEmptyAfterCopyToLocal` @ `0x498b10`;
- `FormatOverlayTerrainLabelText` @ `0x4d7860`,
  `LoadNationDisplayNameSharedRefFromField8` @ `0x4d7a40` (already owned by
  TGreatPower.cpp), and the text-engine ports above.

## SetUiResourceContextTagWord @ 0x4270e0 is __thiscall with unknown receiver

Body is `*(dword*)this = param`. Callsites (TDiplomacyMapView 3x, TMapDialog, ...)
still call the old no-arg thunk shape and drop the palette-index argument; the
receiver object (ecx at the callsites) must be identified from the listing before
retyping. Same family: `thunk_WrapperFor_InvalidateCityDialogRectRegion_At004f6d90`
(real body `0x4f6d90`, 513b, a `TDiplomacyMapView` cursor-mode method worth porting).

## TSimMgr field-offset comment drift

`TSimMgr.h` field comments drift by 4 from `field_64` onward (`preferenceValues` is
`+0x44..+0x5f`, so `field_64` sits at `+0x60`, `pad68` at `+0x64`, ...). Verify against
the ctor listing and fix the comment names.

## Remaining thunk_ clusters (post 2026-07 QuickDraw retirement; 136 refs left)

- `thunk_SetGlobalUiInvalidationFlagAndReturnPrevious_At0049d9xx` (7 leaves,
  0x49d900..0x49da80, 35 refs): vtable-slot bodies on the TAdorner family whose
  release body is the assert-macro flag pulse
  (`prev = SetFlag(0); SetFlag(prev); ret 4`, one ignored arg). Port as real slot
  bodies using the TemporarilyClearAndRestore helper shape and rename per slot role.
- `thunk_ComputeHexNeighborTileIndices_At005a1400` (7 refs) and
  `thunk_NormalizeWrappedMapCoord108x60` (4 refs): map-geometry leaves, likely
  cleanly portable free functions.
- `thunk_BuildUiTextStyleDescriptor_At005b62e0` (7 refs): TDeluxeText slot 0x78
  body — part of the text-engine recovery above.
- `thunk_SetUiControlVisibleFlagAndMaybeRefreshWindow_At00570de0`,
  `thunk_DeleteObjectIfNonNullViaVslot04_At004b5ed0`,
  `thunk_InvalidateMapRegionForOrderEntry`,
  `thunk_InitializeDirectSoundDeviceAndChannels`, NoOpCallback pairs — small
  per-callsite jobs; verify receiver/convention before retargeting.

## TMilitaryUnit full class recovery (follow-up to the 2026-07 mission-scoring cleanup)

The TStationedUnitNode/TMilitaryUnit split is merged (one class, RTTI 0x66ed70, size
0x44, base TObject) with a field/getter surface model. Still to port: constructor and
CreateObject @ 0x5c2cb0 (217b), GetRuntimeClass @ 0x5c2dd0, vtable annotation +
serialization (needs the TObject WriteTo/ReadFrom slots), and the sibling classes
TUnit (0x66ed40, ctor 0x5c2430, size 0x24) / TCivUnit (0x66ed58, ctor 0x5c2860,
size 0x28). Fields 0x08-0x13, 0x1c-0x23, 0x28-0x33, 0x3a-0x3f are still pads.

## Remaining dropped-arg typedef casts in TDefendProvinceMission 0x53e6e0

The mission-scoring cleanup fixed the accumulate/weight family, but the same body still
calls through zero-arg casts that likely drop real arguments (verify each receiver/args
in the listing before retargeting): `ComputeAggregateWeightedChildCostForMatchingType5NavyOrders`
@ 0x557170 (called per nation with no nation arg!), `TileHasMovementClassId` @ 0x515e50,
`AreAllLinkedEntriesTerrainFlagBit2Clear` @ 0x518a20. `just typedef-cast-audit` reports
cross-file signature drift for this pattern class.

## Library-region residue: what actually remains (post 2026-07 audit)

State: 1,075 generated LIBRARY markers; ~370 unmarked function rows remain in the FID
range 0x5e539c..0x626c7d. Findings from the extension attempt:

- The `prototype` column's embedded mangled names are NOT trustworthy for identity
  (12 different addresses all carried `?Create@CHotKeyCtrl@...`); only the `symbol`
  column and unique demangled-name matches are, and those yielded just 4 new markers
  (CDragListBox::Dropped, _abort, CDC::GetClipBox, CPaintDC ctor).
- LIBRARY-marking an *unlinked* library function scores 0.00% (the recomp contains no
  body to pair — the linker never pulls the .obj member because no recomp code
  references it). More markers alone do not raise scores; the lever is either real
  linkage (arrives naturally as ported code calls into MFC/CRT) or a report-policy
  decision to exclude unlinked library code from the compared set.
- 22 identified rows are blocked as `skip_referenced_project_alias`: manual code still
  references the stub name through Hard-Rule-9 externs (e.g. AfxGetMainWnd,
  FromHandlePermanent). Migrating those callsites to the real MFC declarations
  releases them.
- The ~350 remaining unnamed rows need a masked-byte matcher against the
  fid-generation Ghidra project's .obj programs (FID skipped small/common bodies —
  see vendor/msvc500/fid-generation/fidb/common.txt). Positional context helps:
  unmatched runs between two FID-matched neighbors from the same .obj follow the
  .lib member order.
- `tmp_decomp/msvc500_fid_matches.csv` is the tool's complete source of truth and is
  gitignored; it can be reconstructed from src/game/library_msvc500_fid.cpp marker
  pairs + fidb/functions.txt obj paths. The tool now refuses to shrink the marker set
  without --allow-marker-removals.

## Global-data xref oracle: apply loop + disputed annotations

`just global-xref-oracle` (tools/reccmp/global_xref_oracle.py) mines reccmp asm
diffs for (original address <-> recomp symbol) global pairs; round 1 applied 32
rows (`provenance=xref_oracle` in symbols.csv) and moved 31 functions to 100%
with zero regressions. The loop is at fixpoint for auto-application; what
remains is its *dispute list* — places where existing annotations disagree with
observed instruction alignment (verify in Ghidra before touching):

- `g_pDisplayMgr`: annotated at 0x6a2158, oracle votes 6x for 0x6a436c.
- The nation-state pointer block 0x6a4310..0x6a43d8: cross-votes between
  g_apNationStates / g_apTerrainTypeDescriptorTable / g_pLocalizationTable /
  g_pUiRuntimeContext suggest one or more rows in that run are off by a slot
  (0x6a438c currently rowed as g_apNationStates_End but votes as
  g_pLocalizationTable; 0x6a20f8 rowed g_pLocalizationTable, votes
  g_pUiRuntimeContext).
- 0x63e044 rowed g_pRegistrySettingsSectionAlt_0063E044 but recomp aligns it
  with DAT_006a1348 usage.

Extensions worth building: the same mining for (STRING) refs (1,162 orig-only
strings) and (FLOAT) refs (275 original float-pool constants, 0 paired — the
recomp side reports no FLO entities at all, so check whether the reccmp fork
detects MSVC500 constant pools before blaming annotations).

## Misleading-name backlog (spotted 2026-07, not yet renamed)

- `GetSurfaceObjectAtContextOffset24` returns `context->surfaceObject`
  (a `TBitmapSurfaceNode**` handle) — "AtContextOffset24" is stale now that the
  field is typed.
- `GetSurfaceHeaderFromSurfaceObject` @ `0x497300` actually returns
  `(*handle)->pixelBits` (the pixel buffer), not a header.
- `WrapperFor_FreeHeapBufferIfNotNull_At00413550` family — several are
  surface/record slot releasers like the renamed
  `FreeQuickDrawSurfaceContextSlot` @ `0x4feb50`; audit per address.
- `ApplyAuxOutputVolumeFromScalar` @ `0x593cb0` (22b) scales 0-255 to 0-65280 and
  calls `0x47cdd0` (likely waveOut/aux volume) — port both, then retire
  `WrapperFor_thunk_ApplyAuxOutputVolumeFromScalar_At00593cb0` in TTwoPicSlider.

## Backdrop window bring-up under `just debug`

Goal: get the first visible window on screen by recovering the loading/backdrop
window as real C++ rather than stubs or vtable facades. **Runtime confirmed (2026-06):**
backdrop window is visible under `just debug`; main-frame reveal/teardown still needs
shape work.

Current recovered surface:
- `TBackdropWindow` cluster: `0x49cb90..0x49cfa0`.
- Retail base vtable: `0x670b4c`; retail derived vtable: `0x64bca8`.
- Object size: `0x40`; important fields: `CWnd::m_hWnd` at `+0x1c`, backdrop BMP
  handle at `+0x3c`.
- Guarded creator: `WrapperFor_AllocateWithFallbackHandler_At0049cc60` @ `0x49cc60`
  (reads `g_cachedShowSplashFlag`; see `docs/reference/initinstance-port-plan.md`).
- Inner init: `CreateGlobalBackdropWindowWithDefaultBmp3B6` @ `0x49cca0`.
- Input refresh/destroy path: `RefreshBackdropOnInputMessages` @ `0x49cdf0`
  (slot `0x18` / `CWnd::DestroyWindow` in the observed window flow).
- Backdrop initializer: `TBackdropWindow::InitializeDefaultBackdropWindowFromBmp3B6`
  @ `0x49ce90`.
- Teardown/reveal path: `TBackdropWindow::PostNcDestroy` @ `0x49cfa0` (retail vtable
  slot `0x2b` ILT → this body).
- Globals: `DAT_006a2050` (backdrop `TBackdropWindow*`), temp map/wait-cursor buffer
  `DAT_006a2054`, cached splash flag `g_cachedShowSplashFlag` @ `0x006a2018`
  (`CCommandLineInfo::m_bShowSplash` as `BOOL` — **not** a filename pointer or shell command).

Remaining work:
1. Verify the `TBackdropWindow` base model. The class is structurally `CWnd`-derived,
   but the repo's current MFC vtable model emits extra OLE/dispatch slots for
   `CWnd`-derived classes, so do not force a `// VTABLE:` annotation until the inherited
   slot surface can compare honestly. Keep calls as real methods/virtuals; no raw
   `vftable[]`, no `VCall_*`, no constructor bridge.
2. Runtime proof of teardown trigger: verify the teardown releases the BMP, nulls
   `DAT_006a2050`, releases `DAT_006a2054` if needed, and calls
   `CMainFrame::ConfigureTopLevelWindowStyleAndPlacement` so the hidden main frame
   becomes maximized/visible.
3. Shape passes for remaining functions (all currently 50-75%):
   - `0x49cfa0` ~60% - teardown path
   - `0x49d090` ~50% - OnCreate wait cursor logic
   - `0x49ce90` ~75% - BMP initialization
   - `0x49cdf0` ~75% - input refresh
   - `0x49cca0`/`0x49cbf0` ~31–33% - creator path
4. Verification loop for this batch:
   - `just regen-stubs && just build`
   - `just compare 0x0049cbf0 0x0049cca0 0x0049cdf0 0x0049ce90 0x0049cfa0 0x49d090 0x49d180`
   - `just gates`
   - `just stats` and `just stats-baseline-update` once the runtime path is accepted

Current compare snapshot (2026-06-30): `0x49ce90`/`0x49cdf0`/`0x49d180` ~75%,
`0x49cfa0` ~60%, `0x49d090` ~50%, `0x49cca0`/`0x49cbf0` ~31–33%.
`0x49cc60` on reccmp ignore list.

Updated 2026-06-30: Wired teardown trigger in source; shape passes completed for all functions.
All gates passing (vtable 100%, datacmp OK).

### Main-frame paint follow-ups (2026-07-02)

Backdrop teardown and the main-frame reveal now work. The remaining blank-client-area
gap is downstream: painting reaches a TView tree only through a realized `TWindow`
whose `CMcWindow::OnPaint` starts slot-0x43 recursion. `CIncludeView` is not that paint
host (no `WM_PAINT` map entry; no-op `OnDraw`).

Open work:
- Identify where the original builds and realizes the main-screen `TWindow` (window
  registry / `TViewMgr` / CreateTWindowInstance chain), then route
  `BuildStartupIntroBackground` through that host instead of the current
  `nativeWindow50` shortcut.
- Port the remaining CMcWindow message handlers if they block the realized host path
  (`WM_LBUTTONDOWN/UP`, `WM_MOUSEMOVE`, `WM_CLOSE`, `WM_KEYDOWN/UP`, `WM_SHOWWINDOW`,
  palette messages, `WM_CHAR`, custom `0x468`/`0x36a`).
- Trace the `TMovieView` created after the startup background picture
  (`TMovieView` size 0x94, ctor `0x5e2230`) and decide whether it is load-bearing for
  the first screen.

## Game init & asset loading

Goal: port the asset-loader functions that sit on top of the (already real)
`TModuleLibraryCacheTableStateB` and `g_pModuleLibraryCacheState` (0x6a134c), and remove the
`reinterpret_cast` calling-convention hacks at their call sites. **No new `reinterpret_cast`s**
(use `static_cast`/typed pointers/real types); **do not port MFC/Win32 library code** (link it).
Almost every cast-hidden callee here is a real `__thiscall` method — model the real class.

### Next: picture resource tail
The bitmap cache keystone is now typed: `BuildIndexedBmpResourceById` @ 0x499b40 and
`ReleaseRecordById` @ 0x49a190 are real `TModuleLibraryCacheTableStateB` methods, and
`TAnimation::EnsureBitmapResourceLoadedAndCopyRectSize` @ 0x495b70 uses the typed cache API.
The remaining `TPicture::SetPictureResourceIdAndRefresh` @ 0x48f570 cast is the shared-frame
`SetPictureResourceIdAndRefresh_Impl` @ 0x48f610 thunk/setup path.

### Next: wave sub-system (largest)
Remove TSoundPlayer's remaining fastcall cast (`CallLoadWaveResource`) by porting
**`LoadWaveResourceByNumericIdAndBuildBuffer` @ 0x49c430** as a `TSoundResourceManager` method.

**Followup from backdrop window work (2026-06-30):** After completing backdrop window teardown trigger wiring,
continue with wave sub-system porting to remove remaining fastcall casts in TSoundPlayer.

Current source surface:
- `include/game/TSoundResourceManager.h` already declares
  `int LoadWaveResourceByNumericIdAndBuildBuffer(unsigned int waveId, int slot);`
  but `0x49c430` is still stub-owned.
- `src/game/TSoundPlayer.cpp` still has `CallLoadWaveResource`, which casts the `(void)` stub
  to a fake `__fastcall(void*, int, int, int)` and passes raw manager address `0x6a60c0`.
  Replace that helper with:
  `g_soundResourceManager.LoadWaveResourceByNumericIdAndBuildBuffer(sfxToken, slot)`.

Recovered evidence from listings:

| Address | Evidence | Source model |
|---------|----------|--------------|
| `0x49c430` | saves `ECX`, reads args at stack, `RET 0x8`, reads `this + 0x30` | `TSoundResourceManager::LoadWaveResourceByNumericIdAndBuildBuffer(unsigned int waveId, int slot)` |
| `0x49c720` | saves `ECX` in `EBX`, indexes `[this + slot * 4 + 0x04]`, reads `[this + 0x24]`, `RET 0x8` | `TSoundResourceManager::ReadWaveDataAndFormatViaLoaderWithRetry(WaveLoadDescriptor* desc, int slot)` |
| `0x5e10c0` | 6 pushed args from `0x49c430`; consumes file/resource descriptor and fills wave data/format pointers | free helper `LoadWaveDataAndFormatFromFilePath(...)`; do not model Win32 MMIO/Global APIs |

Porting checklist:
1. Add a small local wave-load descriptor type in `TSoundResourceManager.cpp` for the stack locals
   currently decompiled as `local_64..local_58`:
   - two scalar fields at descriptor offsets `+0x00`, `+0x04`;
   - locked data pointer at `+0x08`;
   - format/data pointer at `+0x0c` (verify exact names from `0x5e10c0` before widening).
2. Add the resource-backed loader descriptor used at `0x49c579..0x49c5e7`:
   - zeroes `0x12` dwords starting at the local resource descriptor;
   - writes resource type tag `0x204d454d` (`"MEM "`);
   - stores `LoadResource(m_module, hResInfo)` and `SizeofResource(m_module, hResInfo)`;
   - calls `LoadWaveDataAndFormatFromFilePath(0, &desc.field0, &desc.field4, &desc.data,
     &desc.format, &resourceDesc)`.
3. Declare only real helpers:
   - `LoadWaveDataAndFormatFromFilePath` as a free helper with its six verified stack args;
   - Win32/CRT/MFC calls (`FindResourceA`, `LoadResource`, `SizeofResource`, `GlobalHandle`,
     `GlobalUnlock`, `GlobalFree`, `CString`) as existing library/MFC APIs, not game stubs.
4. Port `0x49c720` in the same batch if `0x49c430` needs it for a cast-free body. This function
   is a `TSoundResourceManager` method, not a free function: it uses `this->m_channels[slot]` and
   manager field `+0x24`.
5. Before adding more `TAudioChannel` declarations, verify the channel ABI from the listing.
   The new slots used by `0x49c720` (`0x2c`, `0x4c`, `0x50`) push the channel pointer explicitly
   before calling through the vtable, which may be DirectSound/COM-style rather than the normal
   C++ virtual shape currently used for slots `0x30`, `0x34`, and `0x3c`. Do not paper this over
   with a `reinterpret_cast`; recover the receiver shape or stop with the blocker documented.
6. Once both methods are real, update:
   - `config/symbols.csv` rows for `0x49c430` and `0x49c720`;
   - `config/function_ownership.csv` via `just sync-ownership`;
   - generated stubs via `just regen-stubs`;
   - `src/game/TSoundPlayer.cpp` to delete `LoadWaveResourceByNumericIdAndBuildBuffer(void)` and
     `CallLoadWaveResource`.
7. Verification loop:
   - `just regen-stubs && just build`
   - `just format-check include/game/TSoundResourceManager.h src/game/TSoundResourceManager.cpp src/game/TSoundPlayer.cpp`
   - `just compare 0x0049c430 0x0049c720 0x005e50c0`
   - `just build && just gates && just stats`

### Init-chain shape passes (Phase 2 — low risk, no casts, no new classes)
Raise already-ported init functions (pure shape/data passes), most tractable first:
- `InitializeGlobalRuntimeSystemsFromConfig` @ 0x49ded0 (61%) — manager-singleton allocation.
- `ExitInstance` @ 0x413780 (79%) — cleanup chain.
- `LoadLanguageResourcesFromIrgFiles` @ 0x4149a0 (22%) — IRG scan (`FindFirstFileA` is LIBRARY).
- `ShowAutoResolutionDialogIfNeeded` @ 0x415090 (29%) / `ApplyAutoResolutionModeAndPersist`
  @ 0x4155b0 (49%).
- `SetUiRuntimeContextAndActivateMain` @ 0x483340 (32%), `SetGlobalDword6A2018` @ 0x49cc40 (44%).
- `InitInstance` @ 0x412dc0 (39%) — last; rises as its callees firm up.

Blocked (need class recovery first, skip for now):
- `WarnLowDiskSpaceAndConfirmContinue` @ 0x415760 (15%) — needs a warning-dialog class.
- `GetMainViewHostFromActiveThread` @ 0x412a70 (stub) — needs a CWinThread slot.

## Missing RTTI-evidenced vtables (audit 2026-06-27)

See memory `rtti-vtable-audit-2026-06`: watch secondary/aspect vtables; 193 resolved is a subset.

Audit method: mine all 458 MFC `CRuntimeClass` descriptors from the binary
(`scratchpad` scripts `dump_rtti_vtables.py` / `vdiff.py` reuse
`tools/ghidra/apply_mfc_rtti.py` helpers), resolve each to its vtable via the
getter→ILT→vtable chain (193 resolved), and diff against our `// VTABLE:`
annotations. The open residue is the disagreement list below.

### Cat D — RTTI vtable addr disagrees with our current annotation

- **CMcWindow** — RTTI resolves 0x00649e74 (slot0 `DestroyChildResourceWindowAndDetach`);
  memory note records the host CWnd vtable as 0x0064b7c8. Likely host-vs-UI
  vtable; reconcile which is the object's primary. Recovery is in progress.
- **TSortedPtrList** — RTTI 0x00649010, but the class already annotates
  0x00649068/0x00654d90/0x00657040. 0x649010 is almost certainly an adjacent
  embedded-collection (sub-object) vtable; confirm and annotate as secondary if real.
- **TPortZone** — RTTI 0x0065c7e4 vs annotated 0x0065c758 (Δ0x8c). Likely a
  resolver mis-hop or a second vtable; verify slot0 before touching.
- **TAutoGreatPower** — RTTI 0x0065c484 vs annotated 0x00654088 (entirely
  different). **TGreatPower TU is codegen-fragile** (symmetric x87 leaves flip
  100%↔42.86% on recompile — see memory [[tgreatpower-tu-codegen-fragility]]).
  Investigate read-only; do not annotate without isolating the TU risk.

## `TNavyMission.cpp` antipattern audit (2026-07-02) — callconv-cast bridges needing class recovery

Ran `just scan-cdecl-thiscall` + disassembly over every `typedef ... __fastcall/__cdecl`
+ `reinterpret_cast` bridge in `TNavyMission.cpp` (the fake-calling-convention pattern the
MSVC500 guardrail flags). One was cleanly promotable and is **done**:
`GetNavyPrimaryOrderListIndexOfNode` (0x550610) → real `TShip::GetIndexInPrimaryOrderList()`,
100% match (commit `39e7e405`).

The rest are all **confirmed genuine `__thiscall`** (not cdecl/fastcall mislabels), but
each needs a real class/manager recovered before the callsite can become `obj->Method()` —
promoting the call type without the receiver would just move the fake-convention problem,
not fix it. Recorded here so a future session can pick one up as its own decomp-loop pass:

- **`SetMapOrderType9AndQueue`** (0x552f80, 282 bytes) and **`PromoteMapOrderChainAndQueue`**
  (0x5533f0, 566 bytes) — both `__thiscall` on what looks like a `TMapOrderEntry`-shaped
  receiver (offsets +8 type/attachment, +0x10 child-list head, +0x14 active node, +0x28/+0x2c
  queue links match `TMapOrderEntry`/`TMapOrderEntryOwnerContext` fields), but the bodies are
  large and cross-call into:
  - `g_pNavyOrderManager` (a global of unrecovered type `TNavyMgr*` — only a forward
    declaration exists today; needs its own class recovery, at least the fields read here:
    `field_0x4` is a head-of-list pointer walked via `+0x2c` links).
  - `TShip::DeleteMapOrderChildLinkAndReturnNext`, `TScatteredShipsMission::SetMapOrderActiveChildEntry`,
    `TScatteredShipsMission::PropagateMapActionContextDistanceLevelsRecursive` — cross-class
    calls into already-partially-recovered classes, but the exact call graph needs mapping.
  - Realloc-based dynamic `int[]` growth logic (candidate for modeling as a real
    dynamic-array member once the owning struct is understood) at offsets +0x28/+0x2c/+0x30
    of some other still-unnamed context object (looks like a per-zone bucket table, possibly
    related to the `TNavyOrderResourceDescriptor` work from the previous session —
    `DAT_00698120`/`DAT_00698124` byte constants appear in both).
  - `FinalizeQueuedMapOrderEntry`, `MoveMapOrderEntryToQueueHeadIfValid`,
    `RecomputeMapOrderChildAggregateMetric` — more unrecovered free functions in the same
    cluster, likely also real methods on the same receiver class.
  - Verdict: this whole cluster is really "recover the map-order queue manager class"
    (probably `TNavyMgr` plus its owned queue/bucket structures), not a small promotion.

- **`SelectBestMapActionContextForNationDiplomacyMask`** (0x560e70, 197 bytes) — `__thiscall`
  on a receiver with fields at +0x28 (array base), +0x30 (count), and calls two vtable slots
  (`+0x38`, `+0x40`) on elements of that array against `g_apTerrainTypeDescriptorTable`. Smells
  like a per-nation "candidate context list" manager, not yet identified. Needs the array
  element's class recovered first (its vtable slots 0x38/0x40 are the actual unknowns).

- **`IsZoneMaskOrArrayEntryPresentForKey`** (0x55f540, 84 bytes) — `__thiscall`, reads a
  bitmask at `this+0x10` and a growable array (`count@+0x40`, `data@+0x38`) of pointers whose
  first byte is compared against the key. Same "unrecovered per-zone/context manager" shape
  as the previous two; likely all three share one receiver class.

- **`ComputeOrderNodeDistanceQuotientByDescriptorWord24`** (0x550550, 51 bytes) — confirmed
  **receiver-agnostic** like heuristics.md #23: called with both a `TZone*`
  (`QueueMissionOrdersByPriorityForContext`'s `targetZone14`) and a `TMapOrderEntry*`
  (`topOrder`) at different callsites, reading the same `+4`/`+8` offsets from both. The `+8`
  field is dereferenced as a `TScatteredShipsMission*` and calls
  `TScatteredShipsMission::GetCachedMapActionContextDistanceOrRecompute` on it — so `TZone`
  apparently has an (unnamed today) field at `+8` pointing at a `TScatteredShipsMission`,
  which needs verifying/naming on `TZone` before this can become a real receiver-agnostic
  free function (same pattern as `ComputeNavyOrderPriorityContributionPercentByCategory`).

Recommended order if picked up: (1) `TZone`'s `+8` field first (small, unblocks #4 above and
is probably reusable elsewhere), (2) the `IsZoneMaskOrArrayEntryPresentForKey`/
`SelectBestMapActionContextForNationDiplomacyMask` manager class (smaller, self-contained),
(3) the `TNavyMgr`/map-order-queue cluster last (largest, most cross-class).

## Class-size mismatches found by `just class-size-check` (2026-07-02)

The RTTI oracle contradicts two modeled layouts (both missing 0x10 bytes):
- `TArmyMission`: ASSERT_SIZE 0x20 vs RTTI 0x30 (include/game/TArmyMission.h)
- `TMinor`: ASSERT_SIZE 0x2cc vs RTTI 0x2dc (include/game/TMinor.h)
Fix via class recovery (fields exist in the binary that the model lacks), then
promote `class-size-check --strict` into `just gates`.

## Networking/orphan-file pass follow-ups (2026-07-02)

Context: NetMessage/TNetMgr::Send/TMultiplayerMgr-emitter remodel, CAmbitDocument
recovery, CList/CArray template-static modeling (commits d959348..this session).

- **Wrong-receiver audit — `GetActiveNationId`.** The real method is
  `TSimMgr::GetActiveNationId` @ `0x581260` (all original callers load
  `g_pLocalizationTable` 0x6a20f8). The networking cluster is fixed, but the rest of
  the repo still calls a fake unmarked `TViewMgr::GetActiveNationId`
  (TViewMgr.cpp:~157, reads this+0x2e via cast) through `g_pUiRuntimeContext` —
  audit every `g_pUiRuntimeContext->GetActiveNationId()` callsite against the
  original ECX load and retarget; then delete the fake TViewMgr helper.
- **Unported TMultiplayerMgr-TU emitters/handlers** (0x540xxx–0x54c band, ~30
  callers of `TNetMgr::Send` not yet in repo): CreateAndSendTurnEvent11/12/1B/1C
  (0x5493c0/0x5494b0/0x5498d0/0x5499b0), DispatchTurnEventPacketWithCodeAndPayloadBuffer
  0x549ad0, DispatchTileRedrawInvalidateEvent 0x54ab20, HandleDiplomacyTurnEventPacketByCode
  0x543910, EnsureGameFlowStateAndPostTurnEvent5E5 0x544540, EmitTurnEvent10ForFlaggedNationSlots
  0x544720, SetNationStatusAwolByNationIdAndDispatchNotices 0x54b930, etc. All are
  `__thiscall` on g_pGameFlowState — check each with the ECX-load test before porting.
  Also `TNetMgr` method @ 0x407f77-ILT target (called right after Send in 0x5456a0),
  and `TProxyGreatPower::AddToNationMetricAtField10` 0x540a00 has an empty repo body
  but the original calls Send at +0x72 (dropped body).
- **DataHunkMessage / PhaseDataMessage (Mac oracle) still unlocated on Windows.**
  Mac signatures: DataHunkMessage::{Create16, ReadData(void*) const, Release};
  PhaseDataMessage::{CheckSync, SetSync}; used by TMultiplayerMgr::DoGameDataHunk /
  ReceiveStreamMessage. They will surface when the receive path
  (TWNetSessionManager::TryReceiveNetworkPacketIntoResizableBuffer callers, WNetMgr
  GetMessage/HandleMessage analogues in the 0x5e3xxx band) is ported. Candidates
  ruled out: 0x487820 is the TCommand base ctor (symbols.csv name
  "ConstructTurnEventPacketBase" is misleading), 0x49e500 news a TNewGameCommand.
  Mac `TEventList` also unlocated (0x66fa50 turned out to be a CList twin copy).
- **TInterNationEventQueueManager playback iterator**: QueueInterNationEventRecordDeduped
  still calls raw-address `__fastcall` casts 0x407919/0x409679/0x4097dc on a
  TPlaybackWalkState — recover the iterator class; also the `thunk_` marker at ILT
  0x406758 (known thunk_ cluster).
- **TGameWindow raw byte offsets** 0x60/0x6d–0x71/0x9c in
  turn_event_dialog_factory.cpp's BuildTurnOrderNavigationWindow — promote to named
  TWindow/TGameWindow fields once the TWindow layout blockers (docs/TODO + memory)
  are resolved.
- **Flavor-text variant generators (18 fns, one original TU)** behind Hard-Rule-9
  externs in mapped_flavor_text.cpp: AppendRandomMapContextStatusSuffixWithProbability,
  GenerateMappedFlavorTextVariantA–E (0x5d13d0/0x5cfc40/0x5cf1b0/0x5d33a0/0x5ccce0),
  BuildMapContextStatusStringVariantA–L, ShouldRetryMappedFlavorTextGeneration —
  port as a dedicated pass (large string builders).
- **TDefendProvinceMission raw cityScoreTable access** (lines ~73/129/306/390):
  byte-offset casts into TGlobalMapCityScoreRecord, including a float read at +0x9c
  where the record declares `int cityScoreValue` — reconcile the dual int/float use
  and use typed fields.
- **Template twin-copy reccmp gap** (systemic): per-TU original copies of
  CList/CArray member functions (e.g. 0x5e4540..0x5e4a60 WNetMgr copies,
  0x479a80/0x479b00 IncludeView copies) cannot pair against the single recomp
  COMDAT — needs reccmp-side support or per-address SYNTHETIC aliasing.
