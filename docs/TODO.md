# TODO

Living backlog. Keep entries actionable with addresses; move durable design notes to
`docs/reference/`. See also `docs/reference/initinstance-port-plan.md`.

## Game init & asset loading

Goal: port the asset-loader functions that sit on top of the (already real)
`TModuleLibraryCacheTableStateB` and `g_pModuleLibraryCacheState` (0x6a134c), and remove the
`reinterpret_cast` calling-convention hacks at their call sites. **No new `reinterpret_cast`s**
(use `static_cast`/typed pointers/real types); **do not port MFC/Win32 library code** (link it).
Almost every cast-hidden callee here is a real `__thiscall` method — model the real class.

### Done
- `1fbc9bcf` — Deleted the duplicate shadow `ModuleLibraryCacheState` struct in
  `TDiplomacyMapView.cpp`; uses the real `TModuleLibraryCacheTableStateB` and calls
  `LoadBmpResourceByIdCached`/`ReleaseRecordByHandle` directly. Moved the
  `g_pModuleLibraryCacheState` definition (GLOBAL 0x6a134c) to the owning cpp.
- `78744872` — Modeled the sound/wave manager at **0x6a60c0** as real class
  `TSoundResourceManager` (`include/game/TSoundResourceManager.h`) + abstract `TAudioChannel`
  interface (real virtuals at verified slots 0x30/0x34/0x3c, Hard Rule 12). Ported two
  `__thiscall` methods and removed two of TSoundPlayer's three dummy-edx fastcall casts:
  - `UpdateLocalizationAudioSlot` @ 0x49c240 (54.90%)
  - `SetChannelVolumesUntilAccepted` @ 0x49c850 (68.75%)

### Next: bitmap loader keystone (most tractable)
Port **`BuildIndexedBmpResourceById` @ 0x499b40** as a real 4-arg `__thiscall` method on the
*existing* `TModuleLibraryCacheTableStateB`:
`void* BuildIndexedBmpResourceById(short id, int w, int h, int flag)` (callsite evidence:
`cache->BuildIndexedBmpResourceById(field1c, 0x42, 0x42, 0)`; callee does `RET 0x10` = 4 args).
- 642-byte body; sub-callees: `AllocateBitmapSurfaceHeaderAndPixelBuffer`,
  `BuildPaletteFromBitmapColorTable`, `InitializePaletteHolderVtableAndReset`,
  `FindShortKeyHashNodeAndOutputBucketIndex`, `RemoveHashIndexedRecordByShortKey`,
  `BuildIndexedBmpResourceById_Impl` @ 0x49b190. `AllocateWithFallbackHandler(n)` = MFC
  `operator new` (`new T()`), not a stub.
- Unblocks (then port / de-cast):
  - **`TAnimation::EnsureBitmapResourceLoadedAndCopyRectSize` @ 0x495b70** — currently a stub
    (`src/game/TAnimation.cpp`); clean once the cache method exists. Body calls
    `cache->LoadBmpResourceByIdCached(field1c)`, `cache->BuildIndexedBmpResourceById(field1c,
    0x42, 0x42, 0)`, then `CopyOffset10PointPairToOutOrZero` into fields +0x08..+0x14.
  - **`TPicture::SetPictureResourceIdAndRefresh` @ 0x48f570** casts in `src/game/TPicture.cpp`:
    `BuildIndexedBmpResourceById`, `SetPictureResourceIdAndRefresh_Impl` @ 0x48f610, and the
    decrement-refcount thunk (`thunk_DecrementDialogResourceRefCountByShortIdAndCleanup`).
    Note: this callsite uses a shared stack-frame across `_Impl` (0x408d73→0x48f610) and the
    bmp builder — the 4 args are laid out by the `_Impl` setup. Messier than TAnimation; do it
    after the cache method + TAnimation.

### Next: wave sub-system (largest)
Remove TSoundPlayer's remaining fastcall cast (`CallLoadWaveResource`) by porting
**`LoadWaveResourceByNumericIdAndBuildBuffer` @ 0x49c430** as a `TSoundResourceManager` method.
Blocked on recovering the wave sub-system it calls (both are `__thiscall`):
- `ReadWaveDataAndFormatViaLoaderWithRetry` @ 0x49c720 (thiscall — needs `this`; likely the
  wave-descriptor `local_64`).
- `LoadWaveDataAndFormatFromFilePath` @ 0x5e10c0 (6-arg, `MMRESULT`, Win32 MMIO wave parser;
  MMIO/Global* are LIBRARY — call directly).
- The `local_64..local_58` locals form a wave-format descriptor struct; model it to call the
  thiscall helper without a cast. The wave module handle is `TSoundResourceManager::m_module`
  (+0x30); resource type tag `"MEM "` (0x204d454d).

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
annotations. **Cat B (5 classes) is DONE** (commit "annotate 5 RTTI-evidenced
class vtables"). Cat C / Cat D remain.

### Cat C — classes that exist only as forward-decl structs in `root_types.h`

Each has a raw `src/ghidra_autogen/<Class>.cpp` dump (GHIDRA_FUNCTION, banned
scaffolding — reference only, NOT reccmp-paired) but no real
`include/game/<Class>.h`. Recovery recipe per class: create the class header
`class TX : public TBase` + `// VTABLE: IMPERIALISM <addr>`, declare the
override slots (addresses below) as real virtuals in slot order, port honest
bodies into a manual `src/game/TX.cpp` with `// FUNCTION:` markers (no manual
vptr writes / `*AndMaybeFree` / `FreeHeapBufferIfNotNull` scaffolding), then
`just sync-ownership` → `just regen-stubs` → `just build` → `just vtable TX`.
The autogen struct in `root_types.h` can stay (separate TU; same name/layout,
MSVC tags don't affect mangling). Slot 0x00 = `GetRuntimeClass`, slot 0x01 =
scalar deleting destructor (claim via SYNTHETIC + symbols.csv backtick name;
verify it isn't COMDAT-folded across vtables first, à la TAmbitApplication).

Tractable (single inheritance, primary vtable, modest override counts):

None currently.

Done:

| Class | vtable | base (vtable) | override slots |
|---|---|---|---|
| TBattleReportView | 0x0063efa8 | TDiplomacyMapView (0x00655b68) | 9: 0x00,0x01,0x07,0x0f,0x13,0x35,0x37,0x44,0x47 |
| TShipOrder | 0x0064f738 | TProductionOrder (0x0064fa18) | 9: 0x00,0x01,0x0b,0x0c,0x0d,0x10,0x11,0x12,0x13 |
| TCityProductionView | 0x0064fc20 | TNoHilitePicture (0x006606e8) | 17: 0x00,0x01,0x07,0x0f,0x35,0x37,0x44,0x47,0x68,0x74,0x75,0x76,0x77,0x78,0x79,0x7a,0x7b |

`TBattleReportView` recovered 2026-06-27 as a real
`TDiplomacyMapView` subclass with primary vtable **0x0063efa8** and size
0x24d0. Slot 0x01 is modeled as the real scalar-deleting destructor at
0x00430a30; the class cleanup at 0x004ad560 is the slot 0x07 `Free()` override
that releases the transient registry object through the real `TAnimator`
receiver. `just vtable TBattleReportView` passes.

`TShipOrder` recovered 2026-06-27 as a real `TProductionOrder` subclass with
its slots moved out of the temporary `TCapacityOrder` ownership. The shared city
stock block is now modeled as named `TCity::cityStock*` commodity fields rather
than the old offset-array/offset-helper surface; `just vtable TShipOrder` and
`just vtable TCapacityOrder` both pass.

`TCityProductionView` recovered 2026-06-27 as a real
`TNoHilitePicture` subclass with 15 manually owned function bodies moved out of
generated stubs; `just vtable TCityProductionView` passes (one vtable found).


Done:

- **TDiplomacyMapView** recovered 2026-06-27 as a real `TPicture` subclass with
  primary vtable **0x00655b68**. Constructor listing calls `TPicture::TPicture`
  (`0x0048efc0`), not `TPictureButton`; this keeps slot 0x73 as an introduced
  one-argument legend/render virtual instead of conflicting with
  `TPictureButton::IsSelected()`. The stale 0x0066f16c vtable row was renamed
  to `g_TViewMgrTurnEventDispatchTable` as a data boundary; it is a turn-event
  dispatch/data table or RTTI-resolver mis-hop, not an object vtable. `just
  vtable TDiplomacyMapView` passes.

Hard:

None currently.

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

## `IsSelected` (slot 0x73) per-branch arity reconciliation — DONE 2026-06-27

Slot 0x73 (`IsSelected`, offset 0x1cc) is **not a single shared virtual**. The
source now models the verified branch arities:

| Branch | Body addr | Verified arity |
|---|---:|---:|
| TToggleButton / T2PictToggleButton | 0x571330 / 0x5849b0 | 0 |
| TPictureButton (+ inherited button subclasses) | 0x5708c0 | 0 |
| TUpDownPictureButton (+ TCivilianButton, TTextPictureButton, TRadioPictureButton, TMadnessButton, TCzechBox) | 0x571690 | 0 |
| TCivReport / TCombatReportView | 0x590cb0 / 0x58c950 | 1 |
| TArmyInfoView / TArmyPlacard / THQButton / TPlacard | varied | 2 |

Verification notes: Ghidra listing showed `TPictureButton::IsSelected` returns
with plain `RET`; `TUpDownPictureButton::SetControlStateFlagAndMaybeRefresh`
calls slot 0x1cc with no argument pushes; `TCivReport` and
`TCombatReportView` both return with `RET 0x4`. `just build` passed, and
filtered `just vtable` checks for `TPictureButton`, `TUpDownPictureButton`,
`TCivReport`, and `TCombatReportView` were 100%.
