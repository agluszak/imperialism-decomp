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

## RTTI / vtable follow-ups
- cat-C/D missing-vtable follow-ups (see memory `rtti-vtable-audit-2026-06`): watch
  secondary/aspect vtables; 193 resolved is a subset.
