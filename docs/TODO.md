# TODO

Living backlog. Keep entries actionable with addresses; move durable design notes to
`docs/reference/`. See also `docs/reference/initinstance-port-plan.md`.

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
  (reads `g_cachedAppShellCommand`; see `docs/reference/initinstance-port-plan.md`).
- Inner init: `CreateGlobalBackdropWindowWithDefaultBmp3B6` @ `0x49cca0`.
- Input refresh/destroy path: `RefreshBackdropOnInputMessages` @ `0x49cdf0`
  (slot `0x18` / `CWnd::DestroyWindow` in the observed window flow).
- Backdrop initializer: `TBackdropWindow::InitializeDefaultBackdropWindowFromBmp3B6`
  @ `0x49ce90`.
- Teardown/reveal path: `TBackdropWindow::PostNcDestroy` @ `0x49cfa0` (retail vtable
  slot `0x2b` ILT → this body).
- Globals: `DAT_006a2050` (backdrop `TBackdropWindow*`), temp map/wait-cursor buffer
  `DAT_006a2054`, cached shell command `g_cachedAppShellCommand` @ `0x006a2018`
  (`CCommandLineInfo::m_nShellCommand` as `UINT` enum — **not** a filename pointer).

Completed (2026-06-30):
- ~~Model `DAT_006a2018`~~ — **done:** `g_cachedAppShellCommand` +
   `SetCachedAppShellCommand` @ `0x49cc40`; guarded creator @ `0x49cc60`. Semantics
   documented in source (`global_data_tables.cpp`, `ImperialismApp.cpp`).
- ~~Confirm the visible-window path in `just debug`~~ — **done** (backdrop window exists).
- Wired teardown trigger in source: `PostNcDestroy` @ `0x49cfa0` (59.77%), `OnCreate` @ `0x49d090` (50%),
  `InitializeDefaultBackdropWindowFromBmp3B6` @ `0x49ce90` (74.75%), `RefreshBackdropOnInputMessages` @ `0x49cdf0` (74.67%).
- `CMainFrame::ConfigureTopLevelWindowStyleAndPlacement` @ `0x484d70` (79.74%) - MFC library calls.

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
   - `just sync-ownership && just regen-stubs && just build`
   - `just compare 0x0049cbf0 0x0049cca0 0x0049cdf0 0x0049ce90 0x0049cfa0 0x49d090 0x49d180`
   - `just gates`
   - `just stats` and `just stats-commit` once the runtime path is accepted

Current compare snapshot (2026-06-30): `0x49ce90`/`0x49cdf0`/`0x49d180` ~75%,
`0x49cfa0` ~60%, `0x49d090` ~50%, `0x49cca0`/`0x49cbf0` ~31–33%.
`0x49cc60` on reccmp ignore list.

Updated 2026-06-30: Wired teardown trigger in source; shape passes completed for all functions.
All gates passing (vtable 100%, datacmp OK).

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
   - `just sync-ownership && just regen-stubs && just build`
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
