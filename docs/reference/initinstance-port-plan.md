# InitInstance / ExitInstance Port Plan (handoff)

Goal: finish the window-open path — port `ImperialismApp::InitInstance` (`0x00412dc0`) and
`ExitInstance` (`0x00413780`) to faithful, fake-free C++. Work **leaf-up**: every callee must
be a real, correctly-typed declaration before the body can compile cleanly (no
`reinterpret_cast` of `(void)` stubs, no raw vtable, no fake calling conventions).

## Already done (keep, build on)

- `ImperialismApp : public CWinApp` — `include/game/ImperialismApp.h` / `src/game/ImperialismApp.cpp`.
  Ctor `0x412ac0` pairs ~70%. Fields at `+0xC0`: `field_C0`(int), `field_C4`(CString),
  `field_C8`(int, **display-mode-changed flag**), `field_CC..field_E0`(6×CString).
  `field_D0` = slot-0 data-lib path, `field_D8` = primary-lib path. `theApp` global defined.
- **`InitInstance @ 0x00412dc0`** — real body in `ImperialismApp.cpp`: registry branch, module cache,
  language load, auto-resolution, fonts, doc template, shell command, runtime subsystem init,
  `GetMainViewHostFromActiveThread`, `SetUiRuntimeContextAndActivateMain`, title text,
  startup `WM_COMMAND` 100. Match score still ~36% (CCommandLineInfo inlining, empty-string check).
- **`ExitInstance @ 0x00413780`** — real body: display restore, `g_pDisplayMgr` (`DAT_006a2158`) first,
  module cache delete, strategic map / UI view / SFX / root controller teardown, clip-region reset,
  font unload, `CWinApp::ExitInstance`. Match score ~79%.
- **`~TModuleLibraryCacheTableStateB @ 0x00498fe0`** — real dtor in
  `TModuleLibraryCacheTableStateB.cpp` (FreeLibrary + dual `CMap` teardown). Match score ~36%
  (MSVC500 inlines `CMap::RemoveKey` differently than hand-inlined hash walk).
- **`TAmbitApplication`** — `new TAmbitApplication()` at startup; vtable `0x0063e398`.
- **`g_pDisplayMgr` / `DAT_006a2158`** — typed as `TDisplayMgr*` in `diplomacy_globals.h`; constructed
  in `InitializeGlobalRuntimeSystemsFromConfig`, freed first in `ExitInstance`.
- **`ApplyAutoResolutionModeAndPersist @ 0x004155b0`** — real body: `ChangeDisplaySettingsA`,
  `WriteProfileInt`, updates `field_C8`.
- **`ShowAutoResolutionDialogIfNeeded @ 0x00415090`** — uses `TAutoResolutionDialog` +
  `TModalTemplateDialog` modal helpers (`PrepareAndCreateModalFromTemplate` /
  `FinalizeModalDialogAndRestoreOwnerFocus`).
- **`LoadLanguageResourcesFromIrgFiles @ 0x004149a0`** — `ImperialismApp` method: enumerates `Data/*.irg`,
  loads strings into `field_CC..field_E4` (leaf file helpers still stub-backed).
- **Startup helpers** in `startup_helpers.cpp` / `startup_helpers.h`:
  - `InitializeGlobalRuntimeSystemsFromConfig @ 0x0049ded0` — real orchestration: constructs
    `TLanguageMgr`, `TSimMgr`, `TAssetMgr`, `TViewMgr`, `TDisplayMgr`, `TMacViewMgr`, `THelpMgr`,
    and `TMultiplayerMgr` (via `Config::InitDefaults`), then calls
    `InitializeMultiplayerManagerForSessionContext`.
  - `SetUiRuntimeContextAndActivateMain @ 0x00483340` — real body.
  - `GetMainViewHostFromActiveThread @ 0x00412a70` — real body (Afx thread main window + offset `+0x98`).
  - `SetGlobalCallback6A7FACAndReturnPrevious`, `SetGlobalDword6A2018`.
  - `WarnLowDiskSpaceAndConfirmContinue @ 0x00415760` — disk-space check + `TLowDiskWarningDialog`
    (template `0x98`).
- **Manager ctors / init** promoted to real methods:
  - `TLanguageMgr::TLanguageMgr @ 0x507c60`, `ReloadPreplutNewsTableAndResources @ 0x5086a0`
    (partial — leaf reload helpers still TODO).
  - `THelpMgr::THelpMgr @ 0x5005e0`, `InitializeHelpManagerIndexArrayAndState @ 0x500680`.
  - `TAssetMgr::TAssetMgr @ 0x5df280`, `ForwardEnsurePictWvDataGobLoadedBySlot @ 0x5df3a0`.
  - `TMultiplayerMgr::TMultiplayerMgr @ 0x542670` (partial — CString table init still TODO).
  - `TSimMgr::InitializeTurnFlowStateDefaults @ 0x57bbf0`.
  - `g_pHelpMgr` typed in `diplomacy_globals.h` (was raw `0x006a21b8`).
- `CString::Format` (`0x5ff15e`) and `AfxMessageBox` (`0x6185e4`) recognized as real MFC and
  LIBRARY-annotated. Call them directly.

Full context: `docs/reference/imperialism-decomp.md` ("Application Object" + "Asset Loader"),
heuristics note **18** (MFC convention/access traps + CMap), memory
`imperialismapp-keystone-initinstance`.

## Read these first

- Heuristics **15** (call MFC directly / LIBRARY-annotate, don't model), **16** (embedded
  subobject via real type), **18** (AFX_CDECL-looks-like-thiscall, protected-forwarder =
  library fn, verify against docker `afx.h`, CMap recognition, first-link wobble).
- Heuristic **5** / calling-convention recovery: **almost nothing is `__fastcall`** — prefer real
  `__thiscall` methods on the receiver class or normal `__cdecl` free functions with explicit args.
- The **MSVC500 calling-convention guardrail** and **Construction Hard Rules** in `CLAUDE.md`.
- Ground-truth is the **assembly** (`just ghidra-listing 0xADDR`): Ghidra's `this[N].field`
  offsets are unreliable (wrong struct size) and its calling conventions are ~33% wrong.

## Remaining targets, in dependency order

### A. Asset-loader destructor shape (~36%) — optional polish
Hand-inlined `CMap` hash walk in `~TModuleLibraryCacheTableStateB` vs public `RemoveKey`/`GetNextAssoc`.
Only pursue if chasing map-teardown shape; functional teardown is present.

### B. Auto-resolution dialog class — done
`TAutoResolutionDialog` / `TModalTemplateDialog` wired in `ShowAutoResolutionDialogIfNeeded`.

### C. Startup factory leaves — largely done
Orchestration uses real `new` + method calls. Remaining leaf depth:
- `ReloadPreplutNewsTableAndResources` reload helpers (`FreeNestedPointerTableRowsAndResetDimensions`,
  `LoadNewsTabTexResourcesAndBuildEntries`).
- `TMultiplayerMgr` ctor CString table initialization (`CallCallbackRepeatedly` cluster).
- `EnsurePictWvDataGobLoadedBySlot @ 0x5dff20` body (forwarder wired).
- `InitializeOrLoadEntryArray14AndClampLimits @ 0x581400` body (stub).

### D. InitInstance residual match (~36%)
- `CCommandLineInfo` member pokes (partially unavoidable MSVC inlining divergence).
- `CompareAnsiStringsWithMbcsAwareness` vs `g_szEmptyString` for title path — wired; filename-null
  branch uses `m_pchData == nullptr` vs `IsEmpty()`.
- Register allocation around `GetMainViewHostFromActiveThread` / `SetWindowTextOrDelegateToOwner`
  (compiler choice — do not chase).

### E. ExitInstance residual match (~79%)
- Register allocation (`ebp` vs `edi`) — out of scope.
- `ReleaseGlobalClipRegionHandleListAndReset` — present.

### F. Low-disk warning — done
`WarnLowDiskSpaceAndConfirmContinue` uses `TLowDiskWarningDialog` (template `0x98`).

## Workflow & verification (per target)

1. `just ghidra-listing 0xADDR` for real offsets/convention; `just ghidra-decompile 0xADDR` for shape.
2. Promote/own the marker in the right `src/game/<Class>.cpp`; for new free helpers pick the file by
   `config/function_ownership.csv` address neighbors.
3. `just sync-ownership && just regen-stubs && just build` whenever a marker/ownership changes.
4. `just compare 0xADDR --verbose`; aim for a faithful shape (30–70% is fine — don't chase 100%,
   don't add pragmas). `just gates`; `just stats` for blast radius.
5. Expect first-link MFC re-pairing wobble (note 18) when new nafxcw functions get linked — flat
   aggregate, refresh baseline; don't revert clean MFC calls to chase it.

## Traps specific to this work

- Ghidra mislabels `InitInstance` as `CMainFrame::OnEndPrintPreview` and `ExitInstance` as
  `CAmbitDocument::SetForeignMinisterReadyFlag14`. Ignore the names; pair by address.
- A free callee invoked with `ECX=this` is a `__thiscall` method on that receiver — model it on the
  receiver class (e.g. the two auto-resolution helpers are ImperialismApp methods), never a fake
  `__fastcall`/`reinterpret_cast`.
- Do **not** model leaf helpers as `__fastcall(void*, int dummyEdx)` — use real methods or `__cdecl`
  with explicit parameters.
- `CSingleDocTemplate`/`CCommandLineInfo`/`ParseCommandLine`/`ProcessShellCommand`/`AddDocTemplate`/
  `SetRegistryKey` are real MFC — call them; the 3 doc/view `CRuntimeClass`es are data globals to
  `extern`, not classes to model.
