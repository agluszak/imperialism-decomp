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
  InitInstance/ExitInstance are **placeholder bodies** (`return TRUE/0`) at the real addresses.
  No `// VTABLE:` annotation on purpose (original MFC lacks OLE slots retail nafxcw emits).
- `TModuleLibraryCacheTableStateB` asset-loader (the `.gob`-as-DLL-datafile cache) — ctor
  `0x498f60`, `LoadModuleLibrarySlot` `0x4992a0`, `LoadPrimary` `0x499380`. Embedded tables are
  real `CMap<>` members. **Its destructor `0x498fe0` is NOT yet ported** (ExitInstance needs it).
- `CString::Format` (`0x5ff15e`) and `AfxMessageBox` (`0x6185e4`) recognized as real MFC and
  LIBRARY-annotated. Call them directly.

Full context: `docs/reference/imperialism-decomp.md` ("Application Object" + "Asset Loader"),
heuristics note **18** (MFC convention/access traps + CMap), memory
`imperialismapp-keystone-initinstance`.

## Read these first

- Heuristics **15** (call MFC directly / LIBRARY-annotate, don't model), **16** (embedded
  subobject via real type), **18** (AFX_CDECL-looks-like-thiscall, protected-forwarder =
  library fn, verify against docker `afx.h`, CMap recognition, first-link wobble).
- The **MSVC500 calling-convention guardrail** and **construction Hard Rules** in `CLAUDE.md`.
- Ground-truth is the **assembly** (`just ghidra-listing 0xADDR`): Ghidra's `this[N].field`
  offsets are unreliable (wrong struct size) and its calling conventions are ~33% wrong.

## Remaining targets, in dependency order

### A. Asset-loader destructor `0x498fe0` (finishes the cache class)
`DestructModuleLibraryCacheDualTableAndUnloadModules`: `FreeLibrary` the 4 slots (`+0x3c`) +
primary (`+0x4c`), then tear down the two `CMap` members. With real `CMap` members the map
teardown should come from `~CMap()` (member dtors) — model as `~TModuleLibraryCacheTableStateB()`
and let MSVC destruct the members; verify the `FreeLibrary` loop matches. Owns the `// FUNCTION`.

### B. `TAmbitApplication` (TApplication subclass, vtable `0x0063e398`)
InitInstance builds `g_pGlobalUiRootController` (`0x6a1344`) via: `operator new(0x54)` →
ctor `0x40223e` (`ConstructGlobalUiRootControllerState`) → `*(obj)=0x63e398` (sets the derived
vtable). That "ctor then patch vtable" is the construction-bridge tell for
`class TAmbitApplication : public TApplication` with its own vtable `0x63e398`. Model real
inheritance; write `g_pGlobalUiRootController = new TAmbitApplication();`. Dump the vtable
(`just ghidra-vtable-dump TAmbitApplication 0x0063e398`) and diff vs `TApplication`'s to find
the overrides. Retype `g_pGlobalUiRootController` to `TApplication*`/`TAmbitApplication*`.

### C. `DAT_006a2158` class (UI runtime context)
First subsystem freed in ExitInstance (slot `+0x1c` = destroy virtual). InitInstance reads
`SetUiRuntimeContextAndActivateMain(*(int*)(DAT_006a2158 + 4))` and `GetObjectValueAtOffset98`
on it. Identify its class (ctor/vtable; check `config/recovered_globals.csv`, the global is set
in `InitializeGlobalRuntimeSystemsFromConfig` `0x49ded0`). If it can't be recovered yet, it is
the one place that may stay loosely typed — but try the vtable-dump + ctor route first. Needed so
ExitInstance's `obj->Destroy()` is a real virtual, not raw `(**(code**)(*p+0x1c))()`.

### D. Startup helper free functions (give real prototypes, then call directly)
All `__cdecl` unless noted; confirm each convention from the asm (who cleans the stack). For a
genuinely-leaf `__cdecl` helper you only need a real **prototype** to call it (the body can stay
a stub) — but the stub is `(void)`, and the `function_name_overrides.csv` prototype column is
**only emitted under `--use-prototypes`**, which `just regen-stubs` does NOT pass. So either
**(a) port the helper** (preferred when small) or **(b)** add it to a real header you control and
ensure the owning stub regenerates with the right signature. Do **not** whitelist in `stubgen.py`
(banned) and do **not** `reinterpret_cast` the `(void)` stub.
- `SetGlobalCallback6A7FACAndReturnPrevious` (`0x5e7a80`?) → `_DAT_006a1354`; `void*(void* cb)`.
- `ShowAutoResolutionDialogIfNeeded` (`0x415090`) — **`__thiscall` on the app** → declare as an
  `ImperialismApp` method, returns the value stored to `_DAT_006a1350`.
- `ApplyAutoResolutionModeAndPersist` (`0x4155b0`) — **`__thiscall` on the app** → ImperialismApp
  method taking the auto-res mode.
- `SetGlobalDword6A2018` (`0x49cc40`).
- `InitializeGlobalRuntimeSystemsFromConfig` (`0x49ded0`) — `__cdecl`, no args.
- `WarnLowDiskSpaceAndConfirmContinue` (`0x415760`, via ILT `0x407c70`).
- `SetUiRuntimeContextAndActivateMain` (`0x483340`).
- `GetObjectValueAtOffset98` (`0x61d89b`) — `__thiscall` on the `AfxGetThread()` result.
- `LoadLanguageResourcesFromIrgFiles` (`0x4149a0`) — `__cdecl`, 1285 bytes (loads `.irg` text).

### E. InitInstance body `0x00412dc0` (the integration)
Real MFC pieces (call directly, extern the data globals):
- `SetRegistryKey(*(LPCTSTR*)0x0063e038)` — **indirect global**, not Ghidra's `&DAT_006941ec`.
- `CCommandLineInfo cmdInfo; ParseCommandLine(cmdInfo);` then the registry-clear branch when
  `m_strFileName` is null && `m_nShellCommand != 5` (AppRegister) — preserve the exact condition
  from the asm; don't fight CCommandLineInfo's inlined member pokes.
- `g_pModuleLibraryCacheState = new TModuleLibraryCacheTableStateB();` (retype the global).
- `LoadLanguageResourcesFromIrgFiles()`, `g_pModuleLibraryCacheState->LoadPrimaryDataLibraryWithErrorDialog(field_D8)`,
  then `LoadModuleLibrarySlot(field_D0, 0)`, `LoadModuleLibrarySlot("Data/PictPaid.gob", 1)`,
  `LoadModuleLibrarySlot("Data/PictUniv.gob", 3)` — slot paths via the `0x694238`/`0x694220` literals.
- font loop `AddFontResourceA(...)` over `PTR_s_data_WeBeBd___ttf_00694150`; `PostMessageA((HWND)0xffff, WM_FONTCHANGE, 0, 0)`.
- `new CSingleDocTemplate(0x80, &CAmbitDocument::classRuntimeClass /*0x63e7f8*/,
  &TMacViewMgr_RuntimeClass /*0x648628*/, &CIncludeView::classRuntimeClass /*0x6481c8*/)` →
  `AddDocTemplate(...)`. Extern the 3 `CRuntimeClass` globals.
- `ProcessShellCommand(cmdInfo)`; `DAT_006a1348 = &theApp`.
- `g_pGlobalUiRootController = new TAmbitApplication();` (B); `InitializeGlobalRuntimeSystemsFromConfig();`
- `g_pSfxPlaybackSystem = new TSoundPlayer(); g_pSfxPlaybackSystem->InitializeSoundSubsystemAndAllocateChannelLists(0xf);`
  (TSoundPlayer modeled; ctor `0x40923c`, real virtual at vtbl `+0x94`).
- `AfxGetThread()` + its virtual at vtbl `+0x7c` (CWinThread virtual — call the real method);
  `GetObjectValueAtOffset98(...)`; `SetUiRuntimeContextAndActivateMain(*(int*)(DAT_006a2158+4))`.
- Final: `PostMessageA(mainWnd, WM_COMMAND, 100, 0)` (kicks startup command 100).

### F. ExitInstance body `0x00413780`
`if (field_C8) ChangeDisplaySettingsA(NULL, 0);` then free each subsystem via its **real**
slot-7 (byte `+0x1c`) destroy virtual — `DAT_006a2158` (C), `g_pModuleLibraryCacheState` (delete →
its dtor A), `g_pStrategicMapViewSystem` (`TStrategicMapViewSystem`), `g_pUiViewManager`
(`TAssetMgr::Free`), `g_pSfxPlaybackSystem` (`TSoundPlayer`), `g_pGlobalUiRootController`
(`TApplication`/`TAmbitApplication`) — `RemoveFontResourceA` loop, `PostMessageA(WM_FONTCHANGE)`,
then `return CWinApp::ExitInstance();`.

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
- `CSingleDocTemplate`/`CCommandLineInfo`/`ParseCommandLine`/`ProcessShellCommand`/`AddDocTemplate`/
  `SetRegistryKey` are real MFC — call them; the 3 doc/view `CRuntimeClass`es are data globals to
  `extern`, not classes to model.
