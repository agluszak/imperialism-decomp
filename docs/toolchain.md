# Toolchain Notes

This document tracks evidence for the compiler/linker used by Imperialism (1997), and the current reproduction strategy.

## Lint compiler (clang/MinGW) — NOT for reccmp

A second, modern compiler runs purely as a linter to catch errors MSVC 5.0
silently accepts (missing `override`, narrowing, wrong vtable signatures, bad
global linkage, layout `static_assert` failures). It is **never** used for
reccmp matching and must not influence the MSVC500 build.

- Toolchain: `clang` targeting `i686-w64-mingw32` (MinGW-w64 supplies
  `<windows.h>`, gdi32/user32, and the MSVC calling conventions). Packaged in
  `docker/clang-mingw/`; CMake cross-toolchain in `cmake/clang-mingw-i686.cmake`.
- Run with `just build-lint-image` (one-time) then `just lint`. It compiles all
  sources (no link, `IMPERIALISM_LINT_COMPILE_ONLY`) and keeps going past errors
  so one pass reports the whole tree.
- The C++ standard is C++14, which activates the real `override`/`static_assert`
  that `include/compat.h` stubs out for MSVC 5.0 — this is what makes the
  missing-override checks fire.
- `-fms-compatibility` is intentionally **omitted**: it defines `_MSC_VER`, which
  sends MinGW's `windows.h` down an unsupported MSVC path.
- Strictness is phased: warnings are reported but non-fatal until the backlog is
  cleared, then flip `IMPERIALISM_LINT_WERROR=ON` (pass via
  `just lint -DIMPERIALISM_LINT_WERROR=ON`). Initial backlog: ~300
  inconsistent-missing-override warnings + ~42 hard errors (wrong global
  language linkage, `CString::Header` missing `()`, two `TCivDescription`
  layout assertions).

## DirectX 5 SDK headers (dplay.h shadowing)

- The portable `archaic-msvc/msvc500` toolchain ships a **DirectX 1** `<dplay.h>` whose
  `IDirectPlay` puts Receive/Send at vtable +0x54/+0x5c. The binary dispatches Receive
  at +0x64 and Send at +0x68 — the **IDirectPlay2** slot order (3 IUnknown + 22 methods
  before Receive), so the game was built against a DirectX 3+ SDK.
- The Docker image therefore bakes the **DirectX 5 SDK** (August 1997, period-correct;
  `idx5sdk.exe` from archive.org, a WEXTRACT SFX wrapping an MSZip cab) into
  `C:\dxsdk\{include,lib}`. `C:\dxsdk\include` is placed **before** `C:\msvc\include`
  on `INCLUDE` (docker/msvc500/entrypoint.py) so its `dplay.h` shadows the DX1 copy;
  the clang-cl lint toolchain (cmake/clang-cl-i686.cmake) mirrors the same order.
- All `DPERR_*` codes hard-coded in the original error tree
  (`TNetMgr.cpp::LookupDirectPlayErrorDetailText`) were verified to match the DX5
  header values (`MAKE_DPHRESULT` = `0x88770000 + code`, plus the `E_*` aliases).
- Nothing links `dplayx.lib` yet; the lib dir is on `LIB` for future session/lobby
  ports. A gitignored local reference mirror lives at `vendor/directx/` via
  `just vendor-directx-headers`.

## Current Hypothesis

- Architecture: 32-bit x86 PE
- Compiler family: Microsoft Visual C++ (late 90s)
- Most likely candidate range: VC++ 4.x to VC++ 6.0

## Initial Binary Fingerprints (GOG Imperialism.exe)

From `objdump -p` and `strings` on:
`<GOG install>/Imperialism/Imperialism.exe` (GOG-distributed build)

- PE timestamp: `Fri Oct 31 01:07:39 1997`
- PE linker version: `5.0`
- Subsystem: `Windows GUI`, subsystem version `4.0`
- No import of `MSVCRT.dll` (suggests statically linked CRT runtime)
- String present: `Microsoft Visual C++ Runtime Library`
- Extra section present: `.patch` (likely distributor patching layer)
- Rich header: not present in DOS stub (`e_lfanew = 0x80`, no `Rich`/`DanS` marker before PE header)

Interpretation:

- Missing Rich header means VC++ 4.2 is not ruled out by that signal.
- Linker `5.0` is still a meaningful clue for VC++ 5-era tooling, but should not be treated as final proof yet.
- VC++ 6.0 usually reports linker major version `6`, so it remains less likely.
- Because this is a GOG-distributed executable with an extra `.patch` section, keep post-build modifications in scope.

## Suggested Toolchain Order

1. VC++ 5.0-era compiler/linker (primary path)
2. VC++ 4.2-era compiler/linker (fallback path)
3. VC++ 6.0-era (only if matching evidence contradicts earlier fingerprints)

## Evidence To Collect

- Import table and CRT fingerprints (`MSVCRT`, `MSVCRxx`, startup symbols)
- Function prolog/epilog patterns
- Exception handling layout (`__CxxFrameHandler`, SEH style)
- RTTI/vtable layout details
- String and section ordering behavior from linker output

## Practical Strategy

1. Start with a modern-hosted old-compiler setup that can build 32-bit PE binaries.
   Reference implementation in this repo: `docker/msvc500/`.
2. Reconstruct a small set of functions and compare with `reccmp`.
3. Iterate compiler flags before broad source reconstruction.
4. Record every attempted compiler/version/flags set and observed matching deltas.

## Linker Option Notes

- Baseline `RelWithDebInfo` CMake injects `/INCREMENTAL:YES`, but the project adds
  `/INCREMENTAL:NO` later on the `Imperialism.exe` link line; the later flag wins.
  Incremental-link thunks are therefore not the current duplicate-template issue.
- ISLE uses `/OPT:REF` for its MSVC 4.20 targets. On Imperialism this is not usable
  as a default: an isolated `/OPT:REF` build linked successfully, but reccmp function
  coverage collapsed from about 95.95% to 44.17% because the linker discarded
  thousands of unreferenced recomp bodies that this repo intentionally keeps
  addressable for comparison.
- An isolated `/OPT:NOREF` build matched the baseline CList template rows exactly and
  kept the normal comparison surface. It confirms that the current baseline already
  behaves like "keep unreferenced code" for the CList problem; there is no linker flag
  fix for the duplicate original-side CList instantiations.
- Practical conclusion: do not adopt `/OPT:REF` to chase duplicate CList rows. Keep the
  real `CList<...>` source model and treat leftover duplicate original template bodies
  as a reccmp pairing/classification problem. Verified per-TU duplicates are recorded in
  `config/template_aliases.csv` (validated by `just template-alias-check`; discover
  candidates with `just mfc-collection-audit <Class|0xCTOR>`).

## Planned experiment: template-emission compiler matrix (not yet run)

The container uses VC5 RTM (compiler 11.00.7022) with MFC 4.21. The original exe dates
from late 1997, so a serviced VS97 toolchain (SP compiler/linker component versions)
is plausible but unproven. This deserves a controlled standalone experiment — not a
global toolchain switch on speculation. Harness sketch:

- Standalone TU pair embedding `CList<void*, void*>` and `CList<Record, Record&>`
  between scalar fields (`before`/`after`), mirroring the CIncludeView shape.
- Axes: VC5 RTM vs available VS97 SP compiler+linker versions; `/Ob0`/`/Ob1`/`/Ob2`;
  explicit `list()` mem-init vs implicit default construction; empty vs non-empty
  owner dtor; owner ctor and template users in same vs separate TUs; direct
  `AddTail` vs non-inline wrapper; source/object link ordering.
- Record: assembly, object COMDAT inventory, final decorated symbols, vtable count,
  ctor/dtor ordering, and aggregate reccmp effect on representative real functions.
- `#pragma auto_inline(off)` may be probed here in isolation; it affects functions
  defined inside the pragma region, so wrapping only an owner ctor does not stop
  template bodies defined in `afxtempl.h` from inlining — it is not a production fix.
- Per-TU flags or call-shape wrappers go to production only where this experiment
  demonstrates a meaningful net improvement (log results in the template below).

## Python/Ghidra Environment Notes

- The repo syncs with `uv` using `pyghidra==3.1.0` and `jpype1==1.5.2` (see `pyproject.toml`). The stale `java-stubs-converted-strings` dependency conflicted with that `jpype1` pin and was removed.
- The Ghidra program is vendored in-repo at `vendor/ghidra/` (portable `.gzf` archive via Git LFS; live `.rep` regenerated by `just restore-project`). There is no longer any dependency on an external `imperialism_knowledge` checkout; `just class-discovery` runs fully in-repo via `tools/workflow/impk_compat.py`.
- `just ghidra-listing 0xADDR [0xADDR ...]` prints read-only listing-level instructions from the vendored Ghidra project. Use it when decompiler signatures disagree with `reccmp` calling convention evidence.

## Experiment Log Template

## PE resources (SDI template id 0x80)

Retail `Imperialism.exe` embeds a `.rsrc` section; the recomp must too or
`CFrameWnd::LoadFrame(0x80, …)` fails before view creation.

- Hand-maintained script: `resources/imperialism_game.rc` (MENU + ACCELERATOR id
  128). CMake adds it to the `Imperialism` target when `MSVC AND NOT
  IMPERIALISM_LINT_COMPILE_ONLY`; Wine `rc.exe` emits
  `imperialism_game.rc.res` and `link` merges `.rsrc`.
- Inventory/extract helper (reads `ORIGINAL_BINARY`, does not commit retail
  blobs): `uv run python -m tools.workflow.pe_resources inventory|extract-rc|check`.
- Gate: `just resource-check` asserts the built PE has `.rsrc` and MENU 128.

Full retail fidelity (GROUP_ICON/BITMAP 128, DIALOG 152/251) can be grafted
later from `ORIGINAL_BINARY` once binary-to-RC conversion is wired.

- Date:
- Compiler:
- Linker:
- Flags:
- Target function set:
- Match result:
- Notable mismatches:
- Next change:
