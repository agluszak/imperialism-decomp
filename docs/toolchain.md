# Toolchain Notes

This document tracks evidence for the compiler/linker used by Imperialism (1997), and the current reproduction strategy.

## Lint compiler (clang/MinGW) — NOT for reccmp

A second, modern compiler runs purely as a linter to catch errors MSVC 5.0
silently accepts (missing `override`, narrowing, wrong vtable signatures, bad
global linkage, layout `static_assert` failures). It is **never** used for
reccmp matching and must not influence the MSVC500 build.

- Toolchain: `clang-cl` targeting `i686-pc-windows-msvc`, using the vendored
  VC5/MFC and DirectX 5 headers. It is packaged in the shared
  `docker/msvc500/` image; CMake cross-toolchain in `cmake/clang-cl-i686.cmake`.
- Run `just docker-build` once, then `just lint`. It compiles all
  sources (no link, `IMPERIALISM_LINT_COMPILE_ONLY`) and keeps going past errors
  so one pass reports the whole tree.
- The C++ standard is C++14, which activates the real `override`/`static_assert`
  that `include/compat.h` stubs out for MSVC 5.0 — this is what makes the
  missing-override checks fire.
- `-fms-compatibility` is intentionally **omitted**: it defines `_MSC_VER`, which
  changes compatibility behavior that the explicit clang-cl target and retail
  headers already model.
- The same image installs version-matched `clang-tidy`. `just scalar-clang-tidy`
  regenerates the lint compile database before evaluating scalar-focused checks
  on a stable set of manually owned translation units.
- `.clang-tidy` holds a separate reviewed advisory profile for bug-prone source
  shapes, suspicious call arguments, and core analyzer findings. Run
  `just clang-tidy-audit` for the stable five-TU sample, or pass a compilation-
  database path regex to expand it. The profile deliberately excludes
  `modernize-*`, broad `cppcoreguidelines-*`, easily-swappable parameters, and
  missing-default warnings because they conflict with VC5/ABI recovery or bury
  evidence-backed findings in expected decompilation shape.

The LLVM 19 evaluation over all manually owned `src/game/*.cpp` translation
units produced 664 source-visible diagnostics in 131 files. The largest owned
families are signed-char conversions (136, `imperialism-decomp-1uj.99.7`),
redundant casts (116, `imperialism-decomp-1uj.99.2`), analyzer null/call paths
(282), suspicious call arguments (38), and enum casts outside the currently
declared domain (28, `imperialism-decomp-1uj.99.8`). Smaller high-signal groups
include casts through `void*` (17), branch clones (17), assignment in conditions
(12), dead stores (9), redundant expressions (4), `sizeof` misuse (2), macro
parenthesization (2), and implicit multiplication widening (1). These are audit
queues, not automatic fixes: analyzer null reports often follow retail-style
warning/assert paths that deliberately continue, while cast and expression
changes still require listing and reccmp verification.
- `just lint` now forces `IMPERIALISM_LINT_WERROR=ON`; CI also proves the gate
  rejects an intentionally warning-producing translation unit. clang-tidy is
  separate and advisory because its scalar diagnostics need listing-aware
  classification rather than blanket suppression or cast insertion.

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

## Experiment: template-emission compiler matrix

Harness: `just template-emission-matrix` (tools/workflow/template_emission_matrix.py
compiling `experiments/template_emission/{owner,user}.cpp` in the msvc500 container,
host-side COFF COMDAT inventory per TU). Probe: two owners embedding
`CList<void*, void*>` and `CList<ProbeRecord, ProbeRecord&>` between scalar fields,
mirroring the CIncludeView/TApplication shapes.

Results (VC5 RTM 11.00.7022, MFC 4.21, `/O2 /Oy /GX`; 2026-07 run):

- **`/Ob0`**: every collection call goes out-of-line — owner.obj emits 16 CList
  COMDATs (adds ctor, `AddTail`, `NewNode`, `RemoveAll`), user.obj emits 12
  (`AddTail`, `FreeNode`, `IsEmpty`, `NewNode`, `RemoveAll`, `RemoveTail`). This is
  the only mode producing direct calls to out-of-line template COMDATs at call sites.
- **`/Ob1` == `/Ob2`** (identical inventories): owner.obj emits exactly the
  per-instantiation VIRTUAL set — vtable `??_7`, `~CList` `??1`, scalar deleting
  dtor `??_G`, `Serialize` (×2 instantiations = 8) — and user.obj emits ZERO CList
  COMDATs: `AddTail`/`RemoveTail`/`IsEmpty`, including the nested `NewNode`/CPlex
  allocation, inline fully in a simple TU.
- **Same-TU users, explicit vs implicit mem-init, empty vs non-empty owner dtor:
  no change** to the emission inventory. Source-model choices at the owner cannot
  reduce or reshape the duplicate emission.
- **Non-inline `AddTail` wrapper**: adds only the wrapper's own COMDATs; the CList
  bodies stay inlined inside it.

Conclusions:

1. Any TU that constructs or destroys an embedded `CList` emits the full 4-body
   virtual set for that instantiation. The original's per-TU duplicate
   `??_G`/`??1`/`Serialize`/vtable copies are the unavoidable product of multiple
   original TUs owning objects of the same instantiation — exactly the twin families
   recorded in `config/template_aliases.csv`. Alias metadata (not source contortion)
   is confirmed as the correct fix.
2. Original TUs showing direct out-of-line `AddTail`/`RemoveTail` calls were compiled
   with inlining rejected in that context (`/Ob1` permits but does not force); in a
   simple TU the same calls inline completely. This matches the earlier wrapper
   experiments on the giant UI builders: neither wrapper form reproduces a rejected
   inline exactly, so treat those as site-local call-shape mismatches.
3. Still open (needs alternate toolchain binaries, not vendored): the VS97
   service-pack compiler/linker axis. When such binaries are available, add cells
   with a different image tag to `tools/workflow/template_emission_matrix.py`.
   `#pragma auto_inline(off)` remains probe-only: it affects functions defined
   inside the pragma region, so wrapping an owner ctor does not stop template bodies
   defined in `afxtempl.h` from inlining — not a production fix.

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
