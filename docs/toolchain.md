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
- `just lint` now forces `IMPERIALISM_LINT_WERROR=ON`; `just precommit` also proves the gate
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

### ICF matrix (2026-07-23) — /OPT:NOREF,/OPT:NOICF pinned as the matching baseline

- **LINK 5.00.7022 supports ICF.** Its usage string advertises
  `/OPT:{REF|NOREF|ICF[,iterations]|NOICF}` — ICF is not a VC6 novelty. Combined with
  the retail image's incremental-link evidence (the 0x401000–0x409ab5 ILT plus stale
  5-byte `jmp` islands with nop padding at functions' pre-relink addresses), this fully
  explains the original's folded/aliased leaf destructors: 228 scalar-deleting-dtor
  call chains resolve through islands into just 10 shared bodies (most leaf views end
  at `TView::~TView` 0x48a9d0). The islands encode the original developers' relink
  history, so **no clean link — ours or theirs — can reproduce those addresses**;
  per-function pairing with named island claims is the attainable maximum (see the
  ctors-dtors-eh skill note of the same date).
- Four isolated configs, `/Oy /Ob1 /OPT:NOREF` constant (scratch harness: per-config
  `build-icf-X` dir, `just build_dir=X cmake_flags=... _build-msvc500-unlocked`):

  | config | extra flags | exact | original-only | vtables 100% | .text |
  |---|---|---|---|---|---|
  | A | `/OPT:NOICF` | 3778 (+0) | 214 (+0) | 444/444 | byte-identical to baseline |
  | B | `/OPT:ICF` | 3205 (−573) | 1400 (+1186) | 4/444 | — |
  | C | `/Gy /OPT:NOICF` | 3778 (+0) | 214 (+0) | 444/444 | byte-identical to baseline |
  | D | `/Gy /OPT:ICF` | 3205 (−573) | 1400 (+1186) | 4/444 | — |

- Conclusions: the effective default of our link was already NOREF+NOICF (A's `.text`
  is byte-identical); it is now pinned explicitly in the justfile `cmake_flags`
  (`IMPERIALISM_MATCH_LINK_FLAGS_CSV=/OPT:NOREF,/OPT:NOICF`) so a toolchain or CMake
  default change can never silently alter folding. `/Gy` is a no-op for this codebase
  (class members and inlines are already COMDATs). Enabling ICF on our side is
  catastrophic for the comparison surface — hundreds of markers collapse onto folded
  bodies and 440/444 vtables lose slot pairings — while the *average similarity* rises
  (+4.13 pp) because honest low-scoring tiny pairings disappear: never judge a linker
  experiment by the unweighted average. Fold-awareness belongs in reccmp equivalence
  metadata (bd 5jjn), never in our link flags; the VC5 service-pack axis is bd fh2r.

### VC5 service-pack probe (2026-07-23) — RTM confirmed on three independent axes

Toolchains from github.com/archaic-msvc (`msvc500`, `msvc500sp1`, `msvc500sp2`,
`msvc500sp3`), probed by bind-mounting each over `C:\msvc` in the stock docker image
(no image rebuild needed).

- Binary differential: `cl.exe` (driver) is identical in all four; **SP1 and SP2 ship
  byte-identical compilers/linkers** (c1xx 11.00.7149, LINK 5.02.7132, PE stamps
  1997-05/06); SP3 is c1xx 11.00.7307 + LINK 5.10.7303 (PE stamps 1997-11-04). RTM is
  c1xx 11.00.0000-family + LINK 5.00.7022 (1997-01-23).
- **The retail exe rules out every SP without building anything**: its PE linker-version
  stamp is 5.0 (SP1/2 stamp 5.2, SP3 stamps 5.10) and its link timestamp is
  **1997-10-31 — four days before SP3's binaries were even built**.
- Full-build measurements (pinned `/Oy /Ob1 /OPT:NOREF /OPT:NOICF`) confirm empirically:
  SP1: exact 3778 -> 3520 (−258), avg −2.26 pp; SP3: exact 3778 -> 3516 (−262),
  avg −2.26 pp; vtables stay 444/444 in both. The SP compilers change codegen broadly
  and match strictly worse.
- Conclusion: **the retail toolchain is VC5 RTM (cl 11.00.7022 / LINK 5.00.7022); keep
  it.** The "standalone body + inlined users" emission cases are not compiler-version
  artifacts — they are inherent /Ob1 behavior, to be handled by source placement and
  equivalence metadata, not by switching toolchains.
- Per-function anatomy of the SP1 delta (rules out "we overfit to RTM and SP1 is the
  real toolchain"): 817 functions regress (190 game-range lost 100%; a further 62
  lost-exact rows sit in the MFC/CRT range and are **library contamination** — the SP
  repos ship a different `nafxcw.lib`, so a pure compiler probe would mount only
  `bin/`). Size-weighted similarity drops 53.08% -> 49.94% (−3.13 pp, worse than the
  −2.26 pp unweighted drop) because the breakage concentrates in big mechanical
  bodies whose source has essentially one plausible form — e.g. `TCity::WriteTo`
  (915B, 100% -> 20.9%): retail/RTM cache a repeated virtual-call pointer in EDI and
  reuse `call edi`; SP1 re-reads the vtable and re-loads `call [eax+0x78]` per call.
  Serializers like that cannot be "overfit", so retail bytes = RTM output. On the
  other side, 168 functions improve under SP1 but they are almost entirely our
  worst-modeled bodies (raw 20-40%, inconclusive/mismatch) drifting closer by
  optimizer accident; the only two that reach 100% under SP1
  (`ComputeMinisterSkillFloatSlot89` 0x4e05d0, `ComputeNationRuntimeAdvisoryMetricCase6`
  0x4e0770) are **already proven `effective` under RTM** (commutative operand order /
  load folding) — SP1 merely emits the byte order the proof already declared
  equivalent. Verdict: zero genuine SP1-only matches; the hypothesis is dead.

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

### Uncalled out-of-line copies of fully-inlined constructors

Some original constructors exist twice: inlined into every user *and* as a
standalone body with zero xrefs. `TInteriorMinister::TInteriorMinister` is the
worked example — 0x4be1d0 is a 31-byte standalone copy nothing calls, while
`TInteriorMinister::CreateObject` (0x4be0d0) and
`TCityInteriorMinister::TCityInteriorMinister` (0x4be840) both carry the same
body inlined.

That combination needs an out-of-line definition (so the body is emitted
unconditionally) *plus* automatic inlining of a non-`inline` function (so both
users still inline it) *plus* both users living in one TU. The original binary
has all three: the two classes interleave in one address range
(0x4be0d0 … 0x4be1d0 … 0x4be840).

Our build cannot reproduce it, and the three arrangements are mutually
exclusive (measured 2026-07-23, `/Oy /Ob1`):

| Ctor definition | 0x4be1d0 | 0x4be0d0 | 0x4be840 |
| --- | --- | --- | --- |
| in-class in the header (current) | not emitted | 100% | 100% |
| out-of-line in `TInteriorMinister.cpp` | 100% | 46.15% | 73.68% |

The middle column is the whole prize (a 31-byte ctor) and the other two columns
are the price, so the in-class form stays. Under `/Ob1` a non-`inline`
definition is never auto-inlined, so the same-TU user (`CreateObject`) emits a
call instead of the body; and VC5 emits no COMDAT at all for an inline function
whose every call site was inlined, so no linker setting can bring 0x4be1d0 back
(`reccmp-roadmap` reports it as "the compiler has probably inlined this
function", i.e. absent from the PDB, not discarded at link time).

Reproducing it would take `/Ob2` on a TU holding both classes — a toolchain
axis change plus a merge that Hard Rule 7 forbids. Treat this shape as
recognised-and-accepted: keep the `// FUNCTION:` marker on the in-class
definition so the address stays owned, and expect it to stay unpaired.

## Python/Ghidra Environment Notes

- The repo syncs with `uv` using `pyghidra==3.1.0` and `jpype1==1.5.2` (see `pyproject.toml`). The stale `java-stubs-converted-strings` dependency conflicted with that `jpype1` pin and was removed.
- The Ghidra program is vendored in-repo at `vendor/ghidra/` (portable `.gzf` archive via Git LFS; live `.rep` regenerated by `just restore-project`). There is no longer any dependency on an external `imperialism_knowledge` checkout; `just class-discovery` runs fully in-repo via `tools/workflow/impk_compat.py`.
- `just ghidra listing 0xADDR [0xADDR ...]` prints read-only listing-level instructions from the vendored Ghidra project. Use it when decompiler signatures disagree with `reccmp` calling convention evidence.

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
