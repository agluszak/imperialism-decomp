# Imperialism Decomp — Agent Guide

Decompilation workspace for the Windows game **Imperialism (1997)**. We reverse the
binary into matching C++, rebuild it with the original MSVC500 toolchain in
Docker/Wine, and track per-function similarity with `reccmp`. The goal is a
byte-faithful, reproducible-in-git rebuild.

This file is the contract: the invariants below hold for all work. Per-workflow
detail lives in **skills** (`.claude/skills/`); read the relevant skill before
starting that kind of task.

## Skills (how to do each workflow)

- **`decomp-loop`** — the core function-porting loop (promote → shape pass → data
  pass → build → compare). Its `heuristics.md` is the running matching playbook
  (numbered notes + appended lessons).
- **`ghidra`** — inspect `Imperialism.exe` via pyghidra (listing, decompile, vtable
  dump, cdecl/thiscall scan) and the interactive function-documentation methodology.
- **`quality-control`** — build, reccmp detect/compare/stats, gates,
  formatting, and reccmp pairing-failure diagnosis.
- **`sync-pipeline`** — the derived-artifact pipeline: symbols.csv, function
  ownership, autogen stubs, name overrides, `regen-stubs`/`db-resync`, and the
  resync failure→fix taxonomy (junk thunk rows, type flips, size clamps).
- **`class-recovery`** — class/vtable reconstruction, slice/class discovery,
  Mac-evidence oracle use, and real-virtual dispatch on recovered classes.
- **`vtable-matching`** — drive `just vtable <Class>` to 100%: read the reccmp vtable
  diff and fix per-slot mismatches (inherited-base, scalar-deleting-dtor, missing
  override, stub-in-slot, imported-thunk). Separate from `class-recovery`, which
  reconstructs an unknown layout/inheritance in the first place.
- **`run-debug`** — run the recomp under Wine, scripted winedbg sessions, and the
  capture-by-window-ID screenshot recipe for visual verification.

## IMPORTANT
- Game is compiled with MSVC500 (Visual C++ 5.0), which is an old compiler. DO NOT USE modern C++ features or syntax.
- ghidra uses unreliable, placeholder names and calling conventions. Almost every method
  in this project should be a thiscall belonging to a proper class
- code coming from MFC/other Windows libraries MUST NOT be modelled/ported. Use // LIBRARY annotations for it
- ILT thunks must not be used at all - they should be completely ignored. Use the target methods instead.

## Docs (the durable record)

- Git history — clear commit messages are the durable execution record for what
  changed, how it was verified, and any score deltas.
- `docs/workflows.md` — the three canonical command playbooks (daily port loop,
  marker/ownership edits, full Ghidra DB resync). Start here when unsure which
  `just` target to run; `just --list` groups every target and flags mutating ones.
- `docs/toolchain.md` — compiler/linker forensics and reproduction decisions.
- `docs/reference/` — layout/contract and game-domain references (struct layouts,
  function/entry-chain map, bitmap IDs, tech unlocks).

## Environment & tooling

- **Python tooling runs through `uv`.** Use the `just` targets (preferred) or
  `uv run python -m tools...`; never bare `python`. `.env` holds only machine-specific
  paths (`GHIDRA_INSTALL_DIR`, `ORIGINAL_BINARY`, optional `MACOS_IMPERIALISM_DUMP`);
  see `.env.example`. Everything else is a constant in the `justfile`.
- **MSVC/MFC headers are available locally for reference.** Populate the gitignored
  mirror with `just vendor-msvc500-headers`, then inspect
  `vendor/msvc500/headers/{include,mfc/include,atl/include}` instead of guessing MFC
  signatures or collection layouts.
- **Ghidra is the ground-truth evidence source.** Read the disassembly before trusting
  a decompile or a name: `just ghidra-listing 0xADDR`, `just ghidra-vtable-dump`,
  `just scan-cdecl-thiscall`, plus decompile via the `ghidra` skill. Prefer this over
  objdump. The vendored project (`vendor/ghidra`) is authoritative; the tools verify the
  installed Ghidra matches `ghidra.toml` and fail fast on a mismatch.
- **Ghidra naming and calling conventions are provisional** (see Hard Rule 6 and the
  MSVC500 calling-convention guardrail): treat every name and
  `__cdecl`/`__fastcall`/`__thiscall` label as a hypothesis to verify against the
  assembly, never as ground truth.

### reccmp verification & comparison commands

Each wraps a `uv run reccmp-*` tool via a `just` target (Hard Rule 2 — prefer the
target). They need a built binary + reccmp DB.

- `just precommit` — the whole pre-commit sequence in one command: `build` +
  `gates` + `test` (tooling unit tests) + `stats`.
- `just gates` — the pre-commit mechanical source-policy gates. Now also runs
  `uv run reccmp-decomplint` (annotation linting: marker syntax, duplicate addresses,
  stray markers) via the `just decomplint` target.
- `just vtable [Name]` (`uv run reccmp-vtable`) — assert virtual-table correctness
  against the original; optionally filter by class-name substring.
- `just datacmp [-a]` (`uv run reccmp-datacmp`) — compare global data values between
  the original and the recompiled binary.
- `just roadmap` (`uv run reccmp-roadmap`) — compare symbol locations (functions,
  vtables, data) between original and recompiled.
- `just stackcmp 0xADDR` (`uv run reccmp-stackcmp`) — compare the stack layout of a
  single near-matching function.

## Hard Rules

1. No inline assembly. (enforced by `just antipattern-gate`)
2. Use `just` targets for normal workflow (`tooling-check`, `build`, `detect`,
   `compare`, `stats`, `promote`, `sync-ownership`, `regen-stubs`). Do not run raw
   `docker` or `uv run reccmp-*` when a `just` target exists; if no target exists,
   keep the direct command minimal and add a target afterward.
3. `// FUNCTION: IMPERIALISM 0x...` must be immediately followed by the function
   declaration — no comment or blank line between them. (enforced by `just marker-gate`)
4. One owned implementation per address in manual source; no duplicate `// FUNCTION`
   for the same address across manual files and stubs. (enforced by `just marker-gate`)
5. After editing markers/ownership, run `just regen-stubs` (it runs `sync-ownership`
   and the symbols.csv integrity check first) → `just build`, and `just gates` before
   committing (raw-vtable + construction anti-pattern + marker-hygiene gates; run
   `just format-check <touched paths>` separately on files you edited).
6. Keep naming from Ghidra unless there is a concrete semantic reason to rename; never
   rename for style only. But treat Ghidra class/method/field names as **provisional** —
   they may be auto-generated placeholders, even entirely random. reccmp pairs by the
   `// FUNCTION:` address marker, not by name, so drive matching and field naming from
   observed behavior in the disassembly, and keep tentative names hedged.
7. Keep class-owned functions in `src/game/<ClassName>.cpp`; shared trade helpers in
   `src/game/trade_helpers.cpp` and `include/game/trade_quickdraw.h`. Do not hand-edit
   generated files under
   `src/ghidra_autogen/`, `src/autogen/stubs/`, or `include/ghidra_autogen/`.
8. Promote repeated `this + offset` / `reinterpret_cast` access that maps to a stable
   class region into a typed class field (or typed view struct) instead of cast-helper
   indirection.
9. Keep external thunk declarations in the generic repo form (`undefined4 ...(void)`)
   and use typed local function-pointer casts at callsites; changing thunk
   declaration signatures directly causes MSVC name-mangling linker breaks.
10. MSVC500 keeps `for` loop variables in function scope; do not redeclare the same
    loop variable name later in the same function.
11. For vtable calls in manual code, use real `virtual` methods on recovered classes — no
    local `typedef ...Fn` + `reinterpret_cast` blocks, no raw `vftable[...]` indexing,
    and no generated `VCall_*` facade wrappers.
12. When adding a dispatch to an unrecovered receiver, declare the method on the owning
    class header at the verified slot and call `obj->Method(args)` directly.
13. The raw-vtable gate (`just vtable-gate`) must pass; do not add new raw-vtable
    patterns in files not already baseline-tracked.
14. Rewriting `reccmp-project.yml` ignore lists is opt-in: only `just generate-ignores`
    and `just session-loop --refresh-ignore` do it; run them only when you explicitly
    intend to rewrite ignore configuration (`just session-loop` alone is read-only).
15. Mac CodeWarrior evidence (vendored at `vendor/macos_codewarrior/`) is a
    name/signature **oracle only** — it must never assign Windows addresses, calling
    conventions, vtables, or inheritance.

## Hard rules: real C++ construction and inheritance

Mandatory. Do not use bridge thunks, placement-new shims, manual vtable writes, or fake
runtime helpers when a real C++ construct can express the same thing. Full recipes,
examples, and rationale: `docs/reference/construction.md`.

1. **Prefer real inheritance over construction bridges.** A structurally-derived class
   is `class TDerived : public TBase`, and its ctor calls `: TBase()` naturally — not
   `ConstructTBaseAtThis(this)` / `new (this) TBase()` / `VCall_RuntimeBaseCtor(this)`.
2. **No manual vtable writes** (`*(void**)this = ...`, `vptr = g_vtbl...`). The
   `// VTABLE:` annotation + C++ inheritance own vtable emission; a needed vptr write
   means the class model is wrong. Allowed only in quarantined runtime files with a
   comment proving it isn't normal construction. *(enforced by `just antipattern-gate`)*
3. **Constructor field init is about placement.** Use member-initializer lists (in
   declaration order) when the original writes scalar fields before constructing later
   non-POD members; body assignments force the member construction first and mismatch.
4. **Declaration order is part of the reconstruction** — C++ constructs members in
   declaration order. Match the original layout; do not reorder fields for looks.
5. **Use real member objects, not raw storage + init helpers** — declare a `CString`
   member as `CString`, not `unsigned char[4]` + `InitializeCString`. Raw storage only
   while the type is genuinely unknown.
6. **Compiler construction/destruction helpers are compiler output, not source-model
   APIs.** MSVC EH/vector iterator functions (`CallCallbackRepeatedly`,
   `InvokeCallbackNTimesWithSehGuard`, array constructors/destructors, cleanup callbacks,
   unwind helpers) and scalar deleting destructors must not be restored, wrapped, ported
   into invented helper TUs, or renamed as gameplay/runtime abstractions in manual game
   code. Do not keep them as "runtime helpers" either: in manual source they must
   disappear into real C++ source constructs. Recover the actual element/member type and
   let C++ member arrays, constructors, destructors, scalar deleting destructors, and
   inheritance emit those helper calls naturally. Never introduce `callback_helpers`,
   `CallCallbackRepeatedly`, `InvokeCallbackRepeatedly`, raw callback-address wrappers,
   or similar fake abstractions as a substitute for the real element type.
7. **Virtual calls are real virtual calls / real member methods**, not `VCall_*`
   facades or `reinterpret_cast` to fake calling conventions (see the guardrail below).
8. **No `operator new`/`operator delete` factories or `__cdecl` free-function factory /
   class-name helpers** (`CreateTViewInstance`, etc.) as a porting approach — port real
   methods + real inheritance. The retired "EH-new factory" pattern is not a template.
   *(baseline-tracked by `just antipattern-gate`)*
9. **No placement-new (`new (this) T()`) for base construction** — use real
   inheritance. Placement-new is only for genuine placement semantics (pools, explicit
   reconstruction into a buffer). *(enforced by `just antipattern-gate`)*
10. **Scalar deleting destructors (`??_G`/`??_E`) are compiler-generated** — claim them
   with `// SYNTHETIC` + an exact backtick name in `config/symbols.csv`; never
   hand-write a `Destruct*AndMaybeFree` bridge. Requires a genuinely polymorphic class.
11. **Retire temporary scaffolding** (`Construct*AtThis`, `VCall_*Runtime`,
    `*AndMaybeFree`) as classes become understood; name any unavoidable bridge as
    temporary with a removal condition. *(count baseline-tracked by `just antipattern-gate`)*
12. **Don't corrupt the source model to chase a local score.** A 70% match with correct
    architecture beats a 100% match built on fake source that blocks hierarchy recovery.
    **This applies to gates too:** a failing `just gates` / `just vtable` with correct
    source is not permission to revert to stubs — see the gate-chasing guardrail below.
13. **Evidence required for inheritance** — base edges need constructor/destructor
    sequencing, vtable layout, prefix-layout, or Mac-symbol evidence; never names alone.

## Gate-chasing guardrail (never revert architecture to pass verification)

When `just gates`, `just vtable`, `just build`, or pre-commit checks fail **after** you
have promoted real C++ shape — typed fields, real methods, `new T()`, typed singleton
globals — **never undo that work to make verification pass.** Regressing from real
methods back to `extern undefined4` + `reinterpret_cast` at the callsite is strictly
worse than a failing gate and is treated as a source-model corruption (construction
Hard Rule 11).

### Typical failure mode (do not repeat)

1. Port real shape: named fields instead of `this + offset`, `g_pX->Method()` instead of
   a free-function stub, `new TNetMgr()` instead of a heap shim.
2. A gate fails (`just vtable`, duplicate `// FUNCTION:`, `antipattern-gate`, link error).
3. Agent **reverts step 1** — restores stub casts, `new char[]` buffers, or deletes the
   promoted method — so the gate passes.

Step 3 is **forbidden**. Fix forward or stop and report; never fix backward.

### Fix forward (in order)

1. **Build/link** — missing symbol: promote/own the callee as a real method, or use a
   genuine LIBRARY symbol (`operator new` at `0x606f73`, not a fake
   `AllocateWithFallbackHandler` stub). Wrong owner: `just regen-stubs`.
2. **Duplicate marker** — one address, one owner; move `// FUNCTION:` to the class that
   owns the method, sync ownership, regen stubs. Do not delete the manual method.
3. **`just vtable Class`** — first `new T()` in manual code can expose a pre-existing
   class-model gap. Fix slot ownership / imports / missing overrides on that class; do
   **not** stop constructing the class and do **not** re-stub callsites.
4. **`antipattern-gate`** — prefer `new T()` over explicit `operator new` + placement;
   prefer real inheritance over bridge thunks. Do not replace `new T()` with stub dispatch.

If none of the above can resolve the gate **without** architectural regression, **stop
and report** what failed, what you tried, and what class-model work remains. A blocked
commit with correct source beats a passing commit with reverted stubs.

### Callee classification (pick once, do not flip-flop)

| Evidence | Correct model | Forbidden rollback |
|----------|---------------|--------------------|
| `mov ecx, …` / callee uses `[ecx+off]` | Real `__thiscall` method on owning class; `obj->Method()` | `reinterpret_cast` to `__thiscall*` on `undefined4` stub |
| Vtable dispatch | Real `virtual` on recovered class | Raw `vftable[i]` or `VCall_*` facade |
| `0x606f73` / `AllocateWithFallbackHandler` in listing | `new T()` (MFC `operator new` LIBRARY in `mfc_heap_library.cpp`) | `new char[n]` + stub ctor cast |
| `// LIBRARY:` in repo | Link against MFC; no stub definition | Add a fake `undefined4` stub |
| Genuine `__cdecl` ILT wrapper, no `this` | Hard Rule 9: `extern undefined4` + typed cast at callsite | — |

**Hard Rule 9 applies only to genuine free-function thunks.** It does **not** permit
re-stubbing a callee you have already verified is `__thiscall` on a recoverable class
because a gate failed.

### Promotion direction is one-way

Temporary bridges must be **retired**, not restored. Once a callsite uses
`g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(...)` or
`new TNetMgr()` / `TNetMgr::ConstructGlobalTurnEventQueueManager(...)`, do not put the
free-function stub or fake calling-convention cast back to unblock a commit.

## MSVC500 calling-convention guardrail

- **Ghidra's calling-convention attribution is frequently WRONG** (it default-labels
  unknown functions `__cdecl`; ~33% of "defined `__cdecl`" are really `__thiscall`, and
  it mislabels `__fastcall`/`__thiscall`/vtable dispatch). Treat every convention from
  Ghidra/decompiler output as a hypothesis to verify against the assembly (who sets
  `ecx`/`edx`, who cleans the stack), never as ground truth.
- **Model real classes with real methods/virtuals — do not fake calling conventions
  with `reinterpret_cast` to paper over Ghidra's labels.** This is the single most
  repeated correction. (`reinterpret_cast` to a `__thiscall` function pointer is
  enforced against by `just antipattern-gate`.)
  - If a call is `thiscall`, the callee is a class method: declare it as a real method
    on the real class and call `obj->Method(args)`. Do NOT cast a free-function pointer
    to a fake `__fastcall(void*, int /*edx*/, ...)` shape with a dummy `edx`.
  - If a call is a **vtable dispatch**, model the real C++ class with real `virtual`
    methods (in the correct slot order — verify the slot offset in the disassembly) and
    call `obj->Virtual(args)` directly on the owning recovered class.
- A `reinterpret_cast` that only adjusts a return type or argument types of a genuinely
  same-convention free function (e.g. a real `__cdecl(void)` thunk) is fine. Faking the
  *convention* (esp. thiscall-as-fastcall-with-dummy-edx) is not.
- For an unavoidable free-function bridge where no class can yet be modeled, prefer
  `__fastcall` and keep the bridge out of primary method bodies — but first ask whether
  the right fix is to recover the owning class.

## Type-modeling guardrail

- **Use the correct type, and the real MFC type when the data is one.** Model a field,
  parameter, or local as the actual type the original used — not `int`, raw
  `unsigned char[]` storage, or a hand-rolled struct standing in for a known type. When
  the layout/behaviour is an MFC class, declare it as that MFC type (`CString`,
  `CPtrList`/`CObList`/`CObArray`/`CTypedPtrList`, `CPoint`/`CRect`/`RECT`, `CWnd`,
  `CArchive`, `CRuntimeClass`, …) so members construct correctly and call sites use the
  real API instead of walking protected internals (see the `mfc-collections` skill and
  construction Hard Rule 5). A `reinterpret_cast` to reach a method is the smell that the
  underlying type is mismodelled.
- **Never borrow a type from a neighbouring signature.** A parameter labelled `TEvent*`
  on one method does not make the object passed there a `TEvent`. Confirm the object's
  real class first (its constructor/vtable, `config/recovered_globals.csv`, `symbols.csv`,
  or the Mac oracle) before typing or casting. Distinct classes that merely share a layout
  region or a slot are *not* interchangeable — `PostCommand(TCommand*)` vs
  `PostAnEvent(TEvent*)` in the Mac evidence proves `TCommand` ≠ `TEvent`, so a
  `TCommand`→`TEvent*` cast is a genuine type pun, not an identity.
- **An opaque/polymorphic vtable slot takes `void*`, not one caller's type.** When
  different overrides interpret the same slot's argument differently (one caller passes a
  `RECT*`, another a `TCommand*`), type the parameter `void*` and do the interpretation
  (`static_cast<TCommand*>`) inside each override body. Every call site then converts
  implicitly (cast-free); confine the one genuine cross-type pun to a single spot in the
  body. Do not pick one caller's type and force the others to `reinterpret_cast`.
- **Type pointer-bearing fields as typed pointers** (`TEventHandler* targetHandler`, not
  `int field10`) and update the init helper's argument to match, so call sites pass real
  objects via implicit upcast with no cast. Exception: a single offset reused as both an
  `int` and a pointer in different methods must stay `int`/raw — do not force a pointer
  type onto a dual-purpose slot.
- **Renames and pointer↔pointer / int-as-int narrowing are codegen-neutral and safe.**
  reccmp pairs by address and these casts compile to nothing, so aligning a C++ identifier
  to the curated `symbols.csv` name (reuse it — don't invent a third) and tightening types
  cannot regress a score; confirm with `just compare <addr>`. Update an override's
  signature in lockstep with the base, or it silently stops overriding (`override` fails to
  compile, or a new vtable slot is created).

## Commit-message policy

**Pre-commit verification** (required before every commit):

1. `just precommit` — build + all gates + tooling tests + stats in one command
2. Review the stats deltas vs `config/reccmp_progress_baseline.json`
3. `just stats-baseline-update` — refresh the baseline; commit it with the source change

If gates fail or stats regress for reasons unrelated to your edit, stop and report
rather than committing around the failure. See `.cursor/rules/commit-workflow.mdc`.

**Never revert promoted real C++ to pass gates** — typed fields, real methods, `new T()`,
typed globals. See **Gate-chasing guardrail** above. A failing gate with correct source
must be fixed forward or reported; stub/`reinterpret_cast` rollback is not an acceptable
gate fix.

- Do not add routine execution entries to `docs/worklog.md`; keep `docs/worklog.md`
  as historical context only.
- Write clear commit messages that explain what changed, how it was verified, and
  any relevant score deltas or accepted residual risks.
- Don't duplicate the same long status across multiple files.
- Persist transferable matching lessons as numbered notes in
  `.claude/skills/decomp-loop/heuristics.md`.
