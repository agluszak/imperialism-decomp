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
  pass → build → compare). Its `heuristics.md` is the 85-entry matching playbook.
- **`ghidra`** — inspect `Imperialism.exe` via pyghidra (listing, decompile, vtable
  dump, cdecl/thiscall scan) and the interactive function-documentation methodology.
- **`quality-control`** — build, reccmp detect/compare/stats, canaries, gates,
  formatting, and reccmp pairing-failure diagnosis.
- **`class-recovery`** — class/vtable reconstruction, Mac evidence, the vcall facade
  registry, and facade→virtual migration.

## Docs (the durable record)

- `docs/worklog.md` — chronological execution log (timestamps, commands, score
  deltas). The ground truth for what happened.
- `docs/toolchain.md` — compiler/linker forensics and reproduction decisions.
- `docs/reference/` — layout/contract and game-domain references (struct layouts,
  function/entry-chain map, bitmap IDs, tech unlocks).

## Environment & tooling

- **Python tooling runs through `uv`.** Use the `just` targets (preferred) or
  `uv run python -m tools...`; never bare `python`. `.env` holds only machine-specific
  paths (`GHIDRA_INSTALL_DIR`, `ORIGINAL_BINARY`, optional `MACOS_IMPERIALISM_DUMP`);
  see `.env.example`. Everything else is a constant in the `justfile`.
- **Ghidra is the ground-truth evidence source.** Read the disassembly before trusting
  a decompile or a name: `just ghidra-listing 0xADDR`, `just ghidra-vtable-dump`,
  `just scan-cdecl-thiscall`, plus decompile via the `ghidra` skill. Prefer this over
  objdump. The vendored project (`vendor/ghidra`) is authoritative; the tools verify the
  installed Ghidra matches `ghidra.toml` and fail fast on a mismatch.
- **Ghidra naming and calling conventions are provisional** (see Hard Rule 6 and the
  MSVC500 calling-convention guardrail): treat every name and
  `__cdecl`/`__fastcall`/`__thiscall` label as a hypothesis to verify against the
  assembly, never as ground truth.

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
5. After editing markers/ownership, run `just sync-ownership` → `just regen-stubs` →
   `just build`, and `just gates` before committing (raw-vtable + construction
   anti-pattern + marker-hygiene gates; run `just format-check <touched paths>`
   separately on files you edited).
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
11. For vtable calls in manual code, call through generated facades in
    `include/game/generated/vcall_facades.h` (or real virtuals) — no local
    `typedef ...Fn` + `reinterpret_cast` blocks, no raw `vftable[...]` indexing. Keep
    low-level slot-cast mechanics isolated in `include/game/vcall_runtime.h`.
12. `config/vtable_slots.csv` is the single source of truth for generated vcall
    wrappers; after changing it, run `just gen-vcall-facades` before build/compare.
13. The raw-vtable gate (`just vtable-gate`) must pass; do not add new raw-vtable
    patterns in files not already baseline-tracked.
14. `just session-loop` mutates `reccmp-project.yml` ignore lists; run it only when you
    explicitly intend to rewrite ignore configuration.
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
6. **Virtual calls are real virtual calls / real member methods**, not `VCall_*`
   facades or `reinterpret_cast` to fake calling conventions (see the guardrail below).
7. **No `operator new`/`operator delete` factories or `__cdecl` free-function factory /
   class-name helpers** (`CreateTViewInstance`, etc.) as a porting approach — port real
   methods + real inheritance. The retired "EH-new factory" pattern is not a template.
   *(baseline-tracked by `just antipattern-gate`)*
8. **No placement-new (`new (this) T()`) for base construction** — use real
   inheritance. Placement-new is only for genuine placement semantics (pools, explicit
   reconstruction into a buffer). *(enforced by `just antipattern-gate`)*
9. **Scalar deleting destructors (`??_G`/`??_E`) are compiler-generated** — claim them
   with `// SYNTHETIC` + an exact backtick name in `config/symbols.csv`; never
   hand-write a `Destruct*AndMaybeFree` bridge. Requires a genuinely polymorphic class.
10. **Retire temporary scaffolding** (`Construct*AtThis`, `VCall_*Runtime`,
    `*AndMaybeFree`) as classes become understood; name any unavoidable bridge as
    temporary with a removal condition. *(count baseline-tracked by `just antipattern-gate`)*
11. **Don't corrupt the source model to chase a local score.** A 70% match with correct
    architecture beats a 100% match built on fake source that blocks hierarchy recovery.
12. **Evidence required for inheritance** — base edges need constructor/destructor
    sequencing, vtable layout, prefix-layout, or Mac-symbol evidence; never names alone.

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
    call `obj->Virtual(args)`. Do NOT route it through the `vcall_runtime` /
    `VCall_*` facades; those inject a spurious `xor edx,edx` and reload the vtable per
    call. Owning the real virtual lets MSVC cache the vtable in a register across calls,
    matching the original. (The `vcall_runtime` facade layer is legacy scaffolding we
    intend to delete entirely — do not add to it; migrate off it.)
- A `reinterpret_cast` that only adjusts a return type or argument types of a genuinely
  same-convention free function (e.g. a real `__cdecl(void)` thunk) is fine. Faking the
  *convention* (esp. thiscall-as-fastcall-with-dummy-edx) is not.
- For an unavoidable free-function bridge where no class can yet be modeled, prefer
  `__fastcall` and keep the bridge out of primary method bodies — but first ask whether
  the right fix is to recover the owning class.

## Logging policy

- Keep execution detail in `docs/worklog.md` (one timestamped entry per session/change
  with commands and score deltas).
- Don't duplicate the same long status across multiple files.
- Persist transferable matching lessons as numbered notes in
  `.claude/skills/decomp-loop/heuristics.md`.

