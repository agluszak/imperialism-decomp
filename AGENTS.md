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

## Hard Rules

1. No inline assembly.
2. Use `just` targets for normal workflow (`tooling-check`, `build`, `detect`,
   `compare`, `stats`, `promote`, `sync-ownership`, `regen-stubs`). Do not run raw
   `docker` or `uv run reccmp-*` when a `just` target exists; if no target exists,
   keep the direct command minimal and add a target afterward.
3. `// FUNCTION: IMPERIALISM 0x...` must be immediately followed by the function
   declaration — no comment or blank line between them.
4. One owned implementation per address in manual source; no duplicate `// FUNCTION`
   for the same address across manual files and stubs.
5. After editing markers/ownership, run `just sync-ownership` → `just regen-stubs` →
   `just build`.
6. Keep naming from Ghidra unless there is a concrete semantic reason to rename; never
   rename for style only.
7. Keep class-owned functions in `src/game/<ClassName>.cpp`; non-class/global trade
   code in `src/game/trade_screen.cpp`. Do not hand-edit generated files under
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

## MSVC500 calling-convention guardrail

- **Ghidra's calling-convention attribution is frequently WRONG** (it default-labels
  unknown functions `__cdecl`; ~33% of "defined `__cdecl`" are really `__thiscall`, and
  it mislabels `__fastcall`/`__thiscall`/vtable dispatch). Treat every convention from
  Ghidra/decompiler output as a hypothesis to verify against the assembly (who sets
  `ecx`/`edx`, who cleans the stack), never as ground truth.
- **Model real classes with real methods/virtuals — do not fake calling conventions
  with `reinterpret_cast` to paper over Ghidra's labels.** This is the single most
  repeated correction.
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
