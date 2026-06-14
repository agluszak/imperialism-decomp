---
name: quality-control
description: Build, measure, and gate the Imperialism decomp — rebuild with Docker MSVC500, run reccmp detect/compare/stats, check canaries for regressions, enforce the raw-vtable gate, format C++, and diagnose reccmp pairing failures. Use when building, checking similarity scores, guarding against regressions, or debugging why a function won't pair.
---

# Quality control

Build, measurement, gates, and regression diagnosis. Obey the Command Policy in
`AGENTS.md`: use `just` targets, not raw `docker`/`uv run reccmp-*`.

## Build & measure

- `just tooling-check` — verify the toolchain surface is present.
- `just build` — full pipeline: `gen-vcall-facades` → `vtable-gate` → Docker MSVC500
  build.
- `just detect` — re-run reccmp recompiled detection (do this after every rebuild).
- `just compare 0xADDR` — targeted verbose compare of one function (the acceptance
  gate for a touched body). With no address, runs a full compare.
- `just stats` — aggregate progress (aligned function count, average similarity).
  Treat this as a macro trend only; per-function `compare` is the real gate.
- `just compare-canaries` — compare the tracked anchor set
  (`config/canary_targets_*.csv`). Do NOT run reflexively after every change; run it only
  when the edit's blast radius could plausibly reach the canaries — broadly-included
  shared headers, common helpers/macros, build/optimization flags, or a canary function
  itself. Self-contained work (porting one unrelated function, splitting a class into
  per-class files) cannot reach the set, so skip it there. When you do run it, a non-zero
  `below_floor` is a real regression — fix or revert before moving on.

## Export-sync sequence (run whenever markers/ownership change)

```sh
just sync-ownership   # sync function ownership CSV into source annotations
just regen-stubs      # regenerate unresolved stubs
just build
```

## Gates & formatting

- `just gates` — run all mechanical source-policy gates (the pre-commit check):
  `vtable-gate` + `antipattern-gate` + `marker-gate`. Run this before committing.
- `just vtable-gate` — must pass; do not introduce new raw `vftable[...]` patterns in
  files not already baseline-tracked. `just vtable-gate-update` rewrites the baseline
  after an intentional refactor.
- `just antipattern-gate` — enforces the mechanically-checkable real-C++-construction
  Hard Rules (no inline asm, no `new (this)`, no manual vptr writes, no `__thiscall`
  reinterpret_cast; temporary bridge-helper names are baseline-tracked so they ratchet
  down). `just antipattern-gate-update` rewrites the baseline after an intentional,
  reviewed change (e.g. retiring bridges — counts should only go down).
- `just marker-gate` — enforces marker Hard Rules 3 (marker immediately precedes the
  declaration) and 4 (one owned implementation per address across manual files + stubs).
- `just format` / `just format-check <paths>` — clang-format C++. The tree is not fully
  formatted, so run `format-check` on the files you touched, not whole-tree (it is not
  part of `just gates`).
- `just normalize-markers` — reformat `// FUNCTION` / reccmp markers (cosmetic;
  `marker-gate` is the policy check).

## reccmp specifics

reccmp is installed from a pinned fork commit in `pyproject.toml` (no local checkout
needed unless editing reccmp itself). The `just` targets wrap it:

- detection: `reccmp-project detect --what recompiled`
- compare: `reccmp-reccmp --target IMPERIALISM [--verbose 0xADDR]`

Notes: re-run `detect` after each rebuild; tiny wrappers can be folded/aliased by the
linker, so a targeted compare may map to an unexpected symbol; keep `reccmp-user.yml`
local/gitignored and commit only `reccmp-project.yml`.

## Known reccmp failure modes

1. **`Failed to find a match at address 0x...`**
   - Check `// FUNCTION` marker placement (must be immediately above the declaration,
     no comment/blank line between).
   - Check for duplicate address ownership (one impl per address; no duplicate
     `// FUNCTION` across manual files and stubs).
   - Re-run `just sync-ownership` + `just regen-stubs` + `just detect`.
2. **`Dropped duplicate address ...`** — the same address is still annotated in a stub
   shard or another manual file.
3. **Compare name looks like a sentence/comment** — a comment line sits between the
   marker and the declaration.
4. **Build breaks on `__thiscall` in a free typedef** — replace with a `__fastcall`
   bridge shape; never put `__thiscall` casts on free functions/function pointers
   (route through a real class method instead).
