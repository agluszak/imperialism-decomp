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
  (`config/canary_targets_*.csv`); run after every accepted iteration. A non-zero
  `below_floor` is a real regression — fix or revert before moving on.

## Export-sync sequence (run whenever markers/ownership change)

```sh
just sync-ownership   # sync function ownership CSV into source annotations
just regen-stubs      # regenerate unresolved stubs
just build
```

## Gates & formatting

- `just vtable-gate` — must pass; do not introduce new raw `vftable[...]` patterns in
  files not already baseline-tracked. `just vtable-gate-update` rewrites the baseline
  after an intentional refactor.
- `just format` / `just format-check` — clang-format C++.
- `just normalize-markers` — normalize `// FUNCTION` / reccmp markers.

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
