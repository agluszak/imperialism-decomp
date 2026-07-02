---
name: quality-control
description: Build, measure, and gate the Imperialism decomp — rebuild with Docker MSVC500, run reccmp detect/compare/stats, compare aggregate stats against baseline, enforce the raw-vtable gate, format C++, and diagnose reccmp pairing failures. Use when building, checking similarity scores, guarding against regressions, or debugging why a function won't pair.
---

# Quality control

Build, measurement, gates, and regression diagnosis. Obey the Command Policy in
`AGENTS.md`: use `just` targets, not raw `docker`/`uv run reccmp-*`.

## Build & measure

- `just tooling-check` — verify the toolchain surface is present.
- `just build` — full pipeline: `vtable-gate` → Docker MSVC500
  build.
- `just detect` — re-run reccmp recompiled detection (do this after every rebuild).
- `just compare 0xADDR` — targeted verbose compare of one function (the acceptance
  gate for a touched body). With no address, runs a full compare.
- **Batch mode (one PDB parse for many functions — use this instead of looping
  single compares):** `just compare 0xA 0xB 0xC ...` scores several addresses at
  once; `just compare --file src/game/X.cpp` scores every `// FUNCTION:` marker in
  a file; `just compare-class X` is shorthand for the latter. All three run reccmp
  once with `--json` (seconds total, vs ~10s of PDB parsing per single compare).
- `just stats` — aggregate progress compared against the committed baseline. It reports
  improved and worsened metrics separately.
- `just stats-baseline-update` — update the committed aggregate baseline after accepting the
  current stats snapshot. Per-function `compare` remains the real gate for touched
  bodies.

## Pre-commit sequence

```sh
just precommit      # build + gates + tooling tests + stats in one command
just stats-baseline-update   # if stats are acceptable; commit baseline with source
```

See `.cursor/rules/commit-workflow.mdc` for regression thresholds and failure handling.

## Export-sync sequence (run whenever markers/ownership change)

```sh
just regen-stubs      # reconciles ownership CSV + checks symbols.csv, then regenerates stubs
just build
```

## Gates & formatting

- `just gates` — run all mechanical source-policy gates (the pre-commit check):
  `vtable-gate`, `antipattern-gate`, `tgreatpower-gate`, `marker-gate`,
  `vtable-annotation-gate`, `vtable-collision-gate`, `field-layout-gate`,
  `synthetic-gate`, and `decomplint`. **All must pass before committing.**
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
   - Re-run `just regen-stubs` + `just detect`.
2. **`Dropped duplicate address ...`** — the same address is still annotated in a stub
   shard or another manual file.
3. **Compare name looks like a sentence/comment** — a comment line sits between the
   marker and the declaration.
4. **Build breaks on `__thiscall` in a free typedef** — replace with a `__fastcall`
   bridge shape; never put `__thiscall` casts on free functions/function pointers
   (route through a real class method instead).
5. **`InvalidVirtualAddressError: …Imperialism.exe : 0x…`** (reccmp crashes hard
   during compare/stats) — the exe and PDB are out of sync: the PDB references code
   past the current exe. Almost always a wrong-flags build. Rebuild with `just build`
   (real flags: `RelWithDebInfo`, `IMPERIALISM_LINK_MFC=ON`, `/Oy-,/Ob1`) — a good
   build is ~742 KB exe + a fresh ~4.8 MB pdb, not a ~120 KB exe with a stale pdb.
6. **`Target IMPERIALISM is missing data: recompiled_path,recompiled_pdb`** — the
   `build-msvc500/reccmp-build.yml` is stale/missing (e.g. after `rm -rf build-msvc500/`).
   Run `just detect` to repopulate it, then re-run the reccmp tool.
7. **`just vtable` shows *all* (or hundreds of) vtables "not matching", each failing at
   the same slot 0x04** — the scalar-deleting-destructor names in `config/symbols.csv`
   drifted from the form the recomp PDB emits. They must read
   `` <Class>::`scalar deleting destructor' `` (backticks, spaces) to pair; a regen can
   rewrite them to `'scalar_deleting_destructor'` or `Destruct<Class>AndMaybeFree`, which
   never pair. Diff `config/symbols.csv` against the last-good commit and restore the
   scalar-dtor name field per address (commit 22efcd3c restored the whole file from its
   parent after the 5b715e03 regen broke 272/272 vtables and dropped 369 aligned funcs).
   The same regen-induced name drift also shows up as a large `just stats` alignment drop.
