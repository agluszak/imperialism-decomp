# C++ reconstruction workflows

Run these commands from `decomp/`. `just --list` is the authoritative command catalog; commands marked
`MUTATES:` change the named source, configuration, or Ghidra state.

## Fresh checkout

```sh
cp .env.example .env             # set GHIDRA_INSTALL_DIR and ORIGINAL_BINARY
git lfs pull
just vendor-msvc500-headers
just restore-project
just docker-build
just bootstrap-reccmp
just build
```

A new worktree needs its own `.env` and `reccmp-user.yml`. Docker images and the local Ghidra
installation are machine-wide. A worktree beneath a dot-directory needs a dot-free
`GHIDRA_PROJECT_DIR` override because Ghidra refuses such paths. One-time setup recipes
(`vendor-msvc500-headers`, `bootstrap-reccmp`, …) remain invokable even when hidden from
`just --list`.

## Recovery campaigns

```sh
# inspect a saved comparison and choose a shared source-model cause
just compare-report build/comparisons/BASELINE --queue --campaigns --output build/campaign.json
# batch the unanswered retail reads; edit canonical owners and their consumers
# normally cover roughly 50–100 affected functions before expensive verification
just build
just compare --changed
# run the relevant runtime differential when observable behavior may change
just precommit
```

Read the scoped `AGENTS.md` and matching skill before editing. Start with saved reports, group by
shared type/layout/data defects, then signatures/ownership, then behavioral control flow. Fix the
canonical owner across a coherent batch. Use focused comparisons only to resolve a concrete
uncertainty. Rebuild and compare once per substantial batch; full precommit belongs near its end.

## Comparison evidence

```sh
just compare --all --output build/comparisons/BASELINE
just compare 0xADDR TMapMaker:: --file src/game/map_generation/TMapMaker.cpp
just compare --changed --base origin/main
just compare-report build/comparisons/HEAD --base build/comparisons/BASE
just addr 0xADDR
just datacmp
just vtable ClassName
```

`--all` selects only authored `// FUNCTION:` claims from the existing source model. `--file` accepts
source files and headers; headers select their includers through the native source index. Explicit
address selectors must have an authored claim. `--changed` selects changes against the merge base,
including local edits and untracked source files. Build/toolchain changes require `--all`.

reccmp owns pairing and analysis preparation; Ghidriff owns decompiled-code differences. Results are
`no-differences`, `differences`, `unpaired`, and `analysis-failed`. A difference is evidence to inspect,
not a failed percentage test. A clean decompilation does not establish original source spelling.
Retail instructions and runtime differential fixtures remain the stronger evidence.

Each run saves reccmp's manifest, summary, Ghidriff report, direct-call census, and logs, plus authored
selection provenance and full datacmp/vtable diagnostics. `compare-report` counts outcomes, inline
retries and retries that become clean, data issues, and vtable match/different/unpaired results. Its
call queue is an inspection queue, not proof of manual inlining or incorrect behavior. The optional
campaign groups count shared original data findings, direct-call targets, and source owners;
they do not infer which reference caused a difference. The optional
base report must be a whole-authored dataset built at the current merge base; dataset additions and
removals are reported separately from shared-function outcome transitions.

Comparison keeps disposable analysis in `build/reccmp-ghidra/`. It reads reviewed signatures from
the restored committed Imperialism Ghidra archive; it never exports comparison state over that
archive. Preserve saved reports before source changes. Keep VC5 `/Ob1`; inline normalization does
not establish that a helper or translation-unit split existed in the original source.

## Ownership and generated inputs

`// FUNCTION:`, `// STUB:`, `// SYNTHETIC:`, `// TEMPLATE:`, and `// LIBRARY:` markers in manual source
are the ownership authority. CRT/MFC identities live as `// LIBRARY:` / identity
`// SYNTHETIC:` markers (see `src/game/core/library_identities.cpp`). After a marker
change, run `just build`; it rebuilds the source index and stubs. Never edit generated
files to clear a failure.

## Deliberate Ghidra changes

Use the corresponding `just` Ghidra mutation command, inspect the evidence, and export intentionally:

```sh
just ghidra-apply-source --apply
just export-project
```

After a genuine boundary repair, use `just refresh-inventory`, inspect the curated inventory change, and
export the project before committing. Ghidra discovers evidence; manual source remains hand-owned.
