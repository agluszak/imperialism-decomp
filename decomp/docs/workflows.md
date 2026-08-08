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
`GHIDRA_PROJECT_DIR` override because Ghidra refuses such paths.

## Recover a function

```sh
bd update <issue> --claim
just ghidra portprep 0xADDR
just ghidra listing 0xADDR
# edit the manual C++ source
just build
just triage 0xADDR
just precommit
```

Read the scoped `AGENTS.md` and matching skill before editing. Work from instructions and data, not a
decompiler label. `triage` is the comparison authority: act on `mismatch`; accept `effective`; investigate
the metadata/evidence behind `inconclusive`. `just compare 0xADDR` is the optional raw-diff view.

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
