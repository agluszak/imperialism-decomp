# Imperialism C++ reconstruction

This directory reconstructs the 1997 Windows executable using Visual C++ 5.0,
retail and Mac CodeWarrior evidence, Ghidra, and reccmp. It is independent of
the Rust implementation in `../rust/`. Run commands from `decomp/`.

Retail binaries and proprietary game data are not checked in. Supply your own
legally obtained `Imperialism.exe`.

## Setup

Requirements: Git LFS, `just`, `uv`, Docker, Wine/GDB, Java 25 and the pinned
Ghidra fork.

```sh
cp .env.example .env
# Set GHIDRA_INSTALL_DIR, JAVA_HOME, ORIGINAL_BINARY
git lfs pull
just vendor-msvc500-headers
just restore-project
just docker-build
just bootstrap-reccmp
just build
```

The optional Mac dump is only needed to regenerate vendored Mac evidence.
A separate checkout needs its own `.env` and `reccmp-user.yml`; the
Docker image and installed Ghidra distribution can be reused.

## Working on recovered source

```sh
just build
just compare --changed
just compare 0x00401000
just vtable ClassName
just datacmp
just lint
just precommit
```

Comparison differences are evidence to investigate, not a reason to distort
period C++ for a score. Prefer fixing shared semantic, ABI, layout and
ownership causes. Run runtime differentials when behavior is affected, and
use `just precommit` for relevant substantial changes.

`just --list` is the command reference. Ghidra procedures are in
[docs/ghidra-db.md](docs/ghidra-db.md); compiler/toolchain facts are in
[docs/toolchain.md](docs/toolchain.md); compiler-owned emissions are described
in [docs/compiler-emissions.md](docs/compiler-emissions.md).

## Ownership

- `src/`, `include/` — reconstructed C++.
- `config/` — reviewed model inputs.
- `vendor/` — pinned toolchain headers, Mac evidence, and reviewed Ghidra archive.
- `tools/` — Ghidra, comparison, and runtime tooling.
- `build-msvc500/`, `build-runtime-tests/` — disposable outputs.

Change the owning source or input, not generated artifacts. For a deliberate
Ghidra change, inspect it before `just export-project`. The scoped
[AGENTS.md](AGENTS.md) contains source-fidelity rules; durable evidence
references are indexed in [docs/reference/README.md](docs/reference/README.md).
