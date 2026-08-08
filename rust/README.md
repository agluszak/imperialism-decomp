# Imperialism Rust port

This directory is an independent Cargo workspace and a first-class sibling of the C++
reconstruction in `../decomp/`. Run Rust commands from this directory.

- `imperialism-core` owns deterministic game state and the command/event boundary. It has no
  Bevy dependency.
- `imperialism-formats` parses retail files and accesses retail assets directly.
- `imperialism-app` is the only Bevy-dependent crate and owns presentation and lifecycle.
- `imperialism-testkit` reads and verifies canonical snapshots and runs the process-isolated
  differential checks.

The only contracts shared with the C++ implementation are canonical snapshots and the
serializable command/event protocol documented in `../interop/`. The Rust game state does not
depend on C++ layouts or Bevy ECS entities.

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Run a C++ fixture as an external oracle and compare it with a Rust-produced snapshot:

```sh
cargo run -p imperialism-testkit --bin differential -- \
  save_load_roundtrip path/to/rust-snapshot.json --seed 1
```

The runner invokes the existing C++ runtime command across a process boundary. It does not link
the implementations or add Cargo to the repository-root tooling.

## Normal retail launch

Normal launch requires an explicit English GOG installation. The app validates the files it uses
and reads them directly before Bevy constructs a window; the retail path is not persisted.

```sh
cargo run -p imperialism-app -- --retail-dir /path/to/Imperialism
```

## Recovered UI catalog

The existing UI generator also emits the deterministic 640x480 launch catalog consumed by Rust:

```sh
(cd ../decomp && uv run python -m tools.ui_codegen --check)
(cd ../decomp && uv run python -m tools.ui_codegen --write-rust-catalog)
```

The catalog is generated from the committed Mac View IR plus declared Windows deltas. Resource IDs
remain scoped by resource file, and each node preserves its retail rectangle, parent, tag, state,
text/style bindings, historical class, and resource offset. Do not hand-write a second screen
description in the Bevy crate.
