# Imperialism Rust port

This directory is an independent Cargo workspace. It is not part of the CMake, `just`,
MSVC500, or reccmp workflows in the repository root. Run Rust commands from this directory.

- `imperialism-core` owns deterministic game state and the command/event boundary. It has no
  Bevy dependency.
- `imperialism-formats` is the compatibility boundary for retail files and normalized assets.
- `imperialism-app` is the only Bevy-dependent crate and will own presentation and lifecycle.
- `imperialism-testkit` reads and verifies canonical snapshots and will host the process-isolated
  differential runner.

The only contract shared with the C++ implementation is the versioned canonical snapshot and,
later, command protocol. The Rust game state must not depend on C++ layouts or Bevy ECS entities.

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
