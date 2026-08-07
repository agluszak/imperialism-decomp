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

## Strategic-map snapshot viewer

The Bevy app reads a persisted canonical snapshot and a normalized local asset manifest. It does
not start or link the C++ game. To make a development asset pack from the non-copyrighted example
palette and persist a snapshot directly from the retail save fixture:

```sh
cp -r assets.example imported-assets
cargo run -p imperialism-formats --bin legacy-inspect -- \
  ../tests/runtime/fixtures/beginning_of_game.imp --canonical 1 1 1 1 0 \
  > beginning-of-game.snapshot.json
cargo run -p imperialism-app -- beginning-of-game.snapshot.json
```

The app renders through a fixed 960x540 logical canvas with nearest-neighbour scaling and
letterboxing. Cursor hit-testing uses the retail odd-row hex geometry and updates the window title
with the typed tile's terrain, owner, and region. `GameState` stays in `imperialism-core`; Bevy ECS
contains only the immutable presentation handle and entities carrying `TileRef`, `NationRef`,
`CityRef`, `MilitaryUnitRef`, or `ShipRef`.
