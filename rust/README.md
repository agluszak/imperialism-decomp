# Imperialism Rust port

This directory is an independent Cargo workspace and a first-class sibling of the C++
reconstruction in `../decomp/`. Run Rust commands from this directory.

- `imperialism-core` owns deterministic game state and the command/event boundary. It has no
  Bevy dependency.
- `imperialism-formats` is the compatibility boundary for retail files and normalized assets.
- `imperialism-app` is the only Bevy-dependent crate and owns presentation and lifecycle.
- `imperialism-testkit` reads and verifies canonical snapshots and will host the process-isolated
  differential runner.

The only contracts shared with the C++ implementation are versioned canonical snapshots and the
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

Normal launch requires an explicit English GOG installation. The importer validates every required
input and imports or reuses its content-addressed cache before Bevy constructs a window; the retail
path is not persisted.

```sh
cargo run -p imperialism-app -- --retail-dir /path/to/Imperialism
```

Use `--cache-dir PATH` to override the platform cache directory.

## Strategic-map snapshot viewer

The Bevy app reads a persisted canonical snapshot and a normalized local asset manifest. It does
not start or link the C++ game. To make a development asset pack from the non-copyrighted example
palette and persist a snapshot directly from the retail save fixture:

```sh
cp -r assets.example imported-assets
cargo run -p imperialism-formats --bin legacy-inspect -- \
  ../interop/fixtures/beginning_of_game.imp --canonical 1 1 1 1 0 \
  > beginning-of-game.snapshot.json
cargo run -p imperialism-app -- viewer beginning-of-game.snapshot.json
```

The app renders through a fixed logical canvas with nearest-neighbour scaling and
letterboxing. Cursor hit-testing uses the retail odd-row hex geometry and updates the window title
with the typed tile's terrain, owner, and region. `Simulation` stays in `imperialism-core`; the
single-writer Bevy `GameSession` submits serializable commands, records accepted commands, and
publishes ordered domain events. Bevy ECS contains only disposable projections carrying
`TileRef`, `NationRef`, `CityRef`, `MilitaryUnitRef`, or `ShipRef`.

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
