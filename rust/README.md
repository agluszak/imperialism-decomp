# Imperialism Rust port

This directory is an independent Cargo workspace and a first-class sibling of the C++
reconstruction in `../decomp/`. Run Rust commands from this directory.

- `imperialism-core` owns deterministic game state, direct rule operations, and domain events.
  It has no Bevy dependency.
- `imperialism-formats` parses retail files and accesses retail assets directly.
- `imperialism-app` is the only Bevy-dependent crate and owns presentation and lifecycle.
- `imperialism-testkit` reads named semantic captures and runs process-isolated differential
  checks.

Native semantic scenarios capture `before`, `case`, `after`, and `result` JSON; the testkit validates the published runtime envelope strictly and compares operation outcomes as well as complete GameState. Ordinary Rust tests call
`differential(scenario, |state, case| { ... })`, apply the Rust operation, and compare complete
states with `first_serialized_difference`. Retail fixtures live in `../fixtures/retail/`. The Rust
game state does not depend on C++ layouts or Bevy ECS entities.

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Native-oracle differential tests are ignored by default (they need Wine/`just runtime-run`):

```sh
cargo test -p imperialism-testkit -- --ignored
```

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
remain scoped by resource file, and each node carries its runtime rectangle, parent, tag, state,
interactivity, and text/style bindings. Do not hand-write a second screen description in the Bevy
crate.
