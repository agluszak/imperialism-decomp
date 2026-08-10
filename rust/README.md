# Imperialism Rust port

This directory is an independent Cargo workspace and a first-class sibling of the C++
reconstruction in `../decomp/`. Run Rust commands from this directory.

- `imperialism-core` owns deterministic game state and direct typed rule operations. It has no Bevy
  dependency and exposes non-state effects only when a current consumer requires them; there is no
  universal command bus.
- `imperialism-formats` parses retail files and accesses retail assets directly.
- `imperialism-app` is the only Bevy-dependent crate and owns presentation and lifecycle.
- `imperialism-testkit` reads named semantic captures and runs process-isolated differential
  checks.

Native semantic scenarios capture `before`, `case`, `after`, and `result` JSON. The testkit strictly
validates the published scenario name, seed, status, evidence kind, required captures, and unknown
fields, then compares operation outcomes as well as complete `GameState`. Each Rust scenario keeps
its name, case type, result type, and direct apply function together, then calls
`differential(SCENARIO, apply_scenario)`. Retail fixtures live in `../fixtures/retail/`. The Rust game
state does not depend on C++ layouts or Bevy ECS entities.

Evidence classifications are retained: `retail_fixture_oracle` means Rust agrees with the current C++
reconstruction from a retail-derived fixture; it is not direct original-executable equivalence.
`retail_differential` is the classification for behavior checked against the original executable.

Core APIs distinguish malformed external input (`Result`), legal gameplay rejection (a typed outcome
or narrow domain error), and broken internal invariants (structure, assertion, or `expect`).

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

To start from a retail save, also provide the runtime state that the `.imp` file does not store:

```sh
cargo run -p imperialism-app -- \
  --retail-dir /path/to/Imperialism \
  --load-save ../fixtures/retail/beginning_of_game.imp \
  --game-state CRT_RAND MAP_LCG ZONE_LCG SELECTED_NATION
```

Use all four values from the same native capture. In particular, the zone-status RNG state is
process-derived and must not be replaced with a fixture-wide default.

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
