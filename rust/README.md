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

Native semantic transitions capture save-backed `before`/`after` (`.imp` plus ephemeral session
fields), with JSON `case`/`result`, through the C++ `native_transition_oracle` scenario. Domain
integration tests call `compare_native(case, apply)`, which launches `just native-oracle` into a
unique output directory and compares against that run's native `result.json` / `captures.json`.
Retail fixtures live in `../fixtures/retail/`. The Rust game state does not depend on C++ layouts or
Bevy ECS entities.

Evidence classifications are retained: `retail_fixture_oracle` means Rust agrees with the current C++
reconstruction from a retail-derived fixture; it is not direct original-executable equivalence.
`retail_differential` is the classification for behavior checked against the original executable.

Core APIs distinguish malformed external input (`Result`), legal gameplay rejection (a typed outcome
or narrow domain error), and broken internal invariants (structure, assertion, or `expect`).

```sh
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Native-oracle differential tests are ignored by default (they need Wine/`just native-oracle`):

```sh
cargo test -p imperialism-core -- --ignored
```

## Normal retail launch

Normal launch requires an explicit English GOG installation. The app validates the files it uses
and reads them directly before Bevy constructs a window; the retail path is not persisted.

```sh
cargo run -p imperialism-app -- --retail-dir /path/to/Imperialism
```

Saves are read and written as retail `slot0.imp`…`slot7.imp` / `slotA.imp` files in `Save/` under the installation, matching the recovered game. Override that directory with `--save-dir` when developing:

```sh
cargo run -p imperialism-app -- \
  --retail-dir /path/to/Imperialism \
  --save-dir /tmp/imperialism-saves
```

Load Game on the main menu and Save/Load on the in-game Flag menu use that directory. The `.imp`
file does not store RNG. Retail `DoRead` leaves the process CRT `rand()`, map-generation LCG, and
zone-status LCG alone: an in-game load keeps the live session streams, and a main-menu load seeds
CRT from `time(0)` like `TSimMgr::ISimMgr`, leaves the map LCG at BSS zero, and seeds the zone LCG
from the 16 ms tick clock like `GetTickCountDiv16()`.

To start from a retail save, also provide the runtime state that the `.imp` file does not store:

```sh
cargo run -p imperialism-app -- \
  --retail-dir /path/to/Imperialism \
  --load-save ../fixtures/retail/beginning_of_game.imp \
  --game-state CRT_RAND MAP_LCG ZONE_LCG SELECTED_NATION
```

Use all four values from the same native capture. In particular, the zone-status RNG state is
process-derived and must not be replaced with a fixture-wide default.

## Recovered native UI

The existing UI generator emits deterministic native Bevy scenes into `imperialism-app`:

```sh
(cd ../decomp && uv run python -m tools.ui_codegen --check)
(cd ../decomp && uv run python -m tools.ui_codegen --write-rust-ui)
```

The generated source is compiled from the committed Mac View IR plus declared Windows deltas. It
describes `Node`, `Children`, native widget, text, and image components with code-defined BSN;
handwritten retail scene helpers centralize repeated geometry and asset-backed templates. Callers
spawn each concrete scene with `Commands::spawn_scene`. `RetailTag` is used only while binding
recovered controls to typed screen behavior; `Entity` and `ChildOf` are the runtime identity and
hierarchy. Do not add another generic UI representation, generated imperative spawner, or loader.
