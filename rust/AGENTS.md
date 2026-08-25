# Imperialism Rust workspace

This is an independent Cargo workspace. Follow `../AGENTS.md` plus these Rust invariants.

## Architecture

- `imperialism-core` owns authoritative deterministic gameplay state, rules, sequencing, and
  mutation. It has no Bevy dependency. Answer hover and action questions with semantic types
  (`HoverAction`, `CivilianTileAction`, `ArmyMapCursorState`, `DiplomacyMapAction`); do not store
  retail cursor, picture, or sound resource IDs.
- `imperialism-formats` owns retail file decoding and representation quirks. Opaque persisted values
  stay there until their gameplay meaning is recovered.
- `imperialism-app` owns Bevy presentation, input, media, screen routing, and lifecycle. ECS projects
  core state; it is not a second gameplay database or turn sequencer. Map core semantic answers to
  retail cursor, picture, and sound resource IDs here.
- `imperialism-testkit` owns process-isolated access to the C++ oracle and semantic comparison.
- Keep one authoritative representation for each semantic fact and derive projections. Do not add a
  parallel snapshot, sidecar order, ECS authority, or duplicated rule state.
- Prefer direct typed core operations and queries. Add a command, event, effect, validator, wrapper,
  collection abstraction, or framework only when a concrete current caller cannot be served clearly
  without it.

## Retail model

- Port observable retail behavior, not the recovered C++ implementation structure. C++ classes, MFC
  ownership, ABI layout, offsets, integer storage, sentinels, and incidental compiler control flow
  are evidence, not Rust architecture.
- Use semantic Rust types, typed IDs, `Option`, and collections that express the domain. Retail
  representation quirks belong at format, import, export, or oracle boundaries unless the quirk is
  itself observable gameplay semantics.
- Preserve observable retail iteration order, stable identity, RNG state and consumption, operation
  results, ordered non-state effects, rejection behavior, and complete relevant state. Do not sort,
  normalize, or reshape them merely to simplify comparison.
- Production code must be general to the supported retail game, not specialized to a fixture, turn,
  nation, difficulty, or scenario. Recovered rules are complete only when authoritative and invoked
  by the intended production path.

## Recovered UI

- Recovered UI definitions come from committed recovery evidence and the existing generator. Change
  that evidence or generator and regenerate; do not maintain parallel handwritten screen trees.
- Generated output is native Bevy/BSN hierarchy. Handwritten app code wires presentation behavior to
  direct typed core operations and projects authoritative results.
- Keep retail hierarchy, coordinates, tags, ordering, and presentation semantics when observable.
  Do not promote recovery-only offsets or symbolic node identifiers into runtime identity.
- `GameSession` holds only `GameState`. Detailed-map camera origin, city-dialog positions, and
  captured battle-report strings are separate resources (`MapViewOrigin`, `CityWindows`,
  `BattleReportPresentation`) so scrolling or layout changes do not mark gameplay changed. Do not
  split `GameState` itself into ECS components.
- Immutable retail catalogs used by simulation (`GameData`, currently the news story-id table) are
  loaded once onto `GameState` and are not persisted. Do not thread them through gameplay
  operations.
- Immutable retail catalogs used by simulation (`GameData`, currently the news story-id table) are
  loaded once onto `GameState` and are not persisted. Do not thread them through gameplay
  operations.

Use `port-behavior` for the C++-to-Rust differential procedure and `ui-recovery` for the resource-to-
Bevy generation procedure.

## Retail claims

Use recovered C++ source and the existing external-process oracle when retail semantics are uncertain
or a change claims cross-implementation fidelity. Compare complete relevant semantic state, the
operation result, ordered effects, and RNG behavior. Extend the current oracle only when it cannot
observe a required semantic fact; do not add a second harness or repository-owned protocol version.

`retail_fixture_oracle` proves agreement with reconstructed C++ initialized from retail-derived data;
it is not direct retail differential evidence.

## Verification

Run from `rust/`:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
```

Use focused checks while iterating, then run all three for a completed Rust change.
