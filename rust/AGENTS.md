# Imperialism Rust workspace

This is an independent Cargo workspace. Follow `../AGENTS.md` first; this file contains only
Rust-specific invariants.

## Architecture

Current crate ownership:

- `imperialism-core`: authoritative deterministic game state, rules, and typed domain IDs. No Bevy.
- `imperialism-formats`: retail file decoding/import and retail representation quirks.
- `imperialism-app`: Bevy presentation, input, audio, movies, chrome, and lifecycle.
- `imperialism-testkit`: process-isolated C++ oracle and semantic comparison support.

Crate count follows actual ownership. Do not split the core into subsystem crates or introduce
another authoritative state model without a concrete need.

Keep domain types beside their behavior modules (`game`, `map`, `nations`, `city/`, `diplomacy`,
`turn_flow`, `turn_tail`, `ai/`, and so on). City production orders live under `city/`; facility slots are
`CityFacilitySlot`. The AI interior minister that fills city/transport orders lives in
`ai/interior.rs`; `city_transport_phase.rs` keeps the retail `DoCityAndTransport` sequence.
Export a curated crate-root surface—do not reintroduce broad `state::*` or
`production::*` globs or a prelude. In formats, keep retail binary parse separate from `GameState`
projection. In the app, keep `GameSession` in `ui/session.rs` and city UI split by retail dialog
under `ui/city/`. Keep the strategic map split by retail draw stage under `ui/strategic_map/`
(`terrain`, `borders`, `overlays`, `units`). Media playback lives in `imperialism-app::media`;
retail movie/music/WAVE/chrome discovery lives on `RetailAssets`. Do not reconstruct MCI,
DirectSound, VfW, CD devices, or a generic media framework.

Port retail behavior, not the recovered C++ architecture. C++ class hierarchy, ownership, ABI,
integer storage widths, sentinels, offsets, and control flow are evidence, not Rust design. Keep
retail-layout ugliness at format/import/oracle boundaries unless it is itself observable game
semantics.

## Domain model

- Keep gameplay state and rules in `imperialism-core`. Prefer direct typed operations and queries over
  command buses, event-sourcing layers, generic validators, or framework-like indirection.
- Keep recovered semantic state in core. Opaque persisted or captured retail values stay in
  `imperialism-formats` until their gameplay meaning is recovered. Whole-state differential
  comparison must not force unknown save bytes into the domain model.
- `GameState` map and ocean are crate-private. Inspect with `map()` / `ocean()`; change the viewport
  through named methods such as `scroll_map_viewport` and `center_map_on`.
- Core owns the turn sequence: `finish_player_orders`, interrupt answers including
  `close_turn_deal_book`, and `advance_turn`. Newspaper pages are built from `news.tab`
  ids installed once on `GameState` when a live session is created or loaded.
  Those ids are live-session rule input and are omitted from semantic JSON.
  `AppState` is screen routing; `apply_turn_stop` only maps a stop to a screen.
  Do not chain phases in the app.
- Core owns deterministic sequencing and mutation. The app owns presentation decisions and projects
  core state into Bevy; ECS is not the gameplay database.
- Keep one authoritative representation for each fact and derive secondary facts. Prefer semantic
  Rust types, typed IDs, and `Option` over raw retail storage conventions.
- Keep retail-sized semantic IDs when their width is natural. Use `Option` instead of integer
  sentinels. Use `EnumMap` for closed-enum tables. Do not add collection wrappers or widen IDs
  merely to eliminate casts; explicit boundary conversions are fine.
- Persisted city-dialog origins and the strategic viewport origin are saved session state, not
  production or terrain. Model them as `Option<CityWindowPosition>` and `map_view_origin`; keep the
  retail field triples at the formats boundary.
- Return ordinary values or narrow typed outcomes. Represent effects only for ordered observable
  output not already present in state, such as sounds, notifications, or modal/acknowledgement work.
  Do not emit events that merely restate mutations.
- Preserve retail iteration order, collection identity, RNG state, and other observable semantics.
  Do not sort or normalize state merely to make comparison easier.
- Treat supported retail files and repository-owned fixtures as trusted inputs. Use `Result` for
  genuinely recoverable I/O/decoding failures, typed outcomes for legal gameplay rejection, and
  assertions/`expect` for broken internal invariants. Do not repeatedly validate whole state around
  ordinary operations.
- Use ordinary Rust arithmetic and widths unless retail-visible overflow or storage width is proven
  to matter to behavior.
- Do not clone `GameState` to answer a query.
- Separate planning from mutation for order UI: compare the needed quantity against
  `city_order_limit`; do not mutate-and-rollback authoritative state as a probe.

## Production completeness

Do not put code specialized to one fixture, turn, nation, difficulty, or scenario in production.

An incomplete gameplay feature remains disabled. A non-working feature should look non-working; it
must not mutate half the world and pretend to be an implementation.

No production `first_turn_*` APIs.

Do not preserve an abstraction merely because tests were built around it. Testing infrastructure has
no compatibility contract.

## Bevy UI

Use Bevy directly. Recovered UI should become native Bevy/BSN hierarchy, with handwritten code limited
to behavior wiring and small reusable helpers. Do not add a parallel generic UI tree, node registry,
loader, catalog, or imperative scene abstraction beside Bevy entities.

Generated UI is generated: change the recovery evidence or generator, then regenerate it. Use the
`ui-recovery` skill for that workflow.

Put presentation meaning on the actual entities (`IndustryCapacity`,
`CityOrderQuantity`, `TradeDisplay`, `DealBookHost`, `GameStatusDisplay`,
and so on) and project `GameSession` through narrow queries. Do not store
widget entity handles in a parallel object graph, and do not replace that
with generated binding structs, a registry, a second scene model, or another
abstraction layer. Screen-owned presentation lives on the screen entity;
application-level facts such as `SaveDirectory` stay resources. `DespawnOnExit`
belongs on state-scope roots and independently spawned top-level windows/modals;
children inherit lifetime from their parent. Use `Res<RetailAssetsResource>` for
string and palette lookups; `RetailUiAssets` is for loading or mutating Bevy
fonts and images.

Binders attach semantic identity, static style, and interaction. Observers
mutate game or screen state. Projectors are the only code that derive dynamic
presentation from that state, including the first frame. Do not compute the
same display value while binding and again while projecting. Group projected
presentation by the Bevy component being written (`Text`, `ImageNode`,
`Visibility`), not one marker type per widget and not one god-system per
screen.

Keep `EnumMap` for closed-enum tables and `NationTable`/`ProvinceTable` as
persistent domain containers. Do not wrap local palettes or lookup arrays in
table types merely to index by ID.

## Retail fidelity

Prefer recovered C++ source and the existing process oracle when retail semantics are uncertain. Use
Ghidra or `reccmp` only for deliberate reverse-engineering work, not routine Rust development.

When a change claims retail behavior, compare the complete relevant semantic state, operation result,
and ordered non-state effects. Extend the existing oracle only when it cannot observe the required
fact; do not create another protocol or harness for convenience. Use the `port-behavior` skill for
cross-implementation gameplay work.

City production tests follow that same hierarchy: process-isolated C++ differential for retail
behavior, public `GameState` order tests where a local fixture is enough, and tiny pure-function
tests only for non-obvious arithmetic. Do not reconstruct private setter plumbing in tests, and do
not freeze reservation, progress, or constraint field writes that a higher-level test already
covers. Retail binary-format tests stay field-detailed because the representation is the contract.

A test should normally survive only if it pins recovered retail/C++ behavior that is not obvious
from the Rust type declaration, exercises a meaningful branch or interaction, checks a
serialization boundary against independently specified bytes, compares against the native oracle,
or protects a historical bug. Do not keep tests whose sole purpose is inserting a component and
reading it back, echoing a helper argument, restating an enum discriminant, verifying Bevy
lifecycle machinery, asserting that an untouched local is unchanged, or round-tripping our writer
through our reader. Do not keep giant white-box snapshots of incidental initialization values when
the native oracle already compares complete state. A missing fixture is a test failure: do not
`return` early because setup was not what the test expected. UI tests that assert our behavior
should trigger typed `Activate` (or other domain events) rather than reconstructing Bevy pointer
machinery.

## Commands

Run from `rust/`:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
```

Use the narrowest useful test while iterating, then run all three before committing.
