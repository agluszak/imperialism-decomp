# Imperialism Rust workspace

This is an independent Cargo workspace. Follow `../AGENTS.md` first; this file contains only
Rust-specific invariants.

## Architecture

Current crate ownership:

- `imperialism-core`: authoritative deterministic game state, rules, and typed domain IDs. No Bevy.
- `imperialism-formats`: retail file decoding/import and retail representation quirks.
- `imperialism-app`: Bevy presentation, input, audio, and lifecycle.
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
(`terrain`, `borders`, `overlays`, `units`).

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
- Core owns the turn sequence: `finish_player_orders`, the answer methods, and `advance_turn`.
  `AppState` is screen routing. Do not chain phases in the app.
- Core owns deterministic sequencing and mutation. The app owns presentation decisions and projects
  core state into Bevy; ECS is not the gameplay database.
- Keep one authoritative representation for each fact and derive secondary facts. Prefer semantic
  Rust types, typed IDs, and `Option` over raw retail storage conventions.
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
  to matter to behavior. In the semantic model:

```text
identity / index / ordinal     usize (`NationId`, `TileId`, `ProvinceId`, …)
ordinary arithmetic            usually i32
retail short with wrap         i16 (`Stockpile`, other wrapping quantities)
persistent retail identity     its real type (military/civilian unit IDs are i32)
encoded byte / bitfield        u8/u16 (`TileOwnerTag`, packed rendering, river sprites)
enum category                  enum + `EnumMap`
absence                        `Option<T>`, never -1
```

  Integer widths from the 1997 representation belong at the formats/capture boundary unless the
  width itself affects game behavior. Index tables by the ID type (`NationTable`, `TileTable`,
  `TechnologyTable`, `EnumMap`). Do not keep a parallel `get()` that returns the same ordinal, and
  do not reconstruct IDs from raw integers in core loops when `Id::all()` or table `enumerate()`
  already yields them. An `as usize` in ordinary gameplay code is a sign the value should have been
  an ID, table key, or `Option` already.

  Do not add conversion traits, `TryFrom` everywhere, or generic typed-index machinery. Eliminate
  the conversions.
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
`CityOrderQuantity`, `TradeDisplay`, `DealBookHost`, and so on) and project
`GameSession` through narrow queries. Do not store widget entity handles in a
parallel object graph, and do not replace that with generated binding structs, a
registry, a second scene model, or another abstraction layer. Screen-owned
presentation lives on the screen entity; application-level facts such as
`SaveDirectory` stay resources. `DespawnOnExit` belongs on state-scope roots and
independently spawned top-level windows/modals; children inherit lifetime from
their parent.

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

## Commands

Run from `rust/`:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Use the narrowest useful test while iterating, then run all three before committing.
