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
`turn_flow`, and so on). City production orders live under `city/`; facility slots are
`CityFacilitySlot`. Export a curated crate-root surface—do not reintroduce broad `state::*` or
`production::*` globs or a prelude. In formats, keep retail binary parse separate from `GameState`
projection. In the app, keep city UI split by retail dialog under `ui/city/`. Keep the strategic map
split by retail draw stage under `ui/strategic_map/` (`terrain`, `borders`, `overlays`, `units`).

Port retail behavior, not the recovered C++ architecture. C++ class hierarchy, ownership, ABI,
integer storage widths, sentinels, offsets, and control flow are evidence, not Rust design. Keep
retail-layout ugliness at format/import/oracle boundaries unless it is itself observable game
semantics.

## Domain model

- Keep gameplay state and rules in `imperialism-core`. Prefer direct typed operations and queries over
  command buses, event-sourcing layers, generic validators, or framework-like indirection.
- Core owns deterministic sequencing and mutation. The app owns presentation decisions and projects
  core state into Bevy; ECS is not the gameplay database.
- Keep one authoritative representation for each fact and derive secondary facts. Prefer semantic
  Rust types, typed IDs, and `Option` over raw retail storage conventions.
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

City dialogs store concrete entity handles and update only their own controls. Do not replace that
with generated binding structs, a registry, a second scene model, or another abstraction layer.

## Retail fidelity

Prefer recovered C++ source and the existing process oracle when retail semantics are uncertain. Use
Ghidra or `reccmp` only for deliberate reverse-engineering work, not routine Rust development.

When a change claims retail behavior, compare the complete relevant semantic state, operation result,
and ordered non-state effects. Extend the existing oracle only when it cannot observe the required
fact; do not create another protocol or harness for convenience. Use the `port-behavior` skill for
cross-implementation gameplay work.

## Commands

Run from `rust/`:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Use the narrowest useful test while iterating, then run all three before committing.
