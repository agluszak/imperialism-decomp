# Imperialism Rust workspace

This is an independent Cargo workspace. Follow `../AGENTS.md` first; this file contains only
Rust-specific invariants.

## Architecture

Keep the existing four-crate split:

- `imperialism-core`: authoritative deterministic game state, rules, and typed domain IDs. No Bevy.
- `imperialism-formats`: retail file decoding/import and retail representation quirks.
- `imperialism-app`: Bevy presentation, input, audio, and lifecycle.
- `imperialism-testkit`: process-isolated C++ oracle and semantic comparison support.

Do not split the core into subsystem crates or introduce another authoritative state model without a
concrete need.

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

## Bevy UI

Use Bevy directly. Recovered UI should become native Bevy/BSN hierarchy, with handwritten code limited
to behavior wiring and small reusable helpers. Do not add a parallel generic UI tree, node registry,
loader, catalog, or imperative scene abstraction beside Bevy entities.

Generated UI is generated: change the recovery evidence or generator, then regenerate it. Use the
`ui-recovery` skill for that workflow.

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
