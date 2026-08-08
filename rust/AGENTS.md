# Imperialism Rust guide

This directory is an independent Cargo workspace for the Rust implementation. Follow the shared
repository rules in `../AGENTS.md` plus this guide.

## Architecture

- `imperialism-core` owns authoritative deterministic game state, rules, and typed IDs. It must not
  depend on Bevy. Direct domain operations return concrete outputs needed by current callers; emit
  domain events only when an existing consumer or oracle comparison requires them.
- `imperialism-formats` owns retail-file parsing, import, normalization, and retail-format ugliness.
- `imperialism-app` owns Bevy presentation, input, audio, and lifecycle. ECS is a disposable
  projection, not the gameplay database.
- `imperialism-testkit` owns canonical snapshot comparison and process-isolated C++ oracle tooling.
- Port retail behavior, not the recovered C++ class hierarchy, ownership model, MFC types, ABI, or
  incidental control flow.

Keep retail compatibility concessions at format, import, or oracle boundaries. Do not leak raw offsets,
weak identifiers, binary-layout constraints, or C++-shaped APIs into the domain model merely because
the decomp uses them.

## Domain types and arithmetic

- Treat recovered C++ widths, signedness, sentinels, and packed fields as format evidence, not as
  default Rust domain types. Choose core types from the game rule they represent.
- Decode retail packing and sentinel values at format and oracle boundaries. In `imperialism-core`,
  represent absence with `Option`. Prefer plain `bool` fields until multiple independent flags share
  one value; only then consider `bitflags`. Do not expose masks, sentinel integers, or raw retail
  storage entries as domain APIs.
- Normalize one-based indexes, sentinels, and packed encodings once while reading the retail
  format. Do not duplicate a raw value in a widened DTO field and narrow it later; do not add a
  fallible conversion when the source type and branch already prove the destination range. Make
  semantic ID constructors infallible unless retail evidence establishes a real domain bound.
- Use ordinary arithmetic for domain rules. Only use wrapping or fixed-width overflow when retail
  behavior demonstrably depends on that overflow as an observable rule; document that evidence at
  the narrow boundary where it matters.

## Behavioral work

- Prefer recovered C++ source and the existing process oracle when retail semantics matter.
- Do not reach for Ghidra or `reccmp` merely because the repository contains them. Binary-level
  investigation is a deliberate cross-implementation/reverse-engineering task, not part of normal
  Rust or Bevy development.
- Put deterministic behavior in `imperialism-core` as direct operations that return the concrete
  output current callers need. Keep Bevy input and presentation outside the game model.
- Compare complete post-state (and ordered events when a consumer/oracle requires them), not only the
  symptom or a selected field.
- Add the smallest focused Rust test that proves the primary behavior. Do not accumulate edge-case
  or representation-detail tests without a concrete regression they prevent. Add or extend a
  differential oracle when the change asserts retail semantics.
- Preserve deterministic RNG state, iteration order, and observable error behavior. Preserve a
  retail integer width only when it is itself part of the observable rule; otherwise use the
  semantic Rust type. Model retail save-format distinctions only when retail evidence requires them.

Load the `port-behavior` skill for cross-implementation gameplay work. Load `ui-recovery` for the
View IR/catalog/Bevy hierarchy pipeline. Do not create generic Rust or Bevy skills without a repeated,
project-specific workflow that justifies them.

## Commands

Run commands from `rust/`:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Use the narrowest useful test during iteration, then run all three checks before committing. The C++
oracle is invoked through `../decomp/`; never link the implementations.

## Source and docs

- Keep public types narrow and explicit; prefer typed IDs over loosely interpreted integers.
- Keep unsafe code forbidden unless a separately reviewed boundary genuinely requires it.
- Keep generated assets generated. Change the source evidence or generator, then regenerate.
- Update `README.md` when launch/import/operator workflows change.
- Record active follow-up work in Beads, not source TODO inventories or checked-in plans.
