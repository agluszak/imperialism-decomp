# Imperialism Rust guide

This directory is an independent Cargo workspace for the Rust implementation. Follow the shared
repository rules in `../AGENTS.md` plus this guide.

## Architecture

- `imperialism-core` owns authoritative deterministic game state, rules, typed IDs, commands, and
  ordered domain events. It must not depend on Bevy.
- `imperialism-formats` owns retail-file parsing, import, normalization, and retail-format ugliness.
- `imperialism-app` owns Bevy presentation, input, audio, and lifecycle. ECS is a disposable
  projection, not the gameplay database.
- `imperialism-testkit` owns canonical snapshot comparison and process-isolated C++ oracle tooling.
- Port retail behavior, not the recovered C++ class hierarchy, ownership model, MFC types, ABI, or
  incidental control flow.

Keep retail compatibility concessions at format, import, or oracle boundaries. Do not leak raw offsets,
weak identifiers, binary-layout constraints, or C++-shaped APIs into the domain model merely because
the decomp uses them.

## Behavioral work

- Prefer recovered C++ source and the existing process oracle when retail semantics matter.
- Do not reach for Ghidra or `reccmp` merely because the repository contains them. Binary-level
  investigation is a deliberate cross-implementation/reverse-engineering task, not part of normal
  Rust or Bevy development.
- Put deterministic behavior in `imperialism-core`, then expose it through serializable commands and
  events. Bevy systems submit commands and project results.
- Compare complete post-state and ordered events, not only the symptom or a selected field.
- Add ordinary focused Rust tests for every behavior change. Add or extend a differential oracle
  when the change asserts retail semantics.
- Preserve deterministic RNG state, iteration order, integer widths, and error behavior. Model
  retail format-version distinctions only when retail evidence requires them.

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
