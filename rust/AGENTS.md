# Imperialism Rust guide

This directory is an independent Cargo workspace for the Rust implementation. Follow the shared
repository rules in `../AGENTS.md` plus this guide.

## Architecture

Keep these four crates. Do not split the core into subsystem microcrates, move authoritative state
into ECS, or introduce a second snapshot-domain model.

- `imperialism-core` owns authoritative deterministic game state, rules, and typed IDs. It must not
  depend on Bevy. Direct domain operations return concrete outputs needed by current callers; emit
  non-state effects only when an existing consumer or oracle comparison requires them.
- `imperialism-formats` owns retail-file parsing, import, normalization, and retail-format ugliness.
- `imperialism-app` owns Bevy presentation, input, audio, and lifecycle. ECS is a disposable
  projection, not the gameplay database.
- `imperialism-testkit` owns canonical snapshot comparison and process-isolated C++ oracle tooling.
- Port retail behavior, not the recovered C++ class hierarchy, ownership model, MFC types, ABI, or
  incidental control flow.

Keep domain types beside their behavior modules (`game`, `map`, `nations`, `city/`, `diplomacy`,
`turn_flow`, and so on). City production orders live under `city/`; facility slots are
`CityFacilitySlot`. Export a curated crate-root surface—do not reintroduce broad `state::*` or
`production::*` globs or a prelude. In formats, keep retail binary parse separate from `GameState`
projection. In the app, keep city UI split by retail dialog under `ui/city/`.

Keep retail compatibility concessions at format, import, or oracle boundaries. Do not leak raw offsets,
weak identifiers, binary-layout constraints, or C++-shaped APIs into the domain model merely because
the decomp uses them.

## Domain operations and failures

- Prefer direct typed methods on `GameState`. Do not introduce a universal `GameCommand`, command
  bus, event-sourcing layer, or event for every private helper.
- Return operation-specific results when callers need them. Keep effects only for ordered
  observables absent from authoritative state, such as notifications, sounds, modal prompts, or
  acknowledgement requests. Do not emit effects that merely restate state mutations.
- Keep app flow `input → one core operation → state/results/effects → UI projection`. Turn sequencing
  belongs in core through `advance_turn_step` / `advance_until_yield`, not in a Bevy schedule.
- External decode or malformed payload errors return `Result`. Legal gameplay rejection returns a
  typed outcome or narrow domain error the UI can use. Broken internal invariants are prevented by
  structure where practical and otherwise assert or `expect`; do not thread them through rule APIs.

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

## Differential fidelity

- Preserve capture collection order and semantic IDs. Native transitions compare complete
  `before`/`case`/`after` state, the semantic operation result, and any required ordered non-state
  effects; do not normalize order. Model `before`/`after` travel as retail `.imp` saves plus a small
  ephemeral JSON overlay for session-only fields.
- Validate published runtime result envelopes strictly: name, seed, status, evidence kind, required
  captures, and unknown capture fields. Model differentials publish under `native_transition_oracle`.
- Preserve the native oracle's evidence kind. `retail_fixture_oracle` proves agreement with the
  reconstructed C++ executable from a retail-derived fixture; only `retail_differential` certifies
  that behavior against the original executable.
- Advance turns only through `advance_turn_step`. Unported alert, acknowledgement, and phase work
  stops at the current phase; do not mutate to the next phase before its authoritative work and
  effects exist.
- Add a differential by writing one C++ case function plus table row and one Rust integration test
  beside the domain; do not add Python catalog entries for ordinary model transitions.

## Collection order and identities

- Nation, major-nation, minor-nation, resource, production, and map tables are fixed-position
  semantic collections. Preserve their indexes exactly.
- Compare `GameState` vectors in captured order; do not sort or normalize them in the comparator.
  Recruitment currently preserves contiguous per-nation unit blocks.
- `MilitaryUnitId` and `CivilianUnitId` come from retail save `persistent_id` values, and loaded army
  mission references resolve to those persistent military IDs.
- `ShipId` and `TaskForceId` are snapshot-local positions in preserved primary-list and queue order;
  preserve those orders and rewrite every reference together. Legacy projection of non-empty retail
  navy relationships remains unsupported until the save's references can be resolved independently.
  `PhaseCode` remains an open numeric domain; type codes only as rules prove them.

## Behavioral work

- Prefer recovered C++ source and the existing process oracle when retail semantics matter.
- Do not reach for Ghidra or `reccmp` merely because the repository contains them. Binary-level
  investigation is a deliberate cross-implementation/reverse-engineering task, not part of normal
  Rust or Bevy development.
- Put deterministic behavior in `imperialism-core` as direct operations that return the concrete
  output current callers need. Keep Bevy input and presentation outside the game model.
- Compare complete post-state, operation results, and required ordered non-state effects, not only
  the symptom or a selected field.
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
