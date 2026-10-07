# Imperialism Rust workspace

This is an independent Rust implementation. Follow `../AGENTS.md` plus these invariants.

## Architecture

- `imperialism-core` owns deterministic gameplay state, rules, sequencing, and mutation. It has no
  Bevy dependency.
- `imperialism-formats` owns retail file decoding and representation quirks.
- `imperialism-app` owns Bevy presentation, input, media, screen routing, and lifecycle. ECS projects
  core state; it is not a second gameplay database.
- `imperialism-testkit` owns process-isolated access to the C++ oracle and semantic comparison.
- Keep one authoritative representation for each semantic fact. Do not add parallel snapshots,
  sidecars, ECS authority, duplicated rule state, or generic indirection without a concrete current
  need.

## Retail fidelity

- Port observable retail behavior, not the recovered C++ implementation structure. C++ classes, MFC
  ownership, ABI layout, offsets, storage types, and compiler-shaped control flow are evidence, not
  Rust architecture.
- Use semantic Rust types. Keep retail representation quirks at format, import, export, or oracle
  boundaries unless the quirk is itself observable gameplay semantics.
- Preserve observable iteration order, stable identity, RNG state and consumption, operation results,
  ordered effects, rejection behavior, and relevant state.
- Production code must implement the supported retail game generally, not a fixture, scenario, turn,
  nation, or test harness. Recovered behavior is complete only when used by the intended production
  path.

## UI and evidence

Follow `docs/ui-architecture.md` for recovered UI architecture. Change committed recovery evidence or
the existing generator rather than maintaining parallel handwritten screen trees.

Use recovered C++ and the existing external-process oracle when retail semantics are uncertain.
`retail_fixture_oracle` proves agreement with reconstructed C++ initialized from retail-derived data;
it is not direct retail differential evidence.

Use the `port-behavior` and `ui-recovery` skills for their respective procedures. Verification
commands and task runbooks belong in skills, not this file.
