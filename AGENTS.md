# Imperialism repository guide

This repository contains two related implementations of Imperialism (1997):

- `decomp/` is the behaviorally and ABI-faithful C++ reconstruction of the retail game.
- `rust/` is the new Rust implementation.

Retail behavior and evidence are the ultimate behavioral reference. The C++ reconstruction is an
executable oracle for the Rust implementation, but Rust must not reproduce accidental C++/MFC/ABI
structure. Shared contracts are explicit and versioned; the implementations communicate through
serialized data and process boundaries, never by linking Rust to the reconstructed executable.

## Scope

- Follow `decomp/AGENTS.md` for work under `decomp/`.
- Follow `rust/AGENTS.md` for work under `rust/`.
- Cross-implementation changes must satisfy both scoped guides.
- `interop/` contains only contracts and fixtures genuinely shared across implementations.
- Keep implementation-owned code, tests, assets, evidence, and compatibility details in the owning
  subproject. Do not create a generic `shared/` directory.

Start tools from the relevant subproject directory. This keeps implementation-specific instructions,
skills, settings, and command surfaces out of unrelated sessions.

## Shared architecture

- `imperialism-core` owns authoritative deterministic Rust game state and the serializable
  command/event boundary.
- The Bevy application is a presentation, input, and lifecycle client of that domain model.
- Retail import and legacy compatibility belong at format/import boundaries.
- Differential tests invoke the C++ reconstruction as an external process and compare complete
  serialized state and events.
- Canonical snapshots and the serializable command/event protocol are interoperability contracts.
  Version shared formats deliberately and document compatibility changes in `interop/`.

## Beads

This repository uses Beads (`bd`) for durable work tracking and multi-session handoff.

- Run `bd prime` when starting or recovering context.
- Create and claim a Bead before implementation work.
- Use `bd ready`, `bd show <id>`, `bd update <id> --claim`, and `bd close <id>`.
- Record blockers, dependencies, and follow-up work in Beads, not markdown TODO lists.
- Every retail-behavior bug must require faithful source/data/resource/control-flow evidence and a
  semantic test of the real path; symptom suppression is not completion.
- Beads Dolt synchronization is separate from Git publication and requires explicit authorization.

## Git and concurrent work

- Preserve changes you did not create. Never use blanket stash, restore, checkout, reset, or clean
  operations to escape a failure.
- Keep commits scoped and review the complete diff before staging.
- Completed, verified work is committed locally by default. Push or open a PR only when requested.
- Fetch the remote base immediately before publication and verify ancestry rather than trusting a
  potentially stale local branch.
- Do not rewrite policy baselines merely to make a red check pass.
- When verification exposes a real architectural problem, fix forward or report the blocker.

## Documentation

- Keep standing invariants in the nearest scoped `AGENTS.md`.
- Keep repeatable procedures in scoped skills.
- Keep durable technical evidence in the owning subproject's docs or evidence stores.
- Use Beads for active work and Git commits for execution history; do not add worklogs or checked-in
  agent plans.
