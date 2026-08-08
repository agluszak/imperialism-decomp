---
name: port-behavior
description: Port a retail Imperialism gameplay behavior into the deterministic Rust domain model using recovered C++ source and the process-isolated oracle. Use for new or corrected commands, state transitions, rules, RNG behavior, ordered events, snapshot fields, or cross-implementation differential coverage under rust/.
---

# Port retail behavior

Run from `rust/` and obey `AGENTS.md`.

1. Define a bounded retail semantic slice and its observable pre-state, input, complete post-state,
   ordered events, RNG effects, and error behavior.
2. Locate the recovered behavior under `../decomp/`. Prefer recovered source and existing runtime
   evidence. Use Ghidra only as a deliberate cross-implementation investigation when source/oracle
   evidence is insufficient.
3. Reuse the current C++ runtime oracle. Extend it only when the required state or event is not
   observable across the process boundary; keep C++-specific layout out of the contract.
4. Define or extend serializable Rust `GameCommand`, state, and `GameEvent` types. Put authoritative
   deterministic behavior in `imperialism-core`; keep compatibility decoding in
   `imperialism-formats` and orchestration in `imperialism-testkit`.
5. Implement the behavior without copying the C++ class hierarchy, MFC ownership, ABI, or incidental
   compiler control flow.
6. Compare the complete post-state and ordered events against the oracle. Add deterministic focused
   tests, serialization round trips, and a differential regression for retail claims.
7. Run format, clippy, and workspace tests. If the oracle changed, also run the required decomp
   verification from `../decomp/`.

Treat a matching symptom with divergent state/events as a failure. Update the one current contract
and every producer, consumer, fixture, and test together; do not retain old forms for hypothetical
users.
