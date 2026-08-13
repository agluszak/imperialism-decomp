---
name: port-behavior
description: Port a retail Imperialism gameplay behavior into the deterministic Rust domain model using recovered C++ source and the process-isolated oracle. Use for new or corrected direct operations, state transitions, rules, RNG behavior, ordered non-state effects, snapshot fields, or cross-implementation differential coverage under rust/.
---

# Port retail behavior

Run from `rust/` and obey `AGENTS.md`.

1. Define a bounded retail semantic slice and its observable pre-state, input, complete post-state,
   semantic operation result, ordered non-state effects when needed, RNG effects, and rejection/error
   behavior.
2. Locate the recovered behavior under `../decomp/`. Prefer recovered source and existing runtime
   evidence. Use Ghidra only as a deliberate cross-implementation investigation when source/oracle
   evidence is insufficient.
3. Reuse the current C++ runtime oracle. Extend it only when the required state, result, or effect is
   not observable across the process boundary; keep C++-specific layout out of the contract.
4. Add direct typed domain operations and return the concrete output current callers need. Do not add
   a universal `GameCommand` or command bus. Add an effect only for an ordered non-state observable
   required by an existing consumer or oracle comparison; do not restate state mutations. Put
   authoritative deterministic behavior in `imperialism-core`, retail decoding in
   `imperialism-formats`, and oracle orchestration in `imperialism-testkit`.
5. Implement the behavior without copying the C++ class hierarchy, MFC ownership, ABI, or incidental
   compiler control flow.
6. Compare complete post-state, semantic result, and required ordered non-state effects. Preserve the
   native evidence kind: `retail_fixture_oracle` is reconstruction agreement, not direct retail
   proof. Add one C++ `NativeTransition` case plus table row and one ignored `compare_native`
   integration test beside the domain. `compare_native` must consume that run's unique output; do not
   publish through a shared result file. Do not add a Python catalog entry for an ordinary model
   transition. Use a small corpus of deliberately constructed rule cases; reserve stable seed corpora
   for RNG-heavy behavior.
7. Classify failures correctly: external decode/malformed payload → `Result`; legal gameplay
   rejection → typed outcome or narrow domain error; broken internal invariant → structure, assert,
   or `expect`, not a shared rule error.
8. Run format, clippy, and workspace tests. If the oracle changed, also run the required decomp
   verification from `../decomp/`.

Treat a matching symptom with divergent state, result, or required effect as a failure. Update the
one current contract and every producer, consumer, fixture, and test together; do not retain old
forms or version repository-owned protocols for hypothetical users.
