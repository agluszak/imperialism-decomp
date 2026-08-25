---
name: port-behavior
description: Port a bounded retail gameplay operation into Rust core and compare it through the existing C++ process oracle.
---

# Port retail behavior

Run from `rust/`.

1. Identify the recovered C++ operation and its observable pre-state, input, post-state, result,
   ordered effects, RNG behavior, and rejection behavior.
2. Check whether the existing `NativeTransition` and runtime result already expose those semantics.
   Extend the current transition/result only for a missing observable fact, updating every producer
   and consumer together.
3. Implement one direct typed operation in `imperialism-core` and connect it to its production caller.
4. Add representative native transition cases and `compare_native` coverage beside the domain. Compare
   complete relevant state through `ComparisonSnapshot`, the semantic result, ordered effects, and RNG
   state. Use deliberately constructed cases for rules and a small stable seed corpus for RNG-heavy
   behavior. Save-format differentials belong with the retail save loader, not every game-rule case.
5. Keep the evidence label accurate: reconstruction initialized from a retail-derived fixture is
   `retail_fixture_oracle`, not a direct retail differential.
6. Run:

   ```sh
   cargo fmt --all -- --check
   cargo clippy --workspace --all-targets --all-features -- -D warnings
   cargo test --workspace
   ```

7. If C++ oracle source or protocol output changed, run the `verify` procedure from `../decomp/`.

A matching visible symptom with divergent state, result, effects, or RNG is still a failure.
