---
name: port-behavior
description: Keep Rust gameplay behavior aligned with the reconstructed C++ oracle.
---

# Port behavior

Run from `rust/`.

- Implement behavior in `imperialism-core` using semantic Rust types and connect it to the production
  caller.
- Use the existing `NativeTransition`/oracle path; extend it only when an observable semantic fact is
  otherwise unavailable.
- Compare relevant state, result, ordered effects, rejection behavior, and RNG state.
- Keep fixture-derived evidence labeled `retail_fixture_oracle`; it is not direct retail execution.
- Run `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`,
  and `cargo test --workspace`.
