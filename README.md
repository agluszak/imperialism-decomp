# Imperialism

This repository contains two implementations of **Imperialism (1997)** that share behavioral
contracts without sharing implementation structure.

- [`decomp/`](decomp/) reconstructs the Windows retail executable in ABI- and behavior-faithful C++
  using the original MSVC 5.0 toolchain, Ghidra evidence, and `reccmp` verification.
- [`rust/`](rust/) is an independent Rust implementation with deterministic domain state, retail
  importers, a Bevy client, and process-isolated differential tests.
- [`interop/`](interop/) contains only current cross-implementation contracts and fixtures.

Retail behavior is the common reference. The C++ reconstruction can act as an executable oracle for
Rust, but Rust does not link to it or mirror its C++ object layout. Canonical snapshots and the
serializable command/event protocol are the formal boundary.

Run implementation commands from the relevant subproject directory and follow its scoped guide:

- [C++ reconstruction guide](decomp/README.md)
- [Rust implementation guide](rust/README.md)
- [Interoperability contract](interop/README.md)

Repository-wide agent, Beads, Git, and concurrency rules are in [AGENTS.md](AGENTS.md).
