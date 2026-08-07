# Interoperability boundary

This directory contains only contracts and fixtures that are consumed by both the C++ reconstruction
and the Rust implementation. It is not a general-purpose shared-code directory.

The implementations currently interoperate through:

- canonical, versioned JSON snapshots of complete deterministic game state;
- serializable `GameCommand` inputs and ordered domain events;
- process-isolated differential runs in which Rust invokes the C++ runtime oracle and compares the
  resulting state and events;
- the retail-produced fixture in `fixtures/`, whose provenance and digest are recorded beside it.

Rust must not depend on reconstructed C++ object layout, MFC types, calling conventions, or linkage.
Compatibility details owned by one implementation stay in that implementation. Add a schema here
only when it is an actual versioned cross-implementation artifact with producers and consumers on
both sides.

## Fixtures

`fixtures/beginning_of_game.imp` is a retail save used by both implementations. Its metadata file
records the exact SHA-256 digest, format version, provenance, and covered scenarios. The C++ runtime
fixture loader and Rust format tests both resolve this shared path.
