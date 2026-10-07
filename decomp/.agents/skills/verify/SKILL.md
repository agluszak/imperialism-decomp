---
name: verify
description: Run the relevant checks for C++ reconstruction or tooling changes.
---

# Verify

Run from `decomp/`.

- Build with `just build`.
- Use `just compare --changed`; use `just compare --all` for broad build/toolchain changes.
- Run `just vtable ClassName`, `just datacmp`, `just serde-audit`, or runtime differential tests only
  when relevant to the change.
- Format manual source with `just format <paths>` and `just format-check <paths>`.
- Use `just gates` for source-policy changes and `just precommit` before finishing substantial source
  changes.

Treat comparison output as evidence. Do not chase compiler-only differences.
