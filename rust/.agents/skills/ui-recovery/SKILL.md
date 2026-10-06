---
name: ui-recovery
description: Carry retail UI evidence through the existing generator into Bevy.
---

# UI recovery

Use committed recovery evidence and the existing generator; do not hand-edit generated Rust or C++.

From `decomp/`:

```sh
just ui-resource-show FILE:VIEW_ID
uv run python -m tools.ui_rust_codegen --write
just ui-codegen-check
```

Wire generated output in `imperialism-app` using the existing screen route and semantic core operations.
Use focused tests for generator or interaction changes, and runtime differential scenarios for claims
about live retail behavior. Leave unsupported details explicit rather than guessing them.
