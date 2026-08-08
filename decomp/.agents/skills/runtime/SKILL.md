---
name: runtime
description: Run, debug, author, and validate native semantic runtime scenarios for the Imperialism C++ reconstruction under Wine. Use for live retail/recomp behavior, screenshots, winedbg sessions, runtime harness failures, deterministic scenarios, UI screens and flows, fixtures, differential captures, or new runtime tests under decomp/.
---

# Work with the runtime

Run from `decomp/`.

- Read [run-debug.md](references/run-debug.md) for launching under Wine, scripted debugger sessions,
  window-ID capture, and live visual verification.
- Read [runtime-tests.md](references/runtime-tests.md) before adding or migrating a semantic scenario,
  screen, flow, fixture, or protothread script.

Reproduce the retail path and repair incomplete fixture/resource state rather than bypassing it.
Runtime success proves only the path the scenario actually traverses; pair it with source/data/control-
flow evidence when closing a retail-faithfulness bug. Keep the C++ oracle process-isolated from Rust.
