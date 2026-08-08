---
name: runtime
description: Run and author focused retail/recomp runtime scenarios under Wine for the Imperialism C++ reconstruction.
---

# Work with the runtime

Run from `decomp/`.

1. Reproduce one retail path with the existing runtime harness or a focused scenario.
2. Use the actual fixture, resources, and event flow. Do not add test-only state, fallback behavior, or
   a bypass when the scenario cannot reach the retail path; repair the missing model instead.
3. Compare the native result against retail where the semantics matter, then keep the regression test
   deterministic and narrow.
4. Use the runtime/debug `just` targets for Wine, capture, and debugger sessions. A passing scenario
   proves only the path it exercises; pair it with listing/source evidence for a faithfulness claim.
