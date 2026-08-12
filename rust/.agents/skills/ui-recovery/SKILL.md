---
name: ui-recovery
description: Carry recovered Imperialism UI evidence through the Mac View IR and declared Windows deltas into generated native Bevy hierarchies without duplicating screen definitions.
---

# Recover UI into Bevy

Run Rust work from `rust/` and generator work from `../decomp/`.

1. Identify the retail screen, resource file/view ID, hierarchy, rectangles, tags, state, text/style
   bindings, and platform-specific evidence.
2. Change the committed Mac View IR or a narrowly declared Windows delta in `../decomp/`; do not
   hand-author a parallel Bevy screen description.
3. Run the decomp UI generator check and regenerate the checked-in native Rust source through its
   explicit sibling output path.
4. Emit native Bevy components and `ChildOf` directly in `imperialism-app`; invoke one direct typed
   core operation rather than mutating
   authoritative state in ECS. Do not invent a universal `GameCommand` layer for UI wiring. Project
   returned state, results, and required non-state effects.
5. Preserve the fixed logical canvas, retail hierarchy and coordinates, deterministic tag/event
   mapping, resource-file-scoped IDs, and nearest-neighbor presentation rules.
6. Add focused generator and Bevy behavior tests. Use a runtime/differential check when
   asserting live retail behavior rather than static resource structure.

If source evidence is incomplete, keep the gap explicit. Do not guess geometry, hierarchy, state, or
event semantics to make the UI look plausible.
