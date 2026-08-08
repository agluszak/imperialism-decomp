---
name: ui-recovery
description: Carry recovered Imperialism UI evidence through the Mac View IR, declared Windows deltas, generated normalized catalog, and Bevy hierarchy without duplicating screen definitions. Use for retail screen structure, generated UI catalog changes, tags and events, rectangles and hierarchy, Bevy UI projections, or UI differential work under rust/.
---

# Recover UI into Bevy

Run Rust work from `rust/` and generator work from `../decomp/`.

1. Identify the retail screen, resource file/view ID, hierarchy, rectangles, tags, state, text/style
   bindings, and platform-specific evidence.
2. Change the committed Mac View IR or a narrowly declared Windows delta in `../decomp/`; do not
   hand-author a parallel Bevy screen description.
3. Run the decomp UI generator check and regenerate the Rust catalog through its explicit sibling
   output path.
4. Keep catalog decoding/normalization in `imperialism-formats`. Build Bevy presentation and input
   projections in `imperialism-app`; invoke direct domain operations rather than mutating
   authoritative state in ECS.
5. Preserve the fixed logical canvas, retail hierarchy and coordinates, deterministic tag/event
   mapping, resource-file-scoped IDs, and nearest-neighbor presentation rules.
6. Add focused generator/catalog tests and Bevy behavior tests. Use a runtime/differential check when
   asserting live retail behavior rather than static resource structure.

If source evidence is incomplete, keep the gap explicit. Do not guess geometry, hierarchy, state, or
event semantics to make the UI look plausible.
