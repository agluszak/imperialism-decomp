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
4. Emit code-defined BSN containing native Bevy components and `Children` in `imperialism-app`.
   Reuse the small handwritten retail scene functions/templates for geometry, pictures, and fonts;
   do not generate commands, asset-cache access, resource-node locals, or a generic scene component.
   Spawn the concrete generated function with `Commands::spawn_scene`; invoke one direct typed core
   operation rather than mutating
   authoritative state in ECS. Do not invent a universal `GameCommand` layer for UI wiring. Project
   returned state, results, and required non-state effects.
5. Preserve the fixed logical canvas, retail hierarchy and coordinates, deterministic tag/event
   mapping, and nearest-neighbor presentation rules. Resource offsets and symbolic node IDs remain
   recovery evidence used to reconstruct the tree; do not emit them as runtime identity.
6. Add focused generator and Bevy behavior tests. Use a runtime/differential check when
   asserting live retail behavior rather than static resource structure.

Every screen-local top-level scene must be state-scoped with `DespawnOnExit`; descendants inherit
lifetime through `ChildOf`. Do not repeat `DespawnOnExit` on children. Explicit close may despawn
early but must not be the sole cleanup path. `ModalDialog` is only a marker and does not clean
anything up.

If source evidence is incomplete, keep the gap explicit. Do not guess geometry, hierarchy, state, or
event semantics to make the UI look plausible.
