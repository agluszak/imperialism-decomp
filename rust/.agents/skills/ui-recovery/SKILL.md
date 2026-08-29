---
name: ui-recovery
description: Carry retail UI evidence through the committed Mac View IR or Windows delta, generator, BSN output, and Bevy wiring.
---

# Recover UI into Bevy

Generator commands run from `decomp/`; Rust commands run from `rust/`.

1. Identify the retail resource file and View ID plus the evidenced hierarchy, rectangles, tags,
   state, text/style bindings, and Windows-specific differences.
2. Update the committed Mac View IR source or the narrow semantic Windows input in
   `decomp/config/ui_factory_windows_views.yml` / `ui_platform_deltas.yml`. Do not edit generated
   Rust or C++ output.
3. From `decomp/`, inspect and regenerate with:

   ```sh
   just ui-resource-show FILE:VIEW_ID
   (cd ../decomp && uv run python -m tools.ui_rust_codegen --write)
   just ui-codegen-check
   just build
   ```

   Use `just ui-codegen-explain FUNCTION EVENT [NODE]` and
   `just ui-codegen-triage FUNCTION` when tracing generated evidence.
4. In `imperialism-app`, wire the generated native Bevy/BSN scene to its existing screen route,
   presentation components, and direct typed core operation.
5. Add the smallest focused generator or Bevy interaction check needed for the recovered behavior.
   Use a runtime/differential scenario for claims about live retail behavior.
6. Run the three Rust verification commands from `rust/`; if decomp evidence or generation changed,
   run the decomp `verify` procedure too.

If evidence is incomplete, leave the gap explicit rather than guessing geometry, hierarchy, state, or
event semantics.
