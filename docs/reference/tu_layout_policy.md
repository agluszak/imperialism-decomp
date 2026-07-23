# TU layout policy (src/game)

The default is **one class per translation unit, named after the class**:
`src/game/<subsystem>/<ClassName>.cpp` paired with `include/game/<ClassName>.h`, holding every
method the class owns. Free-function modules use a descriptive snake_case name
(`sea_geometry.cpp`, `quickdraw_rendering.cpp`) and must not carry a class-shaped
`TClassName_*` name.

Rules:

1. **Class-owned methods live in the class's own file.** A `// FUNCTION:` marker for
   `TFoo::Bar` belongs in `TFoo.cpp`. reccmp pairs by address marker, so relocating a
   function to its owner file is score-safe (watch anon-namespace helpers, which are
   file-keyed under MSVC500, and possible COMDAT/template-instantiation shifts).
2. **`<ClassName>_<part>.cpp` splits are exceptions**, allowed only with a
   *demonstrated* codegen or reccmp/PDB-pairing reason, recorded both in the file's
   header comment and as a `split_exception` row in
   `config/tu_layout_allowlist.csv`. "The function is big" alone is not a reason.
3. **Family modules** (one file holding a closed set of sibling classes, e.g. the
   minister-personality sets or the resource-template dialog shells) are allowed when
   per-class files would be dozens of near-empty TUs; record them as `family_module`
   rows in the allowlist.
4. **Tiny satellite TUs get merged.** A file holding one or two small methods of a
   class that already has its own TU is a layout defect, not a split exception.
5. No arbitrary or historical names for class-owned code (`cd_audio.cpp` for
   `TCdAudioDevice`, `TC2TemplateDialog.cpp` for 19 dialog classes, etc.); rename to
   the owning class (or family-module name) and update includers.

`config/tu_layout_allowlist.csv` is pipe-separated (`file|kind|reason`) and is
consumed by the structure-audit gate; every `TClassName_*.cpp` split and every
multi-class family file must have a row there, or the gate flags it.

## Allowlist kinds

`config/tu_layout_allowlist.csv` (`file|kind|reason|classes`) records every
deliberate exception, consumed by the structure-audit gate's cross-file
ownership rule:

- `family_module` — a closed sibling set sharing one file (personality modules,
  sea_geometry, TTemplateDialogs). Any class's claims are allowed in the file.
- `companion_record` — file-private helper records whose only methods serve the
  file's main class; the `classes` column names exactly which classes are
  allowed there.
- `split_exception` — a `ClassName_<part>.cpp` TU kept separate for a
  demonstrated codegen/pairing reason (recorded in the reason column and the
  file header). The class must still be the pre-underscore base name.
