# ---------------------------------------------------------------------------
# rewrite — targets that rewrite source/config from symbols or policy.
# Imported by the root justfile (flat namespace: shared variables/recipes work
# across modules). Recipe text is moved verbatim so `just --list` is unchanged.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# rewrite — targets that rewrite source/config from symbols or policy.
# ---------------------------------------------------------------------------

# MUTATES: source files under src/game + include/game.
[private]
[group('rewrite')]
annotate-globals:
  uv run python -m tools.workflow.annotate_globals_from_symbols --paths src/game include/game --write

# MUTATES: reccmp markers in src/ + include/.
[private]
[group('rewrite')]
normalize-markers:
  uv run python -m tools.workflow.normalize_reccmp_markers --paths src include --write

# MUTATES: config/original_entities.csv + `// SYNTHETIC:` comments (with --apply).
# Canonicalize scalar-deleting-destructor spellings to the MSVC500-mangled form.
# Pass --dry-run to preview. `just synthetic-gate` is the mechanical check.
[doc('MUTATES: symbols.csv + // SYNTHETIC: comments. Canonicalize scalar-dtor spellings')]
[private]
[group('rewrite')]
correct-scalar-dtors *args:
  uv run python -m tools.workflow.correct_scalar_dtors {{args}}

# MUTATES: config/original_entities.csv + stub manifest (with --write).
# Dry-run-first vtable repair planner. Applies only deterministic fixes with --write:
# manifest slot promotion, scalar-dtor spelling cleanup, and safe ILT thunk pruning.
[private]
[doc('MUTATES (--write): original_entities.csv. Dry-run-first vtable repair planner')]
[group('rewrite')]
vtable-autofix *args:
  uv run python -m tools.workflow.vtable_autofix {{args}}

# Rebuild the relocation-masked object-matcher report into build evidence (uncommitted).
# identity oracle by matching the original executable against the vendored
# libcmt.lib/nafxcw.lib COFF members. Needs the original binary (ORIGINAL_BINARY).
[group('rewrite')]
build-library-oracle *args:
  uv run python -m tools.mfc.build_library_oracle {{args}}

# MUTATES: the given paths (clang-format).
[group('rewrite')]
format *paths:
  uv run python -m tools.workflow.format_cpp {{paths}}

# MUTATES: resources/cursors with --write. Reconstruct the custom named cursor files
# from the retail PE's GROUP_CURSOR and CURSOR resources; check mode is read-only.
[doc('MUTATES (--write): resources/cursors. Check or regenerate retail cursor assets')]
[group('rewrite')]
cursor-resources mode="--check":
  : "${ORIGINAL_BINARY:?Set ORIGINAL_BINARY in .env}"
  uv run python -m tools.workflow.pe_resources turn-event-cursors \
    "$ORIGINAL_BINARY" resources/cursors {{mode}}

# MUTATES: resources/bitmaps/backdrop_0119.bmp with --write. Reconstruct the
# executable backdrop bitmap from retail RT_BITMAP 281 without changing its DIB.
[doc('MUTATES (--write): retail executable backdrop bitmap 281')]
[group('rewrite')]
backdrop-resource mode="--check":
  : "${ORIGINAL_BINARY:?Set ORIGINAL_BINARY in .env to your retail Imperialism.exe}"
  uv run python -m tools.workflow.pe_resources bitmap \
    "$ORIGINAL_BINARY" resources/bitmaps/backdrop_0119.bmp --id 281 {{mode}}

# MUTATES: resources/chrome with --write. Reconstruct the app icon and version
# blobs read directly from the retail executable by recovered production source.
[doc('MUTATES (--write): direct retail executable icon and version resources')]
[group('rewrite')]
executable-chrome-resources mode="--check":
  : "${ORIGINAL_BINARY:?Set ORIGINAL_BINARY in .env to your retail Imperialism.exe}"
  uv run python -m tools.workflow.pe_resources executable-chrome \
    "$ORIGINAL_BINARY" resources/chrome {{mode}}
