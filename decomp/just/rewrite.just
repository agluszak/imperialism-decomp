# Retail resource extraction and source formatting.

# Build the retail library identity oracle from the original executable and
# vendored libcmt.lib/nafxcw.lib COFF members. Needs ORIGINAL_BINARY.
[private]
[group('rewrite')]
build-library-oracle *args:
  uv run python -m tools.mfc.build_library_oracle {{args}}

# Recover retail ___xi/___xc initializer-array boundaries from __cinit into build evidence.
[private]
[group('rewrite')]
build-crt-startup-oracle *args:
  uv run python -m tools.reccmp.crt_startup_oracle {{args}}

# MUTATES: the given paths (clang-format).
[group('rewrite')]
format *paths:
  uv run python -m tools.workflow.format_cpp {{paths}}

# MUTATES: resources/cursors with --write. Reconstruct the custom named cursor files
# from the retail PE's GROUP_CURSOR and CURSOR resources; check mode is read-only.
[private]
[doc('MUTATES (--write): resources/cursors. Check or regenerate retail cursor assets')]
[group('rewrite')]
cursor-resources mode="--check":
  : "${ORIGINAL_BINARY:?Set ORIGINAL_BINARY in .env}"
  uv run python -m tools.workflow.pe_resources turn-event-cursors \
    "$ORIGINAL_BINARY" resources/cursors {{mode}}

# MUTATES: resources/bitmaps/backdrop_0119.bmp with --write. Reconstruct the
# executable backdrop bitmap from retail RT_BITMAP 281 without changing its DIB.
[private]
[doc('MUTATES (--write): retail executable backdrop bitmap 281')]
[group('rewrite')]
backdrop-resource mode="--check":
  : "${ORIGINAL_BINARY:?Set ORIGINAL_BINARY in .env to your retail Imperialism.exe}"
  uv run python -m tools.workflow.pe_resources bitmap \
    "$ORIGINAL_BINARY" resources/bitmaps/backdrop_0119.bmp --id 281 {{mode}}

# MUTATES: resources/chrome with --write. Reconstruct the app icon and version
# blobs read directly from the retail executable by recovered production source.
[private]
[doc('MUTATES (--write): direct retail executable icon and version resources')]
[group('rewrite')]
executable-chrome-resources mode="--check":
  : "${ORIGINAL_BINARY:?Set ORIGINAL_BINARY in .env to your retail Imperialism.exe}"
  uv run python -m tools.workflow.pe_resources executable-chrome \
    "$ORIGINAL_BINARY" resources/chrome {{mode}}
