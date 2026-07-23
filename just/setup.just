# ---------------------------------------------------------------------------
# setup — one-time bootstrap / image builds.
# Imported by the root justfile (flat namespace: shared variables/recipes work
# across modules). Recipe text is moved verbatim so `just --list` is unchanged.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# setup — one-time bootstrap / image builds.
# ---------------------------------------------------------------------------

[group('setup')]
docker-build:
  docker build --network host -t "{{docker_image}}" -f docker/msvc500/Dockerfile docker/msvc500

[group('setup')]
bootstrap-reccmp:
  : "${ORIGINAL_BINARY:?Set ORIGINAL_BINARY in .env}"
  uv run reccmp-project create --originals "$ORIGINAL_BINARY" --scm

[doc('Install the local generated-reccmp-baseline merge driver (tracked hooks regenerate after conflicts)')]
[group('setup')]
install-reccmp-merge-driver:
  uv run python -m tools.workflow.reccmp_baseline_merge install

# Generate ./compile_commands.json (clang-lint flavor, host paths) for clangd/LSP
# navigation. Not for matching questions — the reccmp build is MSVC500. The lint
# *build* may fail (advisory); the database comes from the CMake configure step.
[group('setup')]
gen-compile-commands:
  -just lint "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"
  uv run python -m tools.workflow.gen_compile_commands

[group('setup')]
vendor-msvc500-headers *args:
  uv run python -m tools.workflow.vendor_msvc500_headers {{args}}

# Mirror the DirectX 5 SDK inc/lib (reference copy of C:\dxsdk in the build image).
[group('setup')]
vendor-directx-headers *args:
  uv run python -m tools.workflow.vendor_directx_headers {{args}}
