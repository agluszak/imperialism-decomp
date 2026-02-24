set shell := ["bash", "-eu", "-o", "pipefail", "-c"]
set dotenv-load := true

target := env_var_or_default("TARGET", "IMPERIALISM")
build_dir := env_var_or_default("BUILD_DIR", "build-msvc500")
docker_image := env_var_or_default("DOCKER_IMAGE", "imperialism-msvc500")
cmake_flags := env_var_or_default("CMAKE_FLAGS", "-DCMAKE_BUILD_TYPE=RelWithDebInfo -DIMPERIALISM_MATCH_FLAGS_CSV=/Oy-,/Ob1")
ghidra_program_name := env_var_or_default("GHIDRA_PROGRAM_NAME", "Imperialism.exe")

default:
  @just --list

sync-ghidra:
  : "${GHIDRA_INSTALL_DIR:?Set GHIDRA_INSTALL_DIR in .env}"
  : "${GHIDRA_PROJECT_DIR:?Set GHIDRA_PROJECT_DIR in .env}"
  : "${GHIDRA_PROJECT_NAME:?Set GHIDRA_PROJECT_NAME in .env}"
  uv run python tools/ghidra/sync_exports.py \
    --ghidra-install-dir "$GHIDRA_INSTALL_DIR" \
    --ghidra-project-dir "$GHIDRA_PROJECT_DIR" \
    --ghidra-project-name "$GHIDRA_PROJECT_NAME" \
    --ghidra-program-name "{{ghidra_program_name}}"

regen-stubs:
  uv run python tools/stubgen.py

annotate-globals:
  uv run python tools/workflow/annotate_globals_from_symbols.py --paths src/game include/game --write

annotate-vtables:
  uv run python tools/workflow/annotate_vtables_from_symbols.py --paths include/game --write

annotate-strings:
  uv run python tools/workflow/annotate_strings_from_symbols.py --paths src/game include/game --write

normalize-markers:
  uv run python tools/workflow/normalize_reccmp_markers.py --paths src include --write

docker-build:
  docker build --network host -t "{{docker_image}}" -f docker/msvc500/Dockerfile docker/msvc500

build:
  mkdir -p "{{build_dir}}"
  docker run --rm --network none \
    -e CMAKE_FLAGS="{{cmake_flags}}" \
    -v "$PWD":/imperialism \
    -v "$PWD/{{build_dir}}":/build \
    "{{docker_image}}"

detect:
  (cd "{{build_dir}}" && uv run reccmp-project detect --what recompiled)

compare addr='':
  if [[ -n "{{addr}}" ]]; then (cd "{{build_dir}}" && uv run reccmp-reccmp --target "{{target}}" --verbose "{{addr}}"); else (cd "{{build_dir}}" && uv run reccmp-reccmp --target "{{target}}"); fi

stats:
  uv run python tools/reccmp/progress_stats.py --target "{{target}}" --build-dir "{{build_dir}}" --detect-recompiled

inventory:
  uv run python tools/reccmp/library_inventory.py --json-out "{{build_dir}}/library_inventory.json"

generate-ignores:
  uv run python tools/reccmp/generate_ignore_functions.py --target "{{target}}" --apply

session-loop pick='8' top='50' min_size='1':
  uv run python tools/reccmp/session_loop.py --target "{{target}}" --pick "{{pick}}" --top "{{top}}" --min-size "{{min_size}}"

bootstrap-reccmp:
  : "${ORIGINAL_BINARY:?Set ORIGINAL_BINARY in .env}"
  uv run python tools/reccmp/bootstrap_reccmp.py --original-binary "$ORIGINAL_BINARY"

promote target_cpp *args:
  uv run python tools/workflow/promote_from_autogen.py --target-cpp "{{target_cpp}}" {{args}}

promote-range target_cpp start end:
  uv run python tools/workflow/promote_from_autogen.py --target-cpp "{{target_cpp}}" --range "{{start}}:{{end}}"

full-sync-build:
  just sync-ghidra
  just regen-stubs
  just build
  just detect
  just stats

format *paths:
  uv run python tools/workflow/format_cpp.py {{paths}}

format-check *paths:
  uv run python tools/workflow/format_cpp.py --check {{paths}}
