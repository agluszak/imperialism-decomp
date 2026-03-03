set shell := ["bash", "-eu", "-o", "pipefail", "-c"]
set dotenv-load := true

target := env_var_or_default("TARGET", "IMPERIALISM")
build_dir := env_var_or_default("BUILD_DIR", "build-msvc500")
docker_image := env_var_or_default("DOCKER_IMAGE", "imperialism-msvc500")
cmake_flags := env_var_or_default("CMAKE_FLAGS", "-DCMAKE_BUILD_TYPE=RelWithDebInfo -DIMPERIALISM_MATCH_FLAGS_CSV=/Oy-,/Ob1")
ghidra_program_name := env_var_or_default("GHIDRA_PROGRAM_NAME", "Imperialism.exe")
name_overrides := env_var_or_default("NAME_OVERRIDES", "config/function_name_overrides.csv")
function_ownership := env_var_or_default("FUNCTION_OWNERSHIP", "config/function_ownership.csv")

default:
  @just --list

sync-ghidra:
  : "${GHIDRA_INSTALL_DIR:?Set GHIDRA_INSTALL_DIR in .env}"
  : "${GHIDRA_PROJECT_DIR:?Set GHIDRA_PROJECT_DIR in .env}"
  : "${GHIDRA_PROJECT_NAME:?Set GHIDRA_PROJECT_NAME in .env}"
  uv run python -m tools.ghidra.sync_exports \
    --ghidra-install-dir "$GHIDRA_INSTALL_DIR" \
    --ghidra-project-dir "$GHIDRA_PROJECT_DIR" \
    --ghidra-project-name "$GHIDRA_PROJECT_NAME" \
    --ghidra-program-name "{{ghidra_program_name}}" \
    --name-overrides "{{name_overrides}}"

import-ghidra *args:
  : "${GHIDRA_INSTALL_DIR:?Set GHIDRA_INSTALL_DIR in .env}"
  : "${GHIDRA_PROJECT_DIR:?Set GHIDRA_PROJECT_DIR in .env}"
  : "${GHIDRA_PROJECT_NAME:?Set GHIDRA_PROJECT_NAME in .env}"
  file_in_project="{{ghidra_program_name}}"; \
  [[ "$file_in_project" == /* ]] || file_in_project="/$file_in_project"; \
  (cd "{{build_dir}}" && GHIDRA_INSTALL_DIR="$GHIDRA_INSTALL_DIR" uv run reccmp-ghidra-import \
    --target "{{target}}" \
    --local-project-name "$GHIDRA_PROJECT_NAME" \
    --local-project-dir "$GHIDRA_PROJECT_DIR" \
    --file "$file_in_project" \
    {{args}})

regen-stubs:
  uv run python -m tools.stubgen \
    --name-overrides "{{name_overrides}}" \
    --ownership-csv "{{function_ownership}}"

sync-ownership:
  uv run python -m tools.workflow.sync_function_ownership \
    --target "{{target}}" \
    --ownership-csv "{{function_ownership}}"

annotate-globals:
  uv run python -m tools.workflow.annotate_globals_from_symbols --paths src/game include/game --write

annotate-vtables:
  uv run python -m tools.workflow.annotate_vtables_from_symbols --paths include/game --write

annotate-strings:
  uv run python -m tools.workflow.annotate_strings_from_symbols --paths src/game include/game --write

gen-vcall-facades:
  uv run python -m tools.workflow.generate_vcall_facades --owner-file src/game/TGreatPower.cpp

normalize-markers:
  uv run python -m tools.workflow.normalize_reccmp_markers --paths src include --write

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
  uv run python -m tools.reccmp.progress_stats --target "{{target}}" --build-dir "{{build_dir}}" --detect-recompiled

inventory:
  uv run python -m tools.reccmp.library_inventory --json-out "{{build_dir}}/library_inventory.json"

generate-ignores:
  uv run python -m tools.reccmp.generate_ignore_functions --target "{{target}}" --apply

session-loop pick='8' top='50' min_size='1':
  uv run python -m tools.reccmp.session_loop --target "{{target}}" --pick "{{pick}}" --top "{{top}}" --min-size "{{min_size}}"

bootstrap-reccmp:
  : "${ORIGINAL_BINARY:?Set ORIGINAL_BINARY in .env}"
  uv run reccmp-project create --originals "$ORIGINAL_BINARY" --scm

promote target_cpp *args:
  uv run python -m tools.workflow.promote_from_autogen \
    --target-cpp "{{target_cpp}}" \
    --ownership-csv "{{function_ownership}}" \
    {{args}}

promote-range target_cpp start end:
  uv run python -m tools.workflow.promote_from_autogen \
    --target-cpp "{{target_cpp}}" \
    --ownership-csv "{{function_ownership}}" \
    --range "{{start}}:{{end}}"

full-sync-build:
  just sync-ghidra
  just sync-ownership
  just regen-stubs
  just build
  just detect
  just stats

format *paths:
  uv run python -m tools.workflow.format_cpp {{paths}}

format-check *paths:
  uv run python -m tools.workflow.format_cpp --check {{paths}}
