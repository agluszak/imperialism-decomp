# Instrumented semantic runtime tests. Runtime actions execute inside the game
# process on its UI thread; no external coordinate automation belongs here.

[doc('Build the native semantic runtime-test executable into build-runtime-tests/')]
[private]
[group('runtime-test')]
runtime-test-build jobs=num_cpus():
  mkdir -p "{{runtime_test_build_dir}}"
  uv run python -m tools.workflow.msvc_build_lock \
    --lock "{{runtime_test_build_dir}}/.msvc-build.lock" -- just _build-runtime-tests-unlocked {{jobs}}

[private]
_build-runtime-tests-unlocked jobs:
  just vtable-gate
  uv run python -m tools.generate --gen-dir "{{runtime_test_build_dir}}/generated"
  uv run python -m tools.runtime.generate_native_registry \
    --output "{{runtime_test_build_dir}}/generated/runtime/RuntimeRegistry.inc"
  docker run --rm --network none \
    -e CMAKE_FLAGS="-DIMPERIALISM_RUNTIME_TESTS=ON" \
    -e CMAKE_GENERATOR="{{ if jobs == '1' { 'NMake Makefiles' } else { 'NMake Makefiles JOM' } }}" \
    -e BUILD_JOBS="{{ if jobs == '1' { '' } else { jobs } }}" \
    -v "$PWD":/imperialism \
    -v "$PWD/{{runtime_test_build_dir}}":/build \
    "{{docker_image}}"

[private]
[doc('Compile the native runtime harness with clang-cl diagnostics')]
[group('runtime-test')]
runtime-harness-lint:
  just runtime-source-policy-gate
  uv run python -m tools.runtime.generate_native_registry \
    --output "{{runtime_lint_build_dir}}/generated/runtime/RuntimeRegistry.inc"
  just _lint-in "{{runtime_lint_build_dir}}" "-DIMPERIALISM_RUNTIME_TESTS=ON"

[private]
[doc('Reject UI/control-tree mechanics, coordinate input, and polling in native runtime scenarios')]
[group('gates')]
runtime-source-policy-gate:
  uv run python -m tools.runtime.source_policy tests/runtime/native

[doc('Create a new native runtime test: source skeleton plus its catalog entry')]
[group('runtime-test')]
runtime-new name base='easy-map' *args:
  uv run python -m tools.runtime.scaffold "{{name}}" --base "{{base}}" {{args}}

[private]
[group('runtime-test')]
runtime-test-list:
  uv run python -m tools.runtime.cli list

[doc('Run one native runtime test against the existing executable, with no build at all')]
[group('runtime-test')]
runtime-run name *args:
  uv run python -m tools.runtime.cli run "{{name}}" {{args}}

[doc('Run one named native semantic runtime test (rebuilds first)')]
[group('runtime-test')]
runtime-test name *args:
  just runtime-test-build
  uv run python -m tools.runtime.cli run "{{name}}" {{args}}

[doc('Run a catalog runtime suite (pr or full); rebuilds first')]
[group('runtime-test')]
runtime-test-suite suite='pr' *args:
  just runtime-test-build
  uv run python -m tools.runtime.cli suite "{{suite}}" {{args}}

[private]
[group('runtime-test')]
runtime-test-determinism suite='full' *args:
  just runtime-test-build
  uv run python -m tools.runtime.cli determinism "{{suite}}" {{args}}

[private]
[group('runtime-test')]
runtime-test-nightly:
  just runtime-test-determinism full --gdb --require-fixtures

[private]
[group('runtime-test')]
runtime-check suite='pr' *args:
  : "${ORIGINAL_BINARY:?Set ORIGINAL_BINARY to your legally obtained Imperialism.exe}"
  test -f "$ORIGINAL_BINARY"
  just runtime-test-build
  uv run python -m tools.runtime.cli suite "{{suite}}" --require-fixtures {{args}}

[private]
[group('runtime-test')]
runtime-prune *args:
  uv run python -m tools.runtime.cli prune {{args}}

[private]
[group('runtime-test')]
runtime-clean:
  uv run python -m tools.runtime.cli clean

[private]
[group('runtime-test')]
runtime-test-show name:
  uv run python -m tools.runtime.cli show "{{name}}"

# Read a screen's real tag hierarchy instead of guessing it from a UI builder or compiling a
# selector to see whether RequireControl rejects it. The live tree is recorded on a
# non-passing run and under --hold; --snapshots renders the recorded snapshots instead.
[doc('Print the UI tree a runtime test last saw, with each node event/actionable state and selector path')]
[group('runtime-test')]
runtime-tree name *args:
  uv run python -m tools.runtime.tree "{{name}}" {{args}}
