# Instrumented semantic runtime tests. Runtime actions execute inside the game
# process on its UI thread; no external coordinate automation belongs here.

[doc('Build the native semantic runtime-test executable into build-runtime-tests/')]
[group('runtime-test')]
runtime-test-build:
  mkdir -p "{{runtime_test_build_dir}}"
  uv run python -m tools.workflow.msvc_build_lock \
    --lock "{{build_dir}}/.msvc-build.lock" -- just _build-runtime-tests-unlocked

[private]
_build-runtime-tests-unlocked:
  just vtable-gate
  uv run python -m tools.generate --gen-dir "{{runtime_test_build_dir}}/generated"
  uv run python -m tools.runtime.generate_native_registry \
    --output "{{runtime_test_build_dir}}/generated/runtime/RuntimeRegistry.inc"
  docker run --rm --network none \
    -e CMAKE_FLAGS="-DIMPERIALISM_RUNTIME_TESTS=ON" \
    -v "$PWD":/imperialism \
    -v "$PWD/{{runtime_test_build_dir}}":/build \
    "{{docker_image}}"

[doc('Compile and run the public-API CString lifetime probe with VC5/MFC 4.2')]
[group('runtime-test')]
cstring-runtime-probe:
  uv run python -m tools.workflow.cstring_runtime_probe \
    --work-dir "{{build_dir}}/cstring-runtime-probe"

[doc('Compile the native runtime harness with clang-cl diagnostics')]
[group('runtime-test')]
runtime-harness-lint:
  uv run python -m tools.runtime.generate_native_registry \
    --output "{{lint_build_dir}}/generated/runtime/RuntimeRegistry.inc"
  just lint "-DIMPERIALISM_RUNTIME_TESTS=ON"

[doc('Ask MSVC500 which array-construction shape it emits (inline / call-loop / vector-ctor iterator); --sweep varies the optimization flags')]
[group('runtime-test')]
vector-ctor-probe *args:
  uv run python -m tools.workflow.vector_ctor_probe \
    --work-dir "{{build_dir}}/vector-ctor-probe" {{args}}

[doc('List registered native semantic runtime tests')]
[group('runtime-test')]
runtime-test-list:
  uv run python -m tools.runtime.cli list

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

[doc('Run a suite twice, in reverse order, and optionally under GDB; compare normalized observations')]
[group('runtime-test')]
runtime-test-determinism suite='full' *args:
  just runtime-test-build
  uv run python -m tools.runtime.cli determinism "{{suite}}" {{args}}

[doc('Nightly runtime determinism run, including debugger-sensitivity comparison')]
[group('runtime-test')]
runtime-test-nightly:
  just runtime-test-determinism full --gdb --require-fixtures

[doc('Build and run a required runtime suite using local retail assets')]
[group('runtime-test')]
runtime-check suite='pr' *args:
  : "${ORIGINAL_BINARY:?Set ORIGINAL_BINARY to your legally obtained Imperialism.exe}"
  test -f "$ORIGINAL_BINARY"
  just runtime-test-build
  uv run python -m tools.runtime.cli suite "{{suite}}" --require-fixtures {{args}}

[doc('Stop this worktree warm wineserver and Xvfb; drop the Wine prefix')]
[group('runtime-test')]
runtime-clean:
  uv run python -m tools.runtime.cli clean

[doc('Show the latest canonical result for a runtime test')]
[group('runtime-test')]
runtime-test-show name:
  uv run python -m tools.runtime.cli show "{{name}}"
