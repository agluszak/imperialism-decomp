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
  just runtime-source-policy-gate
  uv run python -m tools.runtime.generate_native_registry \
    --output "{{lint_build_dir}}/generated/runtime/RuntimeRegistry.inc"
  just lint "-DIMPERIALISM_RUNTIME_TESTS=ON"

[doc('Reject coordinate input and polling synchronization in native runtime scenarios')]
[group('gates')]
runtime-source-policy-gate:
  uv run python -m tools.runtime.source_policy tests/runtime/native

# A hard ban: every scenario is a linear script, so there is no baseline and no count to bless.
# A hit means a scenario reached through the boundary instead of extending it -- put the mechanic
# in a screen, a flow or a probe.
[doc('Ban control-tree mechanics in runtime scenario bodies; --show lists any found')]
[group('gates')]
runtime-script-debt-gate *args:
  uv run python -m tools.runtime.script_debt {{args}}

[doc('Create a new native runtime test: source skeleton plus its catalog entry')]
[group('runtime-test')]
runtime-new name base='easy-map' *args:
  uv run python -m tools.runtime.scaffold "{{name}}" --base "{{base}}" {{args}}

[doc('Ask MSVC500 whether the switch/case __LINE__ script protothread compiles and resumes correctly; --run links and executes it')]
[group('runtime-test')]
protothread-probe *args:
  uv run python -m tools.workflow.protothread_probe \
    --work-dir "{{build_dir}}/protothread-probe" {{args}}

[doc('Ask MSVC500 which array-construction shape it emits (inline / call-loop / vector-ctor iterator); --sweep varies the optimization flags')]
[group('runtime-test')]
vector-ctor-probe *args:
  uv run python -m tools.workflow.vector_ctor_probe \
    --work-dir "{{build_dir}}/vector-ctor-probe" {{args}}

[doc('List registered native semantic runtime tests')]
[group('runtime-test')]
runtime-test-list:
  uv run python -m tools.runtime.cli list

# The three build depths for running one test. `runtime-test` is canonical and gated;
# `runtime-dev` is the authoring inner loop; `runtime-run` re-runs what is already built.
# Only `runtime-test` belongs in precommit -- the inner loop deliberately does not pay for
# the vtable gate or unrelated source generation.

[doc('Run one native runtime test against the existing executable, with no build at all')]
[group('runtime-test')]
runtime-run name *args:
  uv run python -m tools.runtime.cli run "{{name}}" {{args}}

[doc('Recompile only what changed, then run one native runtime test (skips the vtable gate and unrelated generation)')]
[group('runtime-test')]
runtime-dev name *args:
  uv run python -m tools.runtime.incremental_build --build-dir "{{runtime_test_build_dir}}" --docker-image "{{docker_image}}"
  uv run python -m tools.runtime.cli run "{{name}}" {{args}}

[doc('Recompile only what changed in the runtime-test build, without running a test')]
[group('runtime-test')]
runtime-dev-build:
  uv run python -m tools.runtime.incremental_build --build-dir "{{runtime_test_build_dir}}" --docker-image "{{docker_image}}"

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

# Drop old run bundles (each stages its own read-only game/ sandbox, so hand-deleting
# one needs a chmod first). Keeps the newest per test name; --keep 0 removes them all.
[doc('Prune old runtime run bundles, keeping the newest per test')]
[group('runtime-test')]
runtime-prune *args:
  uv run python -m tools.runtime.cli prune {{args}}

[doc('Stop this worktree warm wineserver and Xvfb; drop the Wine prefix')]
[group('runtime-test')]
runtime-clean:
  uv run python -m tools.runtime.cli clean

[doc('Show the latest canonical result for a runtime test')]
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
