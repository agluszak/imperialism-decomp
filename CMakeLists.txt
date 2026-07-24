cmake_minimum_required(VERSION 3.20)

project(imperialism LANGUAGES CXX)

# This single-config project has two static CMake-owned profiles. The default
# production profile is byte matching; enabling the test-only source boundary
# selects the debugger-friendly runtime profile. Build recipes never compose
# compiler or linker flags.
set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Imperialism build type" FORCE)

file(GLOB IMPERIALISM_GAME_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/game/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/game/*/*.cpp"
)

# Lint-only builds (clang/MinGW, see cmake/clang-mingw-i686.cmake) compile the
# sources for diagnostics without linking, since the autogen stubs do not yet
# provide a complete link surface. Default OFF so the MSVC500 reccmp build is
# unaffected and still produces a real executable.
option(IMPERIALISM_LINT_COMPILE_ONLY "Compile sources only; do not link an executable" OFF)
option(IMPERIALISM_RUNTIME_TESTS "Compile the native semantic runtime-test driver" OFF)

if(IMPERIALISM_LINT_COMPILE_ONLY)
    add_library(Imperialism OBJECT
        src/main.cpp
        ${IMPERIALISM_GAME_SOURCES}
    )
else()
    add_executable(Imperialism
        src/main.cpp
        ${IMPERIALISM_GAME_SOURCES}
    )
endif()

# Runtime-test instrumentation belongs to a separate build tree. Nothing under
# tests/runtime/native is part of the production source glob, and the compile
# definition below is absent from the byte-matching build.
if(IMPERIALISM_RUNTIME_TESTS)
    file(GLOB_RECURSE IMPERIALISM_RUNTIME_TEST_SOURCES CONFIGURE_DEPENDS
        tests/runtime/native/*.cpp)
    target_sources(Imperialism PRIVATE ${IMPERIALISM_RUNTIME_TEST_SOURCES})
    target_include_directories(Imperialism PRIVATE tests/runtime/native)
    target_compile_definitions(Imperialism PRIVATE IMPERIALISM_RUNTIME_TESTS=1)
endif()

# Generated build inputs (stubs) live in the build tree, not the source tree.
# `just build` / `just lint` regenerate them (tools.source_index + tools.stubgen)
# before invoking CMake, so every build compiles inputs derived from the current
# source markers — never a stale committed snapshot.
set(IMPERIALISM_GENERATED_DIR
    "${CMAKE_BINARY_DIR}/generated"
    CACHE PATH "Generated build inputs (stubs)")

file(GLOB IMPERIALISM_AUTOGEN_STUB_SOURCES CONFIGURE_DEPENDS
    "${IMPERIALISM_GENERATED_DIR}/stubs/*.cpp"
)
file(GLOB IMPERIALISM_AUTOGEN_UI_SOURCES CONFIGURE_DEPENDS
    "${IMPERIALISM_GENERATED_DIR}/ui/*.cpp"
)
if(IMPERIALISM_AUTOGEN_UI_SOURCES)
    target_sources(Imperialism PRIVATE ${IMPERIALISM_AUTOGEN_UI_SOURCES})
endif()
if(IMPERIALISM_AUTOGEN_STUB_SOURCES)
    target_sources(Imperialism PRIVATE ${IMPERIALISM_AUTOGEN_STUB_SOURCES})
elseif(NOT IMPERIALISM_LINT_COMPILE_ONLY)
    message(FATAL_ERROR
        "No generated stubs in ${IMPERIALISM_GENERATED_DIR}/stubs — run "
        "'just generate' (or 'just build', which runs it) so the link surface "
        "is complete.")
endif()

if(WIN32 AND NOT IMPERIALISM_LINT_COMPILE_ONLY)
    set_target_properties(Imperialism PROPERTIES WIN32_EXECUTABLE YES)
    # winmm: mmio* wave loaders (wave_helpers.cpp) and mci calls.
    # vfw32: MCIWnd* video window APIs (Video for Windows), shipped by the MSVC500
    # toolchain at C:\msvc\lib\vfw32.lib.
    # dsound: DirectSoundCreate (TSoundResourceManager DirectSound init), from the DX5
    # SDK import lib on LIB at C:\dxsdk\lib\dsound.lib.
    # dplayx: DirectPlayCreate/DirectPlayEnumerate (TWNetSessionManager DirectPlay
    # session open/enumerate), same DX5 SDK import-lib directory.
    # dxguid: IID_IDirectPlay2 (QueryInterface upgrade off the DirectPlayCreate result).
    target_link_libraries(Imperialism PRIVATE
        gdi32 user32 winmm vfw32 dsound dplayx dxguid)
endif()

if(MSVC AND NOT IMPERIALISM_LINT_COMPILE_ONLY)
    target_sources(Imperialism PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/resources/imperialism_game.rc"
    )
endif()

# Groundwork for the retail-MFC migration (see docs/worklog.md 2026-06-16 and
# tools/mfc/gen_library_annotations.py). When ON, link the statically-linked retail
# MFC (nafxcw.lib, byte-identical to the original) plus the Win32 import libs MFC
# needs; the toolchain's INCLUDE/LIB already point at C:\msvc\mfc\{include,lib}.
# nafxcw must precede the static CRT (libcmt) on the link line — verified to link a
# minimal exe. OFF until the hand-rolled MFC C* classes are swapped for <afx.h>.
option(IMPERIALISM_LINK_MFC "Link retail static MFC (nafxcw.lib) instead of hand-rolled MFC" ON)
if(IMPERIALISM_LINK_MFC AND MSVC AND NOT IMPERIALISM_LINT_COMPILE_ONLY)
    target_link_libraries(Imperialism PRIVATE
        nafxcw.lib
        advapi32 shell32 comctl32 comdlg32 winspool ole32 oleaut32 oledlg uuid)
endif()

target_include_directories(Imperialism PRIVATE include)
target_compile_definitions(Imperialism PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)

if(IMPERIALISM_LINT_COMPILE_ONLY)
    # Lint-only modern compiler (clang/MinGW or clang-cl). Never used for reccmp; its job is
    # to surface errors MSVC 5.0 silently accepts (missing `override`, narrowing,
    # bad vtable signatures).
    option(IMPERIALISM_LINT_WERROR "Lint build: treat warnings as errors" ON)
    option(IMPERIALISM_LINT_WARNING_GATE_TEST
           "Lint build: add an intentionally warning-producing regression fixture" OFF)

    target_compile_definitions(Imperialism PRIVATE IMPERIALISM_LINT)

    target_compile_options(Imperialism PRIVATE
        # Core diagnostics. NOTE: this compiler is clang-cl (see cmake/clang-cl-i686.cmake),
        # where bare "-Wall"/"-Wextra" are parsed as the MSVC /Wall/​/Wextra spelling — i.e.
        # "enable nearly every diagnostic clang has", not GNU clang's modest -Wall/-Wextra
        # default set. /W4 is the real clang-cl equivalent of a sane default level.
        /W4
        # Tolerate residual MSVC-isms and old-MSVC pragmas in the sources. These must
        # follow /W4: clang-cl processes warning flags in order, and /W4 otherwise
        # re-enables -Wunknown-pragmas.
        -fms-extensions
        -Wno-unknown-pragmas
        -Wno-ignored-pragmas
        # High-value vtable checks — the reason for this second compiler.
        -Werror=inconsistent-missing-override
        -Werror=suggest-override
        -Werror=suggest-destructor-override
        -Werror=non-virtual-dtor
        -Werror=overloaded-virtual
        # Decomp noise that is inherent and not actionable.
        -Wno-unused-parameter
        -Wno-unused-variable
        -Wno-unused-function
        -Wno-cast-function-type
        -Wno-cast-calling-convention
        -Wno-invalid-offsetof
        -Wno-tautological-undefined-compare
        -Wno-missing-braces
        -Wno-missing-field-initializers
        -Wno-unused-private-field
        -Wno-undefined-internal
        -Wno-deprecated-register
        -Wno-microsoft-explicit-constructor-call
        -Wno-array-bounds
        -Wno-switch
        -Wno-mismatched-tags
        # Explicitly disabled: not useful for MSVC500-matching decomp source.
        -Wno-unsafe-buffer-usage
        -Wno-c++98-compat
        -Wno-global-constructors
        -Wno-exit-time-destructors
    )

    if(IMPERIALISM_LINT_WERROR)
        target_compile_options(Imperialism PRIVATE -Werror)
    endif()
    if(IMPERIALISM_LINT_WARNING_GATE_TEST)
        target_sources(Imperialism PRIVATE tests/lint/intentional_warning.cpp)
    endif()
else()
    if(MSVC)
        # Keep runtime static to mirror old retail distribution patterns.
        set_property(
            TARGET Imperialism
            PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
        )

        # Baseline flags for old-MSVC bring-up.
        target_compile_options(Imperialism PRIVATE
            /W3
            /GX
            /GR-
        )
        target_link_options(Imperialism PRIVATE /INCREMENTAL:NO)

        # /Z7 instead of /Zi: VC5 predates /FS, so /Zi's shared vc50.pdb would be a
        # write race under the parallel (jom) build. /Z7 embeds the same C7 debug
        # info per-object; the linker still emits the Imperialism.pdb reccmp reads.
        # Code sections are unaffected (verified: reccmp stats identical).
        foreach(_imp_flags_var
            CMAKE_CXX_FLAGS_RELWITHDEBINFO
            CMAKE_CXX_FLAGS_DEBUG
        )
            string(REPLACE "/Zi" "/Z7" ${_imp_flags_var} "${${_imp_flags_var}}")
        endforeach()

        if(IMPERIALISM_RUNTIME_TESTS)
            # Runtime tests optimize for debugger fidelity rather than byte
            # matching. Apply this to every game frame so GDB can follow
            # conventional EBP chains.
            target_compile_options(Imperialism PRIVATE /Oy-)
            # VC5 PDBs predate the format understood by current LLVM tools.
            # Emit a linker map as the build-specific symbolization sidecar.
            target_link_options(Imperialism PRIVATE /MAP:Imperialism.map)
        else()
            # Production builds are always matching-oriented.
            target_compile_options(Imperialism PRIVATE /Oy /Ob1)
            target_link_options(Imperialism PRIVATE /OPT:NOREF /OPT:NOICF)
        endif()
    else()
        target_compile_options(Imperialism PRIVATE -Wall -Wextra -Wpedantic)
    endif()
endif()
