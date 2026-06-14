cmake_minimum_required(VERSION 3.20)

project(imperialism LANGUAGES CXX)

set(
    IMPERIALISM_MATCH_FLAGS_CSV
    ""
    CACHE STRING
    "Comma-separated extra MSVC compile flags for RelWithDebInfo matching experiments"
)
set(
    IMPERIALISM_MATCH_LINK_FLAGS_CSV
    ""
    CACHE STRING
    "Comma-separated extra MSVC linker flags for RelWithDebInfo matching experiments"
)

file(GLOB IMPERIALISM_GAME_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/game/*.cpp"
)

# Lint-only builds (clang/MinGW, see cmake/clang-mingw-i686.cmake) compile the
# sources for diagnostics without linking, since the autogen stubs do not yet
# provide a complete link surface. Default OFF so the MSVC500 reccmp build is
# unaffected and still produces a real executable.
option(IMPERIALISM_LINT_COMPILE_ONLY "Compile sources only; do not link an executable" OFF)

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

file(
    GLOB IMPERIALISM_AUTOGEN_STUB_SOURCES
    CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/autogen/stubs/*.cpp"
)
if(IMPERIALISM_AUTOGEN_STUB_SOURCES)
    target_sources(Imperialism PRIVATE ${IMPERIALISM_AUTOGEN_STUB_SOURCES})
endif()

if(WIN32 AND NOT IMPERIALISM_LINT_COMPILE_ONLY)
    set_target_properties(Imperialism PROPERTIES WIN32_EXECUTABLE YES)
    target_link_libraries(Imperialism PRIVATE gdi32 user32)
endif()

target_include_directories(Imperialism PRIVATE include)
target_compile_definitions(Imperialism PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)

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

    if(IMPERIALISM_MATCH_FLAGS_CSV)
        set(IMPERIALISM_MATCH_FLAGS_RAW "${IMPERIALISM_MATCH_FLAGS_CSV}")
        if(IMPERIALISM_MATCH_FLAGS_RAW MATCHES ",")
            string(REPLACE "," ";" IMPERIALISM_MATCH_FLAGS "${IMPERIALISM_MATCH_FLAGS_RAW}")
        else()
            # Backward-compat with slash-concatenated form like "/Oy-/Ob1".
            string(REGEX REPLACE "(/[^/]+)" ";\\1" IMPERIALISM_MATCH_FLAGS "${IMPERIALISM_MATCH_FLAGS_RAW}")
            string(REGEX REPLACE "^;" "" IMPERIALISM_MATCH_FLAGS "${IMPERIALISM_MATCH_FLAGS}")
        endif()
        target_compile_options(
            Imperialism
            PRIVATE
            $<$<CONFIG:RelWithDebInfo>:${IMPERIALISM_MATCH_FLAGS}>
        )
    endif()

    if(IMPERIALISM_MATCH_LINK_FLAGS_CSV)
        set(IMPERIALISM_MATCH_LINK_FLAGS_RAW "${IMPERIALISM_MATCH_LINK_FLAGS_CSV}")
        if(IMPERIALISM_MATCH_LINK_FLAGS_RAW MATCHES ",")
            string(REPLACE "," ";" IMPERIALISM_MATCH_LINK_FLAGS "${IMPERIALISM_MATCH_LINK_FLAGS_RAW}")
        else()
            string(REGEX REPLACE "(/[^/]+)" ";\\1" IMPERIALISM_MATCH_LINK_FLAGS "${IMPERIALISM_MATCH_LINK_FLAGS_RAW}")
            string(REGEX REPLACE "^;" "" IMPERIALISM_MATCH_LINK_FLAGS "${IMPERIALISM_MATCH_LINK_FLAGS}")
        endif()
        target_link_options(
            Imperialism
            PRIVATE
            $<$<CONFIG:RelWithDebInfo>:${IMPERIALISM_MATCH_LINK_FLAGS}>
        )
    endif()
elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    # Lint-only modern compiler (clang/MinGW). Never used for reccmp; its job is
    # to surface errors MSVC 5.0 silently accepts (missing `override`, narrowing,
    # bad vtable signatures). The C++ standard comes from the toolchain file
    # (C++14) so real `override`/`static_assert` activate.
    option(IMPERIALISM_LINT_WERROR "Lint build: treat warnings as errors" OFF)

    target_compile_options(Imperialism PRIVATE
        # Tolerate residual MSVC-isms and old-MSVC pragmas in the sources.
        # NB: do NOT add -fms-compatibility — it makes clang define _MSC_VER,
        # which sends the MinGW system headers (windows.h) down an unsupported
        # MSVC code path (VARARGS / __buildmemorybarrier errors).
        -fms-extensions
        -Wno-unknown-pragmas
        -Wno-ignored-pragmas
        # Core diagnostics.
        -Wall
        -Wextra
        # High-value vtable checks — the reason for this second compiler.
        -Winconsistent-missing-override
        -Woverloaded-virtual
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
    )

    if(IMPERIALISM_LINT_WERROR)
        target_compile_options(Imperialism PRIVATE -Werror)
    endif()
else()
    target_compile_options(Imperialism PRIVATE -Wall -Wextra -Wpedantic)
endif()
