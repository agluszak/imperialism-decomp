# CMake cross toolchain for the lint-only build: clang targeting
# i686-w64-mingw32 (MinGW-w64 sysroot). NOT used for reccmp matching.
#
# MinGW-w64 supplies <windows.h>, gdi32/user32 and all MSVC calling
# conventions, while clang at C++14 activates the real `override` /
# `static_assert` that MSVC 5.0 silently ignores.

set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86)

set(_target i686-w64-mingw32)

set(CMAKE_C_COMPILER clang)
set(CMAKE_CXX_COMPILER clang++)
set(CMAKE_C_COMPILER_TARGET ${_target})
set(CMAKE_CXX_COMPILER_TARGET ${_target})

# Use the Debian mingw-w64 sysroot for headers/libs.
set(CMAKE_FIND_ROOT_PATH /usr/${_target})
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# Modern dialect so real `override` / `static_assert` kick in.
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Phase 1 is compile-only (no link): the autogen stubs do not provide a
# complete link surface yet, and we only need clang's front-end diagnostics.
set(IMPERIALISM_LINT_COMPILE_ONLY ON CACHE BOOL "Lint build: compile, do not link")

# Don't try to link during the compiler sanity check (no full link surface).
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
