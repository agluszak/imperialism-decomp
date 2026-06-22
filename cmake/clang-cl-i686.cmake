# CMake cross toolchain for the lint-only build using clang-cl targeting MSVC.
#
# This uses LLVM clang-cl natively on Linux to compile targeting
# i686-pc-windows-msvc, using the actual MSVC and MFC headers located
# in the container.

set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86)

set(_target i686-pc-windows-msvc)

set(CMAKE_C_COMPILER clang-cl)
set(CMAKE_CXX_COMPILER clang-cl)
set(CMAKE_C_COMPILER_TARGET ${_target})
set(CMAKE_CXX_COMPILER_TARGET ${_target})

# Tell clang-cl where the real MSVC/MFC headers are.
set(MSVC_INCLUDE_DIRS
    "/root/.wine/drive_c/msvc/include"
    "/root/.wine/drive_c/msvc/mfc/include"
    "/root/.wine/drive_c/msvc/atl/include"
)

foreach(dir ${MSVC_INCLUDE_DIRS})
    add_compile_options($<$<COMPILE_LANGUAGE:C,CXX>:-imsvc${dir}>)
endforeach()

# Modern dialect so real `override` / `static_assert` kick in.
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Compile-only
set(IMPERIALISM_LINT_COMPILE_ONLY ON CACHE BOOL "Lint build: compile, do not link")
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
