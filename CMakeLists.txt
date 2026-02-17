cmake_minimum_required(VERSION 3.20)

project(imperialism LANGUAGES CXX)

add_executable(Imperialism
    src/main.cpp
    src/autogen/stubs.cpp
)

if(WIN32)
    set_target_properties(Imperialism PROPERTIES WIN32_EXECUTABLE YES)
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
        /EHsc-
        /GR-
    )
    target_link_options(Imperialism PRIVATE /INCREMENTAL:NO)
else()
    target_compile_options(Imperialism PRIVATE -Wall -Wextra -Wpedantic)
endif()
