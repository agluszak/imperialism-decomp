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

add_executable(Imperialism
    src/main.cpp
    ${IMPERIALISM_GAME_SOURCES}
)

file(
    GLOB IMPERIALISM_AUTOGEN_STUB_SOURCES
    CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/autogen/stubs/*.cpp"
)
if(IMPERIALISM_AUTOGEN_STUB_SOURCES)
    target_sources(Imperialism PRIVATE ${IMPERIALISM_AUTOGEN_STUB_SOURCES})
endif()

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
else()
    target_compile_options(Imperialism PRIVATE -Wall -Wextra -Wpedantic)
endif()
