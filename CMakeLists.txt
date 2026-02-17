cmake_minimum_required(VERSION 3.20)

project(imperialism_decomp LANGUAGES C CXX)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(Imperialism
    src/main.cpp
)

if(WIN32)
    set_target_properties(Imperialism PROPERTIES WIN32_EXECUTABLE YES)
endif()

target_include_directories(Imperialism PRIVATE include)
target_compile_definitions(Imperialism PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)

if(MSVC)
    target_compile_options(Imperialism PRIVATE /W4 /wd4100 /wd4201)
else()
    target_compile_options(Imperialism PRIVATE -Wall -Wextra -Wpedantic)
endif()
