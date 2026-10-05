cmake_minimum_required(VERSION 3.20)
project(imperialism_clang_tidy_plugin LANGUAGES C CXX)

find_package(LLVM REQUIRED CONFIG)
find_package(Clang REQUIRED CONFIG)

add_definitions(${LLVM_DEFINITIONS})
add_library(imperialism-clang-tidy MODULE
    ScalarFacts.cpp
    BoolLikeByteCheck.cpp
    RedundantScalarCastCheck.cpp
)
target_compile_features(imperialism-clang-tidy PRIVATE cxx_std_17)
target_include_directories(imperialism-clang-tidy SYSTEM PRIVATE ${LLVM_INCLUDE_DIRS} ${CLANG_INCLUDE_DIRS})
target_link_libraries(imperialism-clang-tidy PRIVATE clangASTMatchers clangTidy)
set_target_properties(imperialism-clang-tidy PROPERTIES PREFIX "")

install(TARGETS imperialism-clang-tidy LIBRARY DESTINATION lib)
