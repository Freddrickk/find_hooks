cmake_minimum_required(VERSION 3.02)
project("find_hooks")

# To avoid this error:
# fatal error C1083: Cannot open include file: 'compiler_support.h': No such file or directory
set(CMAKE_INCLUDE_CURRENT_DIR ON)

add_library("find_hooks" SHARED "src/main.cpp")

set_property(TARGET "find_hooks" PROPERTY CXX_STANDARD           17)
set_property(TARGET "find_hooks" PROPERTY CXX_STANDARD_REQUIRED  ON)

add_subdirectory("external/LIEF" EXCLUDE_FROM_ALL)

target_link_libraries("find_hooks" PUBLIC "LIB_LIEF")
