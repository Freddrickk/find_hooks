cmake_minimum_required(VERSION 3.02)
project(hook_scanner)

# To avoid this error:
# fatal error C1083: Cannot open include file: 'compiler_support.h': No such file or directory
set(CMAKE_INCLUDE_CURRENT_DIR ON)

file(GLOB_RECURSE SRC_CPP RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "src/*.cpp")
add_library(hook_scanner SHARED ${SRC_CPP} )
#add_executable(hook_scanner ${SRC_CPP})

set_property(TARGET hook_scanner PROPERTY CXX_STANDARD           17)
set_property(TARGET hook_scanner PROPERTY CXX_STANDARD_REQUIRED  ON)

target_include_directories(hook_scanner PRIVATE "src")

add_subdirectory("external/LIEF" EXCLUDE_FROM_ALL)

target_link_libraries(hook_scanner PUBLIC "LIB_LIEF")
