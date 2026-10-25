# Standalone build of the interop runner: pulls the library in from the repository root, without
# its tests, so the interop image does not need Catch2 and the top-level build is not touched.
#
#   cmake -S interop/runner -B build/interop -G Ninja && cmake --build build/interop
cmake_minimum_required(VERSION 3.25)

# vcpkg manifest mode with the repository's vcpkg.json (same baseline and versions as the library).
set(OPENIEC61850_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../.." CACHE PATH "openiec61850 source tree")
if(NOT DEFINED CMAKE_TOOLCHAIN_FILE AND DEFINED ENV{VCPKG_ROOT})
  set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake" CACHE STRING "")
endif()
set(VCPKG_MANIFEST_DIR "${OPENIEC61850_ROOT}" CACHE PATH "")
set(OPENIEC61850_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(OPENIEC61850_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "" FORCE)
endif()

project(openiec61850_interop LANGUAGES CXX)

add_subdirectory(${OPENIEC61850_ROOT} openiec61850 EXCLUDE_FROM_ALL)

add_executable(openiec61850_interop interop_runner.cpp)
target_link_libraries(openiec61850_interop PRIVATE openiec61850::openiec61850)
openiec61850_set_warnings(openiec61850_interop)
install(TARGETS openiec61850_interop RUNTIME DESTINATION bin)
