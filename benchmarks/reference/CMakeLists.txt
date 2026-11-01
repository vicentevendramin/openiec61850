# Reference benchmark (GLOSSARY): standalone Release build of openiec61850-server and of the
# load generator, so the default build is not touched. Driven by run.sh.
cmake_minimum_required(VERSION 3.25)

# vcpkg manifest mode with the repository's vcpkg.json (same baseline and versions as the library).
set(OPENIEC61850_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../.." CACHE PATH "openiec61850 source tree")
if(NOT DEFINED CMAKE_TOOLCHAIN_FILE AND DEFINED ENV{VCPKG_ROOT})
  set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake" CACHE STRING "")
endif()
set(VCPKG_MANIFEST_DIR "${OPENIEC61850_ROOT}" CACHE PATH "")
set(OPENIEC61850_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(OPENIEC61850_BUILD_TOOLS ON CACHE BOOL "" FORCE)

project(openiec61850_reference LANGUAGES CXX)

add_subdirectory(${OPENIEC61850_ROOT} openiec61850 EXCLUDE_FROM_ALL)

add_executable(openiec61850_ref_loadgen loadgen.cpp)
target_link_libraries(openiec61850_ref_loadgen PRIVATE openiec61850::openiec61850)
openiec61850_set_warnings(openiec61850_ref_loadgen)
add_custom_target(reference ALL DEPENDS openiec61850_ref_loadgen openiec61850_server_tool)
