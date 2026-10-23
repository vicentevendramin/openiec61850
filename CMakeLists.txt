cmake_minimum_required(VERSION 3.25)

# Use vcpkg in manifest mode automatically when VCPKG_ROOT is set.
if(NOT DEFINED CMAKE_TOOLCHAIN_FILE AND DEFINED ENV{VCPKG_ROOT})
  set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake" CACHE STRING "")
endif()

option(OPENIEC61850_BUILD_TESTS "Build the C++ tests" ON)
option(OPENIEC61850_BUILD_PYTHON "Build the Python module (nanobind)" OFF)
option(OPENIEC61850_BUILD_FUZZERS "Build the fuzzing targets (requires clang)" OFF)
option(OPENIEC61850_ENABLE_TLS "Enable TLS (IEC 62351) via OpenSSL 3" OFF)
option(OPENIEC61850_WARNINGS_AS_ERRORS "Treat warnings as errors" OFF)
set(OPENIEC61850_SANITIZERS "" CACHE STRING "Semicolon-separated list of sanitizers (e.g. address;undefined)")

if(OPENIEC61850_BUILD_TESTS)
  list(APPEND VCPKG_MANIFEST_FEATURES "tests")
endif()
if(OPENIEC61850_ENABLE_TLS)
  list(APPEND VCPKG_MANIFEST_FEATURES "tls")
endif()

project(openiec61850 VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(CompilerWarnings)
include(Sanitizers)

find_package(asio CONFIG REQUIRED)
find_package(pugixml CONFIG REQUIRED)
if(OPENIEC61850_ENABLE_TLS)
  find_package(OpenSSL 3 REQUIRED)
endif()

add_subdirectory(src)

if(OPENIEC61850_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

if(OPENIEC61850_BUILD_PYTHON)
  add_subdirectory(python)
endif()

if(OPENIEC61850_BUILD_FUZZERS)
  add_subdirectory(fuzz)
endif()
