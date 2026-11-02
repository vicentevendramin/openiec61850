# Consumer of an installed openiec61850 (tests the CMake package, not the library): configured
# against an install prefix by tests/package/run.cmake (CTest "package.consumer").
cmake_minimum_required(VERSION 3.25)
project(openiec61850_consumer LANGUAGES CXX)

find_package(openiec61850 ${EXPECTED_VERSION} CONFIG REQUIRED)

add_executable(consumer main.cpp)
target_link_libraries(consumer PRIVATE openiec61850::openiec61850)
