find_package(Python 3.10 COMPONENTS Interpreter Development.Module REQUIRED)

execute_process(
  COMMAND "${Python_EXECUTABLE}" -m nanobind --cmake_dir
  OUTPUT_STRIP_TRAILING_WHITESPACE OUTPUT_VARIABLE nanobind_ROOT)
find_package(nanobind CONFIG REQUIRED)

# Test-only extension exposing the C++ fake server (tests/client/fake_server.*) to the Python
# tests. Never enable it for release wheels.
option(OPENIEC61850_BUILD_PYTHON_TESTING "Build the test-only openiec61850._testing module" OFF)

set(_binding_common src/convert.cpp src/runtime.cpp)

nanobind_add_module(_core NB_STATIC LTO NB_SUPPRESS_WARNINGS
  src/module.cpp
  src/client_binding.cpp
  src/model_binding.cpp
  src/server_binding.cpp
  ${_binding_common})
target_link_libraries(_core PRIVATE openiec61850::openiec61850)
openiec61850_set_warnings(_core)

install(TARGETS _core LIBRARY DESTINATION openiec61850)

if(OPENIEC61850_BUILD_PYTHON_TESTING)
  nanobind_add_module(_testing NB_STATIC NB_SUPPRESS_WARNINGS
    src/testing_module.cpp
    ${_binding_common}
    ${PROJECT_SOURCE_DIR}/tests/client/fake_server.cpp)
  target_include_directories(_testing PRIVATE ${PROJECT_SOURCE_DIR}/tests/client src)
  target_link_libraries(_testing PRIVATE openiec61850::openiec61850)
  openiec61850_set_warnings(_testing)
  install(TARGETS _testing LIBRARY DESTINATION openiec61850)
endif()
