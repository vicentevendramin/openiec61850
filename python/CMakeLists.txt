find_package(Python 3.10 COMPONENTS Interpreter Development.Module REQUIRED)

execute_process(
  COMMAND "${Python_EXECUTABLE}" -m nanobind --cmake_dir
  OUTPUT_STRIP_TRAILING_WHITESPACE OUTPUT_VARIABLE nanobind_ROOT)
find_package(nanobind CONFIG REQUIRED)

nanobind_add_module(_core NB_STATIC LTO
  src/module.cpp)
target_link_libraries(_core PRIVATE openiec61850::openiec61850)

install(TARGETS _core LIBRARY DESTINATION openiec61850)
