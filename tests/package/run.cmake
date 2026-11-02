# cmake -P run.cmake: installs a configured openiec61850 build tree into a fresh prefix, then
# configures, builds and runs the consumer project against it.
# Inputs: BUILD_DIR, WORK_DIR, SOURCE_DIR, PREFIX_PATH (dependency prefixes), CXX_COMPILER,
# CXX_FLAGS, BUILD_TYPE, GENERATOR, VERSION, MODEL.
foreach(var BUILD_DIR WORK_DIR SOURCE_DIR VERSION MODEL GENERATOR)
  if(NOT DEFINED ${var})
    message(FATAL_ERROR "run.cmake: ${var} is not set")
  endif()
endforeach()

function(run)
  execute_process(COMMAND ${ARGN} RESULT_VARIABLE rc)
  if(NOT rc EQUAL 0)
    message(FATAL_ERROR "failed (${rc}): ${ARGN}")
  endif()
endfunction()

file(REMOVE_RECURSE "${WORK_DIR}")
set(prefix "${WORK_DIR}/prefix")
run("${CMAKE_COMMAND}" --install "${BUILD_DIR}" --prefix "${prefix}")

# Only the package files may be needed: no source or build tree paths in the exported targets.
file(GLOB_RECURSE exported "${prefix}/*.cmake")
foreach(f IN LISTS exported)
  file(READ "${f}" text)
  string(FIND "${text}" "${SOURCE_DIR}" hit)
  if(NOT hit EQUAL -1)
    message(FATAL_ERROR "${f} references the source tree")
  endif()
endforeach()

# Through the environment: a ;-list does not survive as one execute_process argument.
set(prefixes "${prefix}" ${PREFIX_PATH})
if(NOT CMAKE_HOST_WIN32)
  string(REPLACE ";" ":" prefixes "${prefixes}")
endif()
set(ENV{CMAKE_PREFIX_PATH} "${prefixes}")
run("${CMAKE_COMMAND}" -S "${SOURCE_DIR}/tests/package" -B "${WORK_DIR}/build" -G "${GENERATOR}"
    "-DCMAKE_CXX_COMPILER=${CXX_COMPILER}"
    "-DCMAKE_CXX_FLAGS=${CXX_FLAGS}"
    "-DCMAKE_BUILD_TYPE=${BUILD_TYPE}"
    "-DEXPECTED_VERSION=${VERSION}")
run("${CMAKE_COMMAND}" --build "${WORK_DIR}/build")
run("${WORK_DIR}/build/consumer" "${VERSION}" "${MODEL}")
