configure_file(version.cpp.in ${CMAKE_CURRENT_BINARY_DIR}/version.cpp @ONLY)
target_sources(openiec61850 PRIVATE
  ${CMAKE_CURRENT_BINARY_DIR}/version.cpp
  error.cpp)
