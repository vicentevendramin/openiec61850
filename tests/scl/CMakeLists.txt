target_sources(openiec61850_tests PRIVATE
  test_address.cpp
  test_btype.cpp
  test_diagnostics.cpp
  test_instance.cpp
  test_load.cpp)
target_compile_definitions(openiec61850_tests PRIVATE
  OPENIEC61850_SCL_TEST_DATA="${CMAKE_CURRENT_SOURCE_DIR}/data")
