if(UNIX AND NOT APPLE)  # samples /proc
  target_sources(openiec61850_tests PRIVATE test_soak.cpp)
endif()
