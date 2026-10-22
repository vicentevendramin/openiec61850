add_library(openiec61850)
add_library(openiec61850::openiec61850 ALIAS openiec61850)

target_include_directories(openiec61850 PUBLIC
  $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>)
target_compile_features(openiec61850 PUBLIC cxx_std_20)
target_link_libraries(openiec61850 PUBLIC asio::asio)
target_compile_definitions(openiec61850 PUBLIC ASIO_NO_DEPRECATED)
if(OPENIEC61850_ENABLE_TLS)
  target_link_libraries(openiec61850 PUBLIC OpenSSL::SSL OpenSSL::Crypto)
  target_compile_definitions(openiec61850 PUBLIC OPENIEC61850_WITH_TLS=1)
endif()
openiec61850_set_warnings(openiec61850)

# Each component adds its sources to the openiec61850 target from its own CMakeLists.txt.
add_subdirectory(core)
add_subdirectory(ber)
