add_library(openiec61850)
add_library(openiec61850::openiec61850 ALIAS openiec61850)

target_include_directories(openiec61850 PUBLIC
  $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>)
target_compile_features(openiec61850 PUBLIC cxx_std_20)
target_link_libraries(openiec61850 PUBLIC asio::asio PRIVATE pugixml::pugixml)
target_compile_definitions(openiec61850 PUBLIC ASIO_NO_DEPRECATED)
if(OPENIEC61850_ENABLE_TLS)
  target_link_libraries(openiec61850 PUBLIC OpenSSL::SSL OpenSSL::Crypto)
  target_compile_definitions(openiec61850 PUBLIC OPENIEC61850_WITH_TLS=1)
endif()
openiec61850_set_warnings(openiec61850)

# Each component adds its sources to the openiec61850 target from its own CMakeLists.txt.
add_subdirectory(core)
add_subdirectory(ber)
add_subdirectory(iso)
add_subdirectory(mms)
add_subdirectory(transport)
add_subdirectory(association)
add_subdirectory(model)
add_subdirectory(client)
add_subdirectory(server)
add_subdirectory(scl)
add_subdirectory(goose)

# Shared builds (BUILD_SHARED_LIBS=ON) rely on default symbol visibility, so they are supported on
# ELF and Mach-O only; Windows has no export macros (yet) and stays static.
if(BUILD_SHARED_LIBS AND WIN32)
  message(FATAL_ERROR "openiec61850: BUILD_SHARED_LIBS is not supported on Windows, build it static")
endif()
set_target_properties(openiec61850 PROPERTIES
  VERSION ${PROJECT_VERSION}
  SOVERSION ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}
  EXPORT_NAME openiec61850)

# Install tree: headers, the library and a relocatable CMake package exporting
# openiec61850::openiec61850 (find_package(openiec61850 CONFIG)).
if(OPENIEC61850_INSTALL)
  include(GNUInstallDirs)
  include(CMakePackageConfigHelpers)
  set(_cmake_dir ${CMAKE_INSTALL_LIBDIR}/cmake/openiec61850)

  install(TARGETS openiec61850 EXPORT openiec61850Targets
          ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
          LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
          RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
          INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
  install(DIRECTORY ${PROJECT_SOURCE_DIR}/include/openiec61850
          DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
          FILES_MATCHING PATTERN "*.hpp")
  install(EXPORT openiec61850Targets
          NAMESPACE openiec61850::
          DESTINATION ${_cmake_dir})

  configure_package_config_file(${PROJECT_SOURCE_DIR}/cmake/openiec61850Config.cmake.in
    ${PROJECT_BINARY_DIR}/openiec61850Config.cmake
    INSTALL_DESTINATION ${_cmake_dir})
  # 0.x: minor versions may break the API, so a 0.1 request does not accept 0.2.
  write_basic_package_version_file(${PROJECT_BINARY_DIR}/openiec61850ConfigVersion.cmake
    COMPATIBILITY SameMinorVersion)
  install(FILES ${PROJECT_BINARY_DIR}/openiec61850Config.cmake
                ${PROJECT_BINARY_DIR}/openiec61850ConfigVersion.cmake
          DESTINATION ${_cmake_dir})
endif()

# Install-tree check: tests/package consumes the installed package from a fresh prefix.
if(OPENIEC61850_INSTALL AND OPENIEC61850_BUILD_TESTS AND NOT CMAKE_CROSSCOMPILING)
  enable_testing()  # the top level enables testing only after this directory
  set(_prefix_path "${CMAKE_PREFIX_PATH}")
  if(DEFINED VCPKG_INSTALLED_DIR AND DEFINED VCPKG_TARGET_TRIPLET)
    list(APPEND _prefix_path "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}")
  endif()
  set(_cxx_flags "")
  if(OPENIEC61850_SANITIZERS AND NOT MSVC)
    list(JOIN OPENIEC61850_SANITIZERS "," _sanitizers)
    set(_cxx_flags "-fsanitize=${_sanitizers}")
  endif()
  string(REPLACE ";" "\;" _prefix_path "${_prefix_path}")
  add_test(NAME package.consumer
           COMMAND ${CMAKE_COMMAND}
                   -DBUILD_DIR=${PROJECT_BINARY_DIR}
                   -DWORK_DIR=${PROJECT_BINARY_DIR}/package-test
                   -DSOURCE_DIR=${PROJECT_SOURCE_DIR}
                   -DPREFIX_PATH=${_prefix_path}
                   -DCXX_COMPILER=${CMAKE_CXX_COMPILER}
                   -DCXX_FLAGS=${_cxx_flags}
                   -DBUILD_TYPE=${CMAKE_BUILD_TYPE}
                   -DGENERATOR=${CMAKE_GENERATOR}
                   -DVERSION=${PROJECT_VERSION}
                   -DMODEL=${PROJECT_SOURCE_DIR}/interop/server/simpleIO.icd
                   -P ${PROJECT_SOURCE_DIR}/tests/package/run.cmake)
  set_tests_properties(package.consumer PROPERTIES TIMEOUT 600 LABELS package)
endif()
