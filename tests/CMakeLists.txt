find_package(Catch2 3 CONFIG REQUIRED)
include(Catch)

add_executable(openiec61850_tests)
target_link_libraries(openiec61850_tests PRIVATE openiec61850::openiec61850 Catch2::Catch2WithMain)
openiec61850_set_warnings(openiec61850_tests)

# Each component adds its tests to the openiec61850_tests target from its own CMakeLists.txt.
add_subdirectory(core)
add_subdirectory(ber)
add_subdirectory(iso)

catch_discover_tests(openiec61850_tests)
