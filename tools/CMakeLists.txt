# Command-line tools: openiec61850-server (serves an SCL model) and openiec61850-client (explores
# a server). Both are installed; OPENIEC61850_BUILD_TOOLS=OFF skips them (Python wheels).
add_library(openiec61850_tools_common STATIC common.cpp)
target_link_libraries(openiec61850_tools_common PUBLIC openiec61850::openiec61850)
openiec61850_set_warnings(openiec61850_tools_common)

add_executable(openiec61850_server_tool server_main.cpp)
add_executable(openiec61850_client_tool client_main.cpp)
set_target_properties(openiec61850_server_tool PROPERTIES OUTPUT_NAME openiec61850-server)
set_target_properties(openiec61850_client_tool PROPERTIES OUTPUT_NAME openiec61850-client)
foreach(tool openiec61850_server_tool openiec61850_client_tool)
  target_link_libraries(${tool} PRIVATE openiec61850_tools_common)
  openiec61850_set_warnings(${tool})
endforeach()

if(OPENIEC61850_INSTALL)
  include(GNUInstallDirs)
  install(TARGETS openiec61850_server_tool openiec61850_client_tool
          RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if(OPENIEC61850_BUILD_TESTS)
  find_program(OPENIEC61850_BASH bash)
  if(OPENIEC61850_BASH)
    add_test(NAME tools.smoke
             COMMAND ${OPENIEC61850_BASH} ${CMAKE_CURRENT_SOURCE_DIR}/smoke_test.sh
                     $<TARGET_FILE:openiec61850_server_tool> $<TARGET_FILE:openiec61850_client_tool>
                     ${PROJECT_SOURCE_DIR}/interop/server/simpleIO.icd)
    set_tests_properties(tools.smoke PROPERTIES TIMEOUT 30)
  endif()
endif()
