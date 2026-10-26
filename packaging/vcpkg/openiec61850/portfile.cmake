# Overlay port that builds the checkout this file lives in:
#   vcpkg install openiec61850 --overlay-ports=<repo>/packaging/vcpkg
# A port for the vcpkg registry would fetch a release tag instead:
#   vcpkg_from_github(OUT_SOURCE_PATH SOURCE_PATH REPO <owner>/openiec61850 REF "v${VERSION}"
#                     SHA512 <sha512 of the tag archive>)
get_filename_component(SOURCE_PATH "${CMAKE_CURRENT_LIST_DIR}/../../.." ABSOLUTE)

# No export macros: shared builds work on ELF/Mach-O only, Windows is static.
if(VCPKG_TARGET_IS_WINDOWS)
  vcpkg_check_linkage(ONLY_STATIC_LIBRARY)
endif()

vcpkg_check_features(OUT_FEATURE_OPTIONS FEATURE_OPTIONS
  FEATURES
    tls   OPENIEC61850_ENABLE_TLS
    tools OPENIEC61850_BUILD_TOOLS)

vcpkg_cmake_configure(
  SOURCE_PATH "${SOURCE_PATH}"
  OPTIONS
    ${FEATURE_OPTIONS}
    -DOPENIEC61850_BUILD_TESTS=OFF
    -DOPENIEC61850_BUILD_PYTHON=OFF
    -DOPENIEC61850_INSTALL=ON
    -DVCPKG_MANIFEST_MODE=OFF)
vcpkg_cmake_install()
vcpkg_cmake_config_fixup(CONFIG_PATH lib/cmake/openiec61850)

if("tools" IN_LIST FEATURES)
  vcpkg_copy_tools(TOOL_NAMES openiec61850-server openiec61850-client AUTO_CLEAN)
endif()

file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/include" "${CURRENT_PACKAGES_DIR}/debug/share")
file(INSTALL "${CMAKE_CURRENT_LIST_DIR}/usage" DESTINATION "${CURRENT_PACKAGES_DIR}/share/${PORT}")
vcpkg_install_copyright(FILE_LIST "${SOURCE_PATH}/LICENSE" "${SOURCE_PATH}/NOTICE")
