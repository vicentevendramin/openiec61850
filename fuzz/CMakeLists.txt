if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  message(FATAL_ERROR "The fuzzers require clang (libFuzzer)")
endif()

# Creates a libFuzzer target: openiec61850_add_fuzzer(fuzz_ber_decode ber/fuzz_ber_decode.cpp)
function(openiec61850_add_fuzzer name)
  add_executable(${name} ${ARGN})
  target_link_libraries(${name} PRIVATE openiec61850::openiec61850)
  target_compile_options(${name} PRIVATE -fsanitize=fuzzer)
  target_link_options(${name} PRIVATE -fsanitize=fuzzer)
endfunction()

# Each component registers its fuzzers and corpus from its own subdirectory.
