# Google Benchmark suite (GLOSSARY "Benchmark de referência"). Built only with
# OPENIEC61850_BUILD_BENCHMARKS=ON (the `bench` preset); never part of the default build.
find_package(benchmark CONFIG REQUIRED)

add_executable(openiec61850_bench
  bench_codec.cpp
  bench_loopback.cpp
  # The client test fake server, compiled read-only from the test tree as the loopback peer.
  ${PROJECT_SOURCE_DIR}/tests/client/fake_server.cpp)
target_include_directories(openiec61850_bench PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${PROJECT_SOURCE_DIR}/tests/client)
target_link_libraries(openiec61850_bench PRIVATE
  openiec61850::openiec61850 benchmark::benchmark benchmark::benchmark_main)
openiec61850_set_warnings(openiec61850_bench)

# `cmake --build --preset bench --target bench-json` runs the whole suite and records
# build/bench/results/latest.json (Google Benchmark JSON, with the machine context).
add_custom_target(bench-json
  COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/results
  COMMAND $<TARGET_FILE:openiec61850_bench>
          --benchmark_repetitions=5 --benchmark_report_aggregates_only=true
          --benchmark_out_format=json
          --benchmark_out=${CMAKE_BINARY_DIR}/results/latest.json
  DEPENDS openiec61850_bench
  USES_TERMINAL
  COMMENT "Running openiec61850_bench -> ${CMAKE_BINARY_DIR}/results/latest.json")
