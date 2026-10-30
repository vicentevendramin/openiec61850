# Applied globally so that the core, tests and fuzzers share the same instrumentation.
if(OPENIEC61850_SANITIZERS)
  if(MSVC)
    if("address" IN_LIST OPENIEC61850_SANITIZERS)
      add_compile_options(/fsanitize=address)
    endif()
  else()
    list(JOIN OPENIEC61850_SANITIZERS "," _sanitizers)
    add_compile_options(-fsanitize=${_sanitizers} -fno-omit-frame-pointer -fno-sanitize-recover=all)
    add_link_options(-fsanitize=${_sanitizers})
  endif()
endif()

# Without this only the fuzz targets are instrumented and libFuzzer cannot see the library's edges.
if(OPENIEC61850_BUILD_FUZZERS)
  add_compile_options(-fsanitize=fuzzer-no-link)
  add_link_options(-fsanitize=fuzzer-no-link)
endif()
