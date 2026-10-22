# Contributing

## Clean-room rule (ADR 0001)

openiec61850 is implemented **only** from the text of the standards (IEC 61850, ISO 9506/MMS, ISO 8072/8073, ISO 8326/8327, ISO 8822/8823, ISO 8649/8650, ITU-T X.690 and RFC 1006).

- Do not read, copy, port or "translate" code from libiec61850 or pyiec61850.
- Running libiec61850 binaries as a test peer and in benchmarks is allowed.
- When referring to a standard in comments, cite the clause (e.g. `// ISO 8327-1 §8.3.1`).

## Environment

Requirements: a C++20 compiler (GCC 13+, Clang 17+ or MSVC 19.38+), CMake 3.25+, Ninja, and vcpkg with `VCPKG_ROOT` set.

```bash
cmake --preset dev && cmake --build --preset dev && ctest --preset dev
cmake --preset asan && cmake --build --preset asan && ctest --preset asan
pip install -e ".[test]" && pytest
```

## Layout

Each component (`ber`, `iso`, `mms`...) has:

- `include/openiec61850/<component>/`: public headers;
- `src/<component>/CMakeLists.txt`: adds sources to the `openiec61850` target;
- `tests/<component>/CMakeLists.txt`: adds tests to the `openiec61850_tests` target;
- `fuzz/<component>/`: fuzzers for every decoder that handles network input (ADR 0003).

Decoders never trust lengths received from the network: every access is bounds-checked against the buffer, and errors are returned as `openiec61850::result<T>`, with no exceptions on the parsing path.
