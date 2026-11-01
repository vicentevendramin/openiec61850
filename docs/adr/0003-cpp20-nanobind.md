# C++20 core with nanobind bindings

The core is written in C++20 and exposed to Python with nanobind, which has less per-call overhead and smaller binaries than pybind11.

## Considered options

- **Rust + PyO3**: memory safety in the network parser and simpler packaging. It lost to the team's familiarity with C++ and to the automation ecosystem, which is mostly C/C++.
- **Go**: rejected as a Python extension. We would have two runtimes in one process (Go scheduler + GIL), only one Go runtime per process, and expensive Go-to-Python callbacks full of cgo restrictions.

## Consequences

Since memory safety does not come from the compiler, the BER/MMS decoder needs continuous fuzzing and sanitizers (ASan/UBSan) in CI from day one.
