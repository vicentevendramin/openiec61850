# openiec61850

A clean-room implementation of the IEC 61850 standard with a C++20 native core and a first-class Python API (`asyncio`), licensed under Apache-2.0.

> Status: early development. The API is not stable yet.

## Why

- **Permissive license**: Apache-2.0 and not derived from libiec61850 (GPLv3), so it can be used in closed-source products.
- **Binding parity**: every public feature of the native core is also available in Python.
- **Asynchronous**: the core runs its own I/O thread that never holds the GIL, and scales to many associations and many concurrent requests.

## Building

```bash
export VCPKG_ROOT=~/vcpkg
cmake --preset dev
cmake --build --preset dev
ctest --preset dev
```

Python:

```bash
pip install ".[test]"
pytest
```

## Documentation

- [Glossary](GLOSSARY.md)
- [Architecture decision records](docs/adr/)
- [Contributing](CONTRIBUTING.md)

## License

Apache License 2.0. See [LICENSE](LICENSE).
