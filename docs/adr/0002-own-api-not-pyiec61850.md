# Own API instead of compatibility with pyiec61850

"100% compatibility" was defined as binding parity: the whole native API exists in Python. It is not compatibility with the libiec61850 C API or with pyiec61850. Imitating the opaque handles and output error parameters of the C API would tie the core to a design that limits performance and is not very Pythonic. Legacy code to migrate, if any, will be served by a separate and optional pyiec61850 compatibility layer.
