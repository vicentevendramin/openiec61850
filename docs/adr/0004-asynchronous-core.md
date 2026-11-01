# Asynchronous core with a synchronous facade

The Client runs on an asynchronous core with its own I/O thread that never holds the GIL. In Python, the `asyncio` API is the first-class one and there is a thin synchronous wrapper on top of it. Reports arrive as an async iterator, with an optional callback. We rejected the blocking-only model with callback threads, in the style of libiec61850, because it does not scale to many associations and many parallel requests within one association.
