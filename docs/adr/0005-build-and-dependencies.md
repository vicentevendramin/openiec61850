# Build and dependencies: CMake, vcpkg, standalone Asio and OpenSSL 3

The build uses CMake with scikit-build-core and produces wheels with cibuildwheel. Dependencies come from vcpkg in manifest mode. Asynchronous I/O uses standalone Asio (epoll/IOCP) and TLS (IEC 62351) uses OpenSSL 3. A custom reactor was rejected for now and only returns to the table if the reference benchmark points to Asio as a bottleneck. mbedTLS was also rejected, because the target platform is desktop and server, not memory-constrained embedded systems.
