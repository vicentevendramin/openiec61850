# Build e dependências: CMake, vcpkg, Asio standalone e OpenSSL 3

O build usa CMake com scikit-build-core e gera as wheels com cibuildwheel. As dependências vêm do vcpkg em manifest mode. O I/O assíncrono usa Asio standalone (epoll/IOCP) e o TLS (IEC 62351) usa OpenSSL 3. Um reactor próprio foi rejeitado por enquanto e só volta à mesa se o benchmark de referência apontar o Asio como gargalo. O mbedTLS também foi rejeitado, porque a plataforma-alvo é desktop e servidor, não embarcado com restrição de memória.
