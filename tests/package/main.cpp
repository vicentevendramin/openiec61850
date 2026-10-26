// Serves an SCL model and reads its server directory back over loopback, using only the installed
// headers and the exported openiec61850::openiec61850 target.
#include <cstdio>
#include <string>
#include <string_view>

#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/address_v4.hpp>

#include "openiec61850/client/client.hpp"
#include "openiec61850/core/version.hpp"
#include "openiec61850/server/scl_model.hpp"
#include "openiec61850/server/server.hpp"

namespace iec = openiec61850;

int main(int argc, char** argv) {
  if (argc != 3) {
    std::fprintf(stderr, "usage: consumer <expected-version> <model.icd>\n");
    return 2;
  }
  if (iec::version().string != std::string_view{argv[1]}) {
    std::fprintf(stderr, "version mismatch: %s\n", std::string{iec::version().string}.c_str());
    return 1;
  }

  auto model = iec::server::load_model_file(argv[2]);
  if (!model) {
    std::fprintf(stderr, "load_model_file: %s\n", model.error().message().c_str());
    return 1;
  }
  asio::io_context io;
  auto srv = iec::server::server::start(io.get_executor(), std::move(*model),
                                        {asio::ip::address_v4::loopback(), 0});
  if (!srv) {
    std::fprintf(stderr, "server::start: %s\n", srv.error().message().c_str());
    return 1;
  }

  int status = 1;
  iec::client::client_options options;
  options.association.port = srv->local_endpoint().port();
  asio::co_spawn(
      io,
      [&]() -> asio::awaitable<void> {
        auto c = co_await iec::client::client::connect(io.get_executor(), options);
        if (c) {
          auto lds = co_await c->get_server_directory();
          if (lds && !lds->empty()) {
            for (const auto& ld : *lds) std::printf("%s\n", ld.c_str());
            status = 0;
          }
          (void)co_await c->release();
        } else {
          std::fprintf(stderr, "connect: %s\n", c.error().message().c_str());
        }
        srv->stop();
      },
      asio::detached);
  io.run();
  return status;
}
