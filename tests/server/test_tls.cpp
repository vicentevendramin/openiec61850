#include <catch2/catch_test_macros.hpp>

#include "openiec61850/transport/tls.hpp"

#ifdef OPENIEC61850_WITH_TLS

#include <optional>
#include <string>

#include "../transport/tls_certs.hpp"
#include "server_test_util.hpp"

using namespace server_test;
using asio::awaitable;
namespace transport = openiec61850::transport;
namespace association = openiec61850::association;

namespace {

std::shared_ptr<transport::tls_context> context(const tls_test::certificate_authority& ca,
                                                const tls_test::key_pair& keys, bool server) {
  transport::tls_config c;
  c.ca_file = ca.certificate();
  c.certificate_file = keys.certificate;
  c.private_key_file = keys.private_key;
  auto ctx = transport::tls_context::create(c, server);
  REQUIRE(ctx);
  return *ctx;
}

}  // namespace

TEST_CASE("Association, services and release over TLS", "[server][tls]") {
  run([]() -> awaitable<void> {
    tls_test::temp_dir dir;
    tls_test::certificate_authority ca(dir.path, "root");
    const auto server_keys = ca.issue("ied1", {"IP:127.0.0.1"});
    const auto client_keys = ca.issue("hmi");

    std::optional<std::string> seen_subject;
    srv::server_options o;
    o.association.transport.tls = context(ca, server_keys, true);
    o.association.authorize = [&](const association::association_request& r, mms::initiate_response&) {
      if (r.tls) seen_subject = r.tls->peer_subject;
      return association::association_decision::accepted();
    };
    auto s = start(co_await asio::this_coro::executor, o);
    auto opts = options_for(s);
    opts.association.transport.tls = context(ca, client_keys, false);
    auto c = co_await connect(opts);

    const auto info = c.association_info();
    REQUIRE(info.tls);
    CHECK(info.tls->peer_subject == "CN=ied1");
    CHECK(seen_subject == "CN=hmi");

    auto lds = co_await c.get_server_directory();
    REQUIRE(lds);
    CHECK(lds->size() == 2);

    auto closed = co_await c.release();
    CHECK(closed);

    // A client without TLS does not get an association.
    auto plain = options_for(s);
    auto refused = co_await client::client::connect(co_await asio::this_coro::executor, plain);
    CHECK_FALSE(refused);
    s.stop();
    co_await s.wait_stopped();
  });
}

#endif
