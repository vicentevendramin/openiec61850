#include <catch2/catch_test_macros.hpp>

#include "openiec61850/transport/tls.hpp"

#ifndef OPENIEC61850_WITH_TLS

TEST_CASE("TLS unavailable without OPENIEC61850_ENABLE_TLS", "[transport][tls]") {
  namespace t = openiec61850::transport;
  CHECK_FALSE(t::tls_context::available());
  CHECK(t::tls_context::create({}, false).error() == openiec61850::errc::unsupported);
}

#else

#include <chrono>
#include <cstdint>
#include <exception>
#include <optional>
#include <string>
#include <utility>

#include <asio/as_tuple.hpp>
#include <asio/bind_cancellation_slot.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/io_context.hpp>
#include <asio/post.hpp>
#include <asio/ssl/error.hpp>
#include <asio/steady_timer.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>

#include "openiec61850/transport/cotp_channel.hpp"
#include "tls_certs.hpp"

using openiec61850::byte_buffer;
using openiec61850::result;
using namespace openiec61850::transport;
using namespace tls_test;
namespace cotp = openiec61850::iso::cotp;
using asio::awaitable;
using asio::ip::tcp;
using namespace std::chrono_literals;

namespace {

const tcp::endpoint any_loopback{asio::ip::address_v4::loopback(), 0};

void run(awaitable<void> (*test)()) {
  asio::io_context ctx;
  std::exception_ptr failure;
  bool done = false;
  asio::co_spawn(ctx, test(), [&](std::exception_ptr e) {
    failure = e;
    done = true;
  });
  ctx.run_for(10s);
  REQUIRE(done);
  if (failure) std::rethrow_exception(failure);
}

awaitable<void> wait_ms(std::chrono::milliseconds d = 1ms) {
  asio::steady_timer t(co_await asio::this_coro::executor, d);
  co_await t.async_wait(asio::use_awaitable);
}

// One CA with a server certificate for 127.0.0.1 and a client certificate.
struct pki {
  temp_dir dir;
  certificate_authority ca{dir.path, "root"};
  key_pair server_keys = ca.issue("ied1", {"DNS:ied1.local", "IP:127.0.0.1"});
  key_pair client_keys = ca.issue("hmi", {"DNS:hmi.local"});

  [[nodiscard]] tls_config server_config() const {
    tls_config c;
    c.ca_file = ca.certificate();
    c.certificate_file = server_keys.certificate;
    c.private_key_file = server_keys.private_key;
    return c;
  }
  [[nodiscard]] tls_config client_config() const {
    tls_config c;
    c.ca_file = ca.certificate();
    c.certificate_file = client_keys.certificate;
    c.private_key_file = client_keys.private_key;
    return c;
  }
};

channel_options options(const tls_config& c, bool server) {
  auto ctx = tls_context::create(c, server);
  REQUIRE(ctx);
  channel_options o;
  o.connect_timeout = 2s;
  o.handshake_timeout = 2s;
  o.tls = *ctx;
  return o;
}

struct outcome {
  result<cotp_channel> client;
  result<cotp_channel> server;
};

awaitable<outcome> connect_pair(channel_options client, channel_options server,
                                std::string host = "127.0.0.1") {
  const auto ex = co_await asio::this_coro::executor;
  auto listener = cotp_listener::listen(ex, any_loopback);
  REQUIRE(listener);
  std::optional<result<cotp_channel>> accepted;
  asio::co_spawn(
      ex,
      [](cotp_listener& l, std::optional<result<cotp_channel>>& out,
         channel_options o) -> awaitable<void> { out.emplace(co_await l.accept(std::move(o))); }(
          *listener, accepted, std::move(server)),
      asio::detached);
  auto connected = co_await cotp_channel::connect(ex, std::move(host),
                                                  listener->local_endpoint().port(), std::move(client));
  // The verdict on a rejected client reaches the server after the client's own handshake ended.
  if (!connected) listener->close();
  while (!accepted) co_await wait_ms();
  co_return outcome{std::move(connected), std::move(*accepted)};
}

byte_buffer pattern(std::size_t size) {
  byte_buffer b(size);
  for (std::size_t i = 0; i < size; ++i) b[i] = static_cast<std::uint8_t>(i * 7);
  return b;
}

}  // namespace

TEST_CASE("TLS mutual authentication and TSDU exchange", "[transport][tls]") {
  run([]() -> awaitable<void> {
    pki p;
    auto r = co_await connect_pair(options(p.client_config(), false), options(p.server_config(), true));
    REQUIRE(r.client);
    REQUIRE(r.server);
    REQUIRE(r.client->tls_session());
    REQUIRE(r.server->tls_session());
    const auto& on_client = *r.client->tls_session();
    const auto& on_server = *r.server->tls_session();
    CHECK(on_client.version == "TLSv1.3");
    CHECK(on_client.cipher == on_server.cipher);
    CHECK(on_client.peer_subject == "CN=ied1");
    CHECK(on_client.peer_issuer == "CN=root");
    CHECK(on_server.peer_subject == "CN=hmi");
    CHECK(on_server.peer_fingerprint_sha256.size() == 64);
    CHECK_FALSE(on_server.peer_serial.empty());

    // Larger than one TLS record and than one TPDU, in both directions.
    const auto big = pattern(100000);
    auto sent = co_await r.client->send(big);
    REQUIRE(sent);
    auto got = co_await r.server->receive();
    REQUIRE(got);
    CHECK(*got == big);
    sent = co_await r.server->send(pattern(10));
    REQUIRE(sent);
    got = co_await r.client->receive();
    REQUIRE(got);
    CHECK(*got == pattern(10));
  });
}

TEST_CASE("TLS 1.2 can be negotiated", "[transport][tls]") {
  run([]() -> awaitable<void> {
    pki p;
    auto server = p.server_config();
    server.max_version = tls_version::tls1_2;
    auto r = co_await connect_pair(options(p.client_config(), false), options(server, true));
    REQUIRE(r.client);
    CHECK(r.client->tls_session()->version == "TLSv1.2");
  });
}

TEST_CASE("TLS client rejects a server of another CA", "[transport][tls]") {
  run([]() -> awaitable<void> {
    pki p;
    certificate_authority other(p.dir.path, "other");
    auto client = p.client_config();
    client.ca_file = other.certificate();
    auto r = co_await connect_pair(options(client, false), options(p.server_config(), true));
    REQUIRE_FALSE(r.client);
    CHECK(r.client.error().category() == asio::error::get_ssl_category());
    CHECK_FALSE(r.server);
  });
}

TEST_CASE("TLS client rejects a certificate for another name", "[transport][tls]") {
  run([]() -> awaitable<void> {
    pki p;
    auto client = p.client_config();
    client.peer_name = "other.local";
    auto r = co_await connect_pair(options(client, false), options(p.server_config(), true));
    CHECK_FALSE(r.client);

    client.peer_name = "ied1.local";
    r = co_await connect_pair(options(client, false), options(p.server_config(), true));
    CHECK(r.client);

    // verify_peer_name off keeps the chain check only.
    client.peer_name = "other.local";
    client.verify_peer_name = false;
    r = co_await connect_pair(options(client, false), options(p.server_config(), true));
    CHECK(r.client);
  });
}

TEST_CASE("TLS client matches an IP literal against IP subject alternative names", "[transport][tls]") {
  run([]() -> awaitable<void> {
    pki p;
    auto server = p.server_config();
    const auto dns_only = p.ca.issue("dns-only", {"DNS:ied1.local"});
    server.certificate_file = dns_only.certificate;
    server.private_key_file = dns_only.private_key;
    auto r = co_await connect_pair(options(p.client_config(), false), options(server, true));
    CHECK_FALSE(r.client);
  });
}

TEST_CASE("TLS server requires a client certificate", "[transport][tls]") {
  run([]() -> awaitable<void> {
    pki p;
    auto client = p.client_config();
    client.certificate_file.clear();
    client.private_key_file.clear();
    auto r = co_await connect_pair(options(client, false), options(p.server_config(), true));
    CHECK_FALSE(r.server);

    // Accepted when the server does not ask for one.
    auto server = p.server_config();
    server.verify_peer = false;
    r = co_await connect_pair(options(client, false), options(server, true));
    REQUIRE(r.server);
    CHECK(r.server->tls_session()->peer_subject.empty());
  });
}

TEST_CASE("TLS server can pin the client name", "[transport][tls]") {
  run([]() -> awaitable<void> {
    pki p;
    auto server = p.server_config();
    server.peer_name = "hmi.local";
    auto r = co_await connect_pair(options(p.client_config(), false), options(server, true));
    CHECK(r.server);
    server.peer_name = "scada.local";
    r = co_await connect_pair(options(p.client_config(), false), options(server, true));
    CHECK_FALSE(r.server);
  });
}

TEST_CASE("TLS rejects a revoked certificate", "[transport][tls]") {
  run([]() -> awaitable<void> {
    pki p;
    auto server = p.server_config();
    server.crl_file = p.ca.revoke(p.client_keys);
    auto r = co_await connect_pair(options(p.client_config(), false), options(server, true));
    CHECK_FALSE(r.server);

    // The list does not touch other certificates of the CA.
    auto client = p.client_config();
    const auto other = p.ca.issue("other", {});
    client.certificate_file = other.certificate;
    client.private_key_file = other.private_key;
    r = co_await connect_pair(options(client, false), options(server, true));
    CHECK(r.server);
  });
}

TEST_CASE("TLS rejects an expired certificate", "[transport][tls]") {
  run([]() -> awaitable<void> {
    pki p;
    auto server = p.server_config();
    const auto expired = p.ca.issue("expired", {"IP:127.0.0.1"}, -30);
    server.certificate_file = expired.certificate;
    server.private_key_file = expired.private_key;
    auto r = co_await connect_pair(options(p.client_config(), false), options(server, true));
    CHECK_FALSE(r.client);
  });
}

TEST_CASE("Plain client against a TLS listener fails instead of hanging", "[transport][tls]") {
  run([]() -> awaitable<void> {
    pki p;
    channel_options plain;
    plain.handshake_timeout = 2s;
    auto r = co_await connect_pair(std::move(plain), options(p.server_config(), true));
    CHECK_FALSE(r.client);
    CHECK_FALSE(r.server);
  });
}

TEST_CASE("TLS handshake is bounded by handshake_timeout", "[transport][tls]") {
  run([]() -> awaitable<void> {
    pki p;
    const auto ex = co_await asio::this_coro::executor;
    tcp::acceptor silent(ex, any_loopback);  // accepts in the backlog, never answers
    auto o = options(p.client_config(), false);
    o.handshake_timeout = 50ms;
    auto c = co_await cotp_channel::connect(ex, silent.local_endpoint(), std::move(o));
    REQUIRE_FALSE(c);
    CHECK(c.error() == asio::error::timed_out);
  });
}

TEST_CASE("TLS receive can be cancelled and the channel stays usable", "[transport][tls]") {
  run([]() -> awaitable<void> {
    pki p;
    auto r = co_await connect_pair(options(p.client_config(), false), options(p.server_config(), true));
    REQUIRE(r.server);
    asio::cancellation_signal signal;
    std::optional<result<byte_buffer>> received;
    const auto ex = co_await asio::this_coro::executor;
    asio::co_spawn(ex,
                   [](cotp_channel& ch, std::optional<result<byte_buffer>>& out) -> awaitable<void> {
                     out.emplace(co_await ch.receive());
                   }(*r.server, received),
                   asio::bind_cancellation_slot(signal.slot(), asio::detached));
    co_await wait_ms(10ms);
    signal.emit(asio::cancellation_type::all);
    while (!received) co_await wait_ms();
    REQUIRE_FALSE(*received);
    CHECK(received->error() == asio::error::operation_aborted);

    auto sent = co_await r.client->send(pattern(64));
    REQUIRE(sent);
    auto got = co_await r.server->receive();
    REQUIRE(got);
    CHECK(*got == pattern(64));
  });
}

TEST_CASE("TLS shutdown delivers queued data and ends the peer's stream", "[transport][tls]") {
  run([]() -> awaitable<void> {
    pki p;
    auto r = co_await connect_pair(options(p.client_config(), false), options(p.server_config(), true));
    REQUIRE(r.server);
    auto sent = co_await r.client->send(pattern(32));
    REQUIRE(sent);
    const auto ex = co_await asio::this_coro::executor;
    asio::co_spawn(ex,
                   [](cotp_channel& ch) -> awaitable<void> { (void)co_await ch.shutdown(); }(*r.client),
                   asio::detached);
    auto got = co_await r.server->receive();
    REQUIRE(got);
    CHECK(*got == pattern(32));
    auto end = co_await r.server->receive();
    REQUIRE_FALSE(end);
    CHECK(end.error() == asio::error::eof);
  });
}

TEST_CASE("TLS peer dropping TCP without close_notify reads as end of stream", "[transport][tls]") {
  run([]() -> awaitable<void> {
    pki p;
    auto r = co_await connect_pair(options(p.client_config(), false), options(p.server_config(), true));
    REQUIRE(r.server);
    r.client->close();
    auto end = co_await r.server->receive();
    REQUIRE_FALSE(end);
    CHECK(end.error() == asio::error::eof);
  });
}

TEST_CASE("TLS configuration errors", "[transport][tls]") {
  pki p;
  tls_config c = p.server_config();

  auto missing_cert = c;
  missing_cert.certificate_file.clear();
  CHECK(tls_context::create(missing_cert, true).error() == std::errc::invalid_argument);

  auto no_identity = c;
  no_identity.certificate_file.clear();
  no_identity.private_key_file.clear();
  CHECK(tls_context::create(no_identity, true).error() == std::errc::invalid_argument);
  CHECK(tls_context::create(no_identity, false));

  auto no_ca = c;
  no_ca.ca_file.clear();
  CHECK(tls_context::create(no_ca, true).error() == std::errc::invalid_argument);
  no_ca.verify_peer = false;
  CHECK(tls_context::create(no_ca, true));

  auto bad_file = c;
  bad_file.ca_file = (p.dir.path / "absent.pem").string();
  CHECK_FALSE(tls_context::create(bad_file, true));

  auto mismatch = c;
  mismatch.private_key_file = p.client_keys.private_key;
  CHECK_FALSE(tls_context::create(mismatch, true));

  auto bad_ciphers = c;
  bad_ciphers.cipher_list = "NOT-A-CIPHER";
  CHECK_FALSE(tls_context::create(bad_ciphers, true));

  CHECK(tls_context::available());
}

#endif
