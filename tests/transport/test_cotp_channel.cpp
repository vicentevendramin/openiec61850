#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstdint>
#include <exception>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <asio/as_tuple.hpp>
#include <asio/bind_cancellation_slot.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/io_context.hpp>
#include <asio/post.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/write.hpp>

#include "openiec61850/transport/cotp_channel.hpp"

using openiec61850::byte_buffer;
using openiec61850::errc;
using openiec61850::result;
using namespace openiec61850::transport;
namespace cotp = openiec61850::iso::cotp;
using asio::awaitable;
using asio::ip::tcp;
using namespace std::chrono_literals;

// Note: GCC evaluates a co_await inside a Catch2 assertion macro twice, so results are
// always stored in a variable before being checked.

namespace {

const tcp::endpoint any_loopback{asio::ip::address_v4::loopback(), 0};

// Runs a test coroutine to completion on a context driven by the test thread.
void run(awaitable<void> (*test)()) {
  asio::io_context ctx;
  std::exception_ptr failure;
  bool done = false;
  asio::co_spawn(ctx, test(), [&](std::exception_ptr e) {
    failure = e;
    done = true;
  });
  ctx.run_for(5s);
  REQUIRE(done);
  if (failure) std::rethrow_exception(failure);
}

awaitable<void> yield() {
  co_await asio::post(co_await asio::this_coro::executor, asio::use_awaitable);
}

template <typename T>
awaitable<T> wait_for(std::optional<T>& slot) {
  while (!slot) co_await yield();
  co_return std::move(*slot);
}

byte_buffer pattern(std::size_t size, std::uint8_t seed) {
  byte_buffer b(size);
  for (std::size_t i = 0; i < size; ++i) b[i] = static_cast<std::uint8_t>(seed + i * 7);
  return b;
}

channel_options client_options(std::size_t max_tpdu = 2048) {
  channel_options o;
  o.cotp.calling_tsap = byte_buffer{0x00, 0x01};
  o.cotp.called_tsap = byte_buffer{0x00, 0x02};
  o.cotp.max_tpdu_size = max_tpdu;
  o.connect_timeout = 1s;
  o.handshake_timeout = 1s;
  return o;
}

channel_options server_options() {
  channel_options o;
  o.cotp.accept_connection = [](const cotp::connection_request& cr) -> std::optional<std::uint8_t> {
    if (cr.called_tsap != byte_buffer{0x00, 0x02}) return cotp::disconnect_reason::address_unknown;
    return std::nullopt;
  };
  o.handshake_timeout = 1s;
  return o;
}

struct channel_pair {
  cotp_channel client;
  cotp_channel server;
};

awaitable<std::pair<result<cotp_channel>, result<cotp_channel>>> try_connect_pair(
    channel_options client = client_options(), channel_options server = server_options()) {
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
  auto connected = co_await cotp_channel::connect(ex, "127.0.0.1", listener->local_endpoint().port(),
                                                  std::move(client));
  auto server_side = co_await wait_for(accepted);
  co_return std::pair{std::move(connected), std::move(server_side)};
}

awaitable<channel_pair> connect_pair(channel_options client = client_options()) {
  auto [c, s] = co_await try_connect_pair(std::move(client));
  REQUIRE(c);
  REQUIRE(s);
  co_return channel_pair{std::move(*c), std::move(*s)};
}

}  // namespace

TEST_CASE("COTP channel handshake over loopback", "[transport]") {
  run([]() -> awaitable<void> {
    auto [client, server] = co_await connect_pair(client_options(1024));
    CHECK(client.is_open());
    CHECK(server.is_open());
    CHECK(client.connection_role() == cotp::role::initiator);
    CHECK(server.connection_role() == cotp::role::responder);
    CHECK(client.connection_info().tpdu_size == 1024);
    CHECK(server.connection_info().tpdu_size == 1024);
    CHECK(server.connection_info().called_tsap == byte_buffer{0x00, 0x02});
    CHECK(client.connection_info().calling_tsap == byte_buffer{0x00, 0x01});
    CHECK(client.remote_endpoint() == server.local_endpoint());
    CHECK(client.local_endpoint() == server.remote_endpoint());
  });
}

TEST_CASE("COTP channel TSDU exchange in both directions", "[transport]") {
  run([]() -> awaitable<void> {
    auto [client, server] = co_await connect_pair(client_options(128));
    for (const std::size_t size : {std::size_t{0}, std::size_t{1}, std::size_t{125},
                                   std::size_t{126}, std::size_t{1000}, std::size_t{65536},
                                   std::size_t{200000}}) {
      const auto request = pattern(size, 1);
      const auto sent = co_await client.send(request);
      REQUIRE(sent);
      auto got = co_await server.receive();
      REQUIRE(got);
      CHECK(*got == request);

      const auto response = pattern(size, 2);
      const auto replied = co_await server.send(response);
      REQUIRE(replied);
      got = co_await client.receive();
      REQUIRE(got);
      CHECK(*got == response);
    }
  });
}

TEST_CASE("COTP channel pipelines concurrent sends in order", "[transport]") {
  run([]() -> awaitable<void> {
    auto [client, server] = co_await connect_pair(client_options(256));
    constexpr int count = 200;
    int completed = 0;
    for (int i = 0; i < count; ++i) {
      asio::co_spawn(
          co_await asio::this_coro::executor,
          [](cotp_channel& ch, int n, int& done) -> awaitable<void> {
            const auto tsdu = pattern(static_cast<std::size_t>(100 + n * 13), static_cast<std::uint8_t>(n));
            const auto r = co_await ch.send(tsdu);
            REQUIRE(r);
            ++done;
          }(client, i, completed),
          asio::detached);
    }
    for (int i = 0; i < count; ++i) {
      auto got = co_await server.receive();
      REQUIRE(got);
      CHECK(*got == pattern(static_cast<std::size_t>(100 + i * 13), static_cast<std::uint8_t>(i)));
    }
    while (completed < count) co_await yield();
  });
}

TEST_CASE("COTP channel callback API", "[transport]") {
  run([]() -> awaitable<void> {
    auto [client, server] = co_await connect_pair();
    std::vector<result<void>> sent;
    for (std::uint8_t i = 0; i < 10; ++i) {
      client.async_send(byte_buffer{i, i, i}, [&sent](result<void> r) { sent.push_back(r); });
    }
    std::optional<result<byte_buffer>> received;
    for (std::uint8_t i = 0; i < 10; ++i) {
      received.reset();
      server.async_receive([&received](result<byte_buffer> r) { received.emplace(std::move(r)); });
      auto got = co_await wait_for(received);
      REQUIRE(got);
      CHECK(*got == byte_buffer{i, i, i});
    }
    while (sent.size() < 10) co_await yield();
    for (const auto& r : sent) CHECK(r);
  });
}

TEST_CASE("COTP channel reports a peer close on receive", "[transport]") {
  run([]() -> awaitable<void> {
    auto [client, server] = co_await connect_pair();
    const auto sent = co_await server.send(byte_buffer{1, 2, 3});
    REQUIRE(sent);
    const auto closed = co_await server.shutdown();
    REQUIRE(closed);
    CHECK_FALSE(server.is_open());

    // Data sent before the close is still delivered.
    auto got = co_await client.receive();
    REQUIRE(got);
    CHECK(*got == byte_buffer{1, 2, 3});
    got = co_await client.receive();
    CHECK(got.error() == asio::error::eof);
    CHECK_FALSE(client.is_open());
    const auto late = co_await client.send(byte_buffer{4});
    CHECK(late.error() == asio::error::eof);
  });
}

TEST_CASE("COTP channel local close aborts a pending receive", "[transport]") {
  run([]() -> awaitable<void> {
    auto [client, server] = co_await connect_pair();
    std::optional<result<byte_buffer>> received;
    client.async_receive([&received](result<byte_buffer> r) { received.emplace(std::move(r)); });
    co_await yield();
    std::optional<result<byte_buffer>> second;
    client.async_receive([&second](result<byte_buffer> r) { second.emplace(std::move(r)); });
    auto busy = co_await wait_for(second);
    CHECK(busy.error() == errc::invalid_state);

    client.close();
    auto got = co_await wait_for(received);
    CHECK(got.error() == asio::error::operation_aborted);
    const auto late = co_await client.send(byte_buffer{1});
    CHECK(late.error() == asio::error::operation_aborted);

    auto peer = co_await server.receive();
    CHECK(peer.error() == asio::error::eof);
  });
}

TEST_CASE("COTP channel refused by the responder's TSAP check", "[transport]") {
  run([]() -> awaitable<void> {
    auto options = client_options();
    options.cotp.called_tsap = byte_buffer{0x00, 0x09};
    auto [client, server] = co_await try_connect_pair(std::move(options));
    CHECK(client.error() == std::errc::connection_refused);
    CHECK(server.error() == std::errc::connection_refused);
  });
}

TEST_CASE("COTP channel connect to a closed port", "[transport]") {
  run([]() -> awaitable<void> {
    const auto ex = co_await asio::this_coro::executor;
    std::uint16_t port = 0;
    {
      auto listener = cotp_listener::listen(ex, any_loopback);
      REQUIRE(listener);
      port = listener->local_endpoint().port();
    }
    co_await yield();  // let the deferred close run
    const tcp::endpoint closed{asio::ip::address_v4::loopback(), port};
    auto ch = co_await cotp_channel::connect(ex, closed, client_options());
    CHECK(ch.error() == asio::error::connection_refused);
  });
}

TEST_CASE("COTP channel handshake timeout", "[transport]") {
  run([]() -> awaitable<void> {
    const auto ex = co_await asio::this_coro::executor;
    // The kernel completes the TCP handshake, but nobody answers the CR.
    auto listener = cotp_listener::listen(ex, any_loopback);
    REQUIRE(listener);
    auto options = client_options();
    options.handshake_timeout = 50ms;
    const auto start = std::chrono::steady_clock::now();
    auto ch = co_await cotp_channel::connect(ex, "127.0.0.1", listener->local_endpoint().port(),
                                             std::move(options));
    CHECK(ch.error() == asio::error::timed_out);
    CHECK(std::chrono::steady_clock::now() - start < 1s);
  });
}

TEST_CASE("COTP channel responder handshake timeout", "[transport]") {
  run([]() -> awaitable<void> {
    const auto ex = co_await asio::this_coro::executor;
    auto listener = cotp_listener::listen(ex, any_loopback);
    REQUIRE(listener);
    // A plain TCP client that never sends a CR.
    tcp::socket raw(ex);
    auto [ec] = co_await raw.async_connect(listener->local_endpoint(),
                                           asio::as_tuple(asio::use_awaitable));
    REQUIRE(!ec);
    auto options = server_options();
    options.handshake_timeout = 50ms;
    auto ch = co_await listener->accept(std::move(options));
    CHECK(ch.error() == asio::error::timed_out);
  });
}

TEST_CASE("COTP channel closes on a peer protocol error", "[transport]") {
  run([]() -> awaitable<void> {
    const auto ex = co_await asio::this_coro::executor;
    auto listener = cotp_listener::listen(ex, any_loopback);
    REQUIRE(listener);
    std::optional<result<cotp_channel>> accepted;
    asio::co_spawn(
        ex,
        [](cotp_listener& l, std::optional<result<cotp_channel>>& out) -> awaitable<void> {
          out.emplace(co_await l.accept(server_options()));
        }(*listener, accepted),
        asio::detached);
    tcp::socket raw(ex);
    auto [ec] = co_await raw.async_connect(listener->local_endpoint(),
                                           asio::as_tuple(asio::use_awaitable));
    REQUIRE(!ec);
    const auto write = [&raw](byte_buffer bytes) -> awaitable<void> {
      auto [wec, n] = co_await asio::async_write(raw, asio::buffer(bytes),
                                                 asio::as_tuple(asio::use_awaitable));
      REQUIRE(!wec);
      CHECK(n == bytes.size());
    };
    // CR with called TSAP 0x0002.
    co_await write(byte_buffer{0x03, 0x00, 0x00, 0x0F, 0x0A, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00,
                               0xC2, 0x02, 0x00, 0x02});
    auto server = co_await wait_for(accepted);
    REQUIRE(server);
    // A TPKT with a bad version.
    co_await write(byte_buffer{0x07, 0x00, 0x00, 0x07, 0x02, 0xF0, 0x80});
    auto got = co_await server->receive();
    CHECK(got.error() == errc::malformed_encoding);
    CHECK_FALSE(server->is_open());
  });
}

namespace {

struct quiet_pair {
  cotp_channel local;
  cotp_channel peer;  // never reads
};

// A plain function: GCC 13 crashes on this braced temporary inside a coroutine.
quiet_pair make_quiet_pair(cotp_channel local, cotp_channel peer) {
  return quiet_pair{std::move(local), std::move(peer)};
}

awaitable<quiet_pair> open_quiet_pair(channel_options options) {
  auto ex = co_await asio::this_coro::executor;
  auto listener = cotp_listener::listen(ex, any_loopback);
  REQUIRE(listener);
  const auto port = listener->local_endpoint().port();
  std::optional<result<cotp_channel>> accepted;
  asio::co_spawn(
      ex,
      [](cotp_listener& l, std::optional<result<cotp_channel>>& out) -> awaitable<void> {
        out.emplace(co_await l.accept());
      }(*listener, accepted),
      asio::detached);
  auto local = co_await cotp_channel::connect(ex, "127.0.0.1", port, std::move(options));
  REQUIRE(local);
  auto peer = co_await wait_for(accepted);
  REQUIRE(peer);
  co_return make_quiet_pair(std::move(*local), std::move(*peer));
}

// Sends until one of them fails, none of them waiting for the previous one.
awaitable<std::error_code> send_until_failure(cotp_channel& c, std::size_t size) {
  auto failure = std::make_shared<std::error_code>();  // the handlers outlive this coroutine
  std::size_t sends = 0;
  while (!*failure && sends < 100000) {
    c.async_send(pattern(size, 1), [failure](result<void> r) {
      if (!r) *failure = r.error();
    });
    ++sends;
    co_await yield();
  }
  co_return *failure;
}

}  // namespace

TEST_CASE("COTP channel fails past max_output_bytes", "[transport]") {
  run([]() -> awaitable<void> {
    channel_options o;
    o.max_output_bytes = 256 * 1024;
    o.write_stall_timeout = 0ms;
    auto p = co_await open_quiet_pair(o);
    const auto failure = co_await send_until_failure(p.local, 60000);
    CHECK(failure == errc::output_limit_exceeded);
    CHECK_FALSE(p.local.is_open());
    auto after = co_await p.local.send(pattern(16, 1));
    REQUIRE_FALSE(after);
    CHECK(after.error() == errc::output_limit_exceeded);
  });
}

TEST_CASE("COTP channel charges tiny TSDUs for what they hold", "[transport]") {
  run([]() -> awaitable<void> {
    channel_options o;
    o.max_output_bytes = 256 * 1024;
    o.write_stall_timeout = 0ms;
    auto p = co_await open_quiet_pair(o);
    // All queued before the first write: their bytes alone are far below the limit.
    auto failure = std::make_shared<std::error_code>();
    for (int i = 0; i < 256; ++i) {
      p.local.async_send(pattern(16, 1), [failure](result<void> r) {
        if (!r) *failure = r.error();
      });
    }
    while (!*failure) co_await yield();
    CHECK(*failure == errc::output_limit_exceeded);
  });
}

TEST_CASE("COTP channel takes a TSDU above the limit into an empty queue", "[transport]") {
  run([]() -> awaitable<void> {
    channel_options o;
    o.max_output_bytes = 1024;
    auto p = co_await open_quiet_pair(o);
    const auto sent = co_await p.local.send(pattern(8192, 1));
    CHECK(sent);
    auto got = co_await p.peer.receive();
    REQUIRE(got);
    CHECK(got->size() == 8192);
  });
}

TEST_CASE("COTP channel fails on a write stall", "[transport]") {
  run([]() -> awaitable<void> {
    channel_options o;
    o.max_output_bytes = 0;
    o.write_stall_timeout = 100ms;
    auto p = co_await open_quiet_pair(o);
    const auto failure = co_await send_until_failure(p.local, 60000);
    CHECK(failure == asio::error::timed_out);
    CHECK_FALSE(p.local.is_open());
  });
}

TEST_CASE("COTP channel shutdown gives up at its limit", "[transport]") {
  run([]() -> awaitable<void> {
    channel_options o;
    o.max_output_bytes = 0;
    o.write_stall_timeout = 0ms;
    auto p = co_await open_quiet_pair(o);
    for (int i = 0; i < 400; ++i) p.local.async_send(pattern(60000, 1), [](result<void>) {});
    co_await yield();
    const auto closed = co_await p.local.shutdown(100ms);
    REQUIRE_FALSE(closed);
    CHECK(closed.error() == asio::error::timed_out);
  });
}

TEST_CASE("COTP channel survives a cancelled receive", "[transport]") {
  run([]() -> awaitable<void> {
    auto [client, server] = co_await connect_pair();
    asio::cancellation_signal signal;
    std::optional<result<byte_buffer>> cancelled;
    asio::co_spawn(
        co_await asio::this_coro::executor,
        [](cotp_channel& ch, std::optional<result<byte_buffer>>& out) -> awaitable<void> {
          out.emplace(co_await ch.receive());
        }(client, cancelled),
        asio::bind_cancellation_slot(signal.slot(), asio::detached));
    co_await yield();
    co_await yield();
    signal.emit(asio::cancellation_type::terminal);
    auto got = co_await wait_for(cancelled);
    CHECK(got.error() == asio::error::operation_aborted);
    CHECK(client.is_open());

    const auto sent = co_await server.send(byte_buffer{9, 9});
    REQUIRE(sent);
    got = co_await client.receive();
    REQUIRE(got);
    CHECK(*got == byte_buffer{9, 9});
  });
}
