#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <future>
#include <optional>
#include <stdexcept>
#include <thread>

#include <asio/co_spawn.hpp>
#include <asio/post.hpp>

#include "openiec61850/transport/cotp_channel.hpp"
#include "openiec61850/transport/io_runtime.hpp"
#include "openiec61850/transport/spawn.hpp"

using openiec61850::byte_buffer;
using openiec61850::result;
using namespace openiec61850::transport;
using namespace std::chrono_literals;

namespace {

// Runs f on the runtime's thread and waits for its result.
template <typename F>
auto on_io_thread(io_runtime& rt, F f) {
  std::promise<decltype(f())> p;
  auto fut = p.get_future();
  asio::post(rt.get_executor(), [&p, &f] { p.set_value(f()); });
  REQUIRE(fut.wait_for(2s) == std::future_status::ready);
  return fut.get();
}

}  // namespace

TEST_CASE("io_runtime start and stop are idempotent", "[transport]") {
  io_runtime rt;
  CHECK_FALSE(rt.running());
  rt.stop();
  rt.join();
  rt.start();
  rt.start();
  CHECK(rt.running());
  CHECK_FALSE(rt.running_in_this_thread());
  CHECK(on_io_thread(rt, [&] { return rt.running_in_this_thread(); }));
  CHECK(on_io_thread(rt, [] { return std::this_thread::get_id(); }) != std::this_thread::get_id());
  rt.stop();
  rt.stop();
  rt.join();
  rt.join();
  CHECK_FALSE(rt.running());

  // Restart after a stop; work posted while stopped runs on restart.
  std::promise<int> p;
  asio::post(rt.get_executor(), [&p] { p.set_value(7); });
  rt.start();
  auto fut = p.get_future();
  REQUIRE(fut.wait_for(2s) == std::future_status::ready);
  CHECK(fut.get() == 7);
}

TEST_CASE("io_runtime stop from the I/O thread and destructor", "[transport]") {
  {
    io_runtime rt;
    rt.start();
    asio::post(rt.get_executor(), [&rt] { rt.stop(); });
    rt.join();
    CHECK_FALSE(rt.running());
  }
  {
    io_runtime rt;
    rt.start();
  }  // the destructor stops and joins
}

TEST_CASE("io_runtime survives a throwing handler", "[transport]") {
  io_runtime rt;
  rt.start();
  asio::post(rt.get_executor(), [] { throw std::runtime_error("boom"); });
  CHECK(on_io_thread(rt, [] { return 1; }) == 1);
  CHECK(rt.take_exception() != nullptr);
  CHECK(rt.take_exception() == nullptr);
}

TEST_CASE("COTP channel driven from another thread through io_runtime", "[transport]") {
  io_runtime rt;
  rt.start();
  const asio::ip::tcp::endpoint loopback{asio::ip::address_v4::loopback(), 0};
  auto listener = cotp_listener::listen(rt.get_executor(), loopback);
  REQUIRE(listener);

  std::promise<result<cotp_channel>> accepted;
  openiec61850::transport::spawn(rt.get_executor(), listener->accept(),
        [&accepted](result<cotp_channel> r) { accepted.set_value(std::move(r)); });

  std::promise<result<cotp_channel>> connected;
  channel_options options;
  options.handshake_timeout = 1s;
  options.connect_timeout = 1s;
  cotp_channel::async_connect(rt.get_executor(), "127.0.0.1", listener->local_endpoint().port(),
                              options, [&connected, &rt](result<cotp_channel> r) {
                                CHECK(rt.running_in_this_thread());
                                connected.set_value(std::move(r));
                              });
  auto client_future = connected.get_future();
  auto server_future = accepted.get_future();
  REQUIRE(client_future.wait_for(2s) == std::future_status::ready);
  REQUIRE(server_future.wait_for(2s) == std::future_status::ready);
  auto client = client_future.get();
  auto server = server_future.get();
  REQUIRE(client);
  REQUIRE(server);

  std::promise<result<byte_buffer>> received;
  server->async_receive([&received](result<byte_buffer> r) { received.set_value(std::move(r)); });
  std::promise<result<void>> sent;
  client->async_send(byte_buffer(5000, 0xAB), [&sent](result<void> r) { sent.set_value(r); });
  auto sent_future = sent.get_future();
  auto received_future = received.get_future();
  REQUIRE(sent_future.wait_for(2s) == std::future_status::ready);
  REQUIRE(received_future.wait_for(2s) == std::future_status::ready);
  CHECK(sent_future.get());
  auto got = received_future.get();
  REQUIRE(got);
  CHECK(*got == byte_buffer(5000, 0xAB));

  // Channels go before the runtime; close() is safe from this thread.
  client->close();
  server->close();
  listener->close();
}
