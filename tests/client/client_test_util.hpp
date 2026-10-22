#pragma once

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <exception>
#include <string_view>

#include <asio/co_spawn.hpp>
#include <asio/io_context.hpp>
#include <asio/post.hpp>
#include <asio/steady_timer.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>

#include "fake_server.hpp"
#include "openiec61850/client/client.hpp"

namespace client_test {

using namespace std::chrono_literals;

// Runs a test coroutine on a fresh io_context; the context is stopped as soon as it finishes.
inline void run(asio::awaitable<void> (*test)()) {
  asio::io_context ctx;
  std::exception_ptr failure;
  bool done = false;
  asio::co_spawn(ctx, test(), [&](std::exception_ptr e) {
    failure = e;
    done = true;
    ctx.stop();
  });
  ctx.run_for(10s);
  REQUIRE(done);
  if (failure) std::rethrow_exception(failure);
}

inline asio::awaitable<void> yield() {
  co_await asio::post(co_await asio::this_coro::executor, asio::use_awaitable);
}

inline asio::awaitable<void> sleep(std::chrono::milliseconds d) {
  asio::steady_timer t(co_await asio::this_coro::executor, d);
  co_await t.async_wait(asio::use_awaitable);
}

inline openiec61850::model::object_reference ref(std::string_view text) {
  auto r = openiec61850::model::object_reference::parse(text);
  REQUIRE(r);
  return *r;
}

inline openiec61850::client::client_options options_for(const openiec61850::testing::fake_server& s) {
  openiec61850::client::client_options o;
  o.association.port = s.port();
  o.association.transport.connect_timeout = 1s;
  o.association.transport.handshake_timeout = 1s;
  o.association.association_timeout = 1s;
  o.association.request_timeout = 2s;
  o.association.release_timeout = 1s;
  return o;
}

inline asio::awaitable<openiec61850::client::client> connect(
    const openiec61850::client::client_options& o) {
  auto c = co_await openiec61850::client::client::connect(co_await asio::this_coro::executor, o);
  REQUIRE(c);
  co_return std::move(*c);
}

}  // namespace client_test
