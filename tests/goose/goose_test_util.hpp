#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/io_context.hpp>

#include "../mms/mms_test_util.hpp"
#include "openiec61850/goose/link.hpp"

namespace goose_test {

using mms_test::hex;
namespace goose = openiec61850::goose;

inline constexpr goose::mac_address mac_a{0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
inline constexpr goose::mac_address mac_b{0x00, 0x11, 0x22, 0x33, 0x44, 0x66};

template <typename T>
asio::awaitable<void> store(asio::awaitable<T> op, std::optional<T>* out) {
  out->emplace(co_await std::move(op));
}

// Runs `op` on ctx until it completes or `timeout` elapses.
template <typename T>
std::optional<T> run(asio::io_context& ctx, asio::awaitable<T> op,
                     std::chrono::milliseconds timeout = std::chrono::milliseconds{2000}) {
  std::optional<T> out;
  asio::co_spawn(ctx, store(std::move(op), &out), asio::detached);
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  ctx.restart();
  while (!out && std::chrono::steady_clock::now() < deadline) {
    ctx.run_one_for(std::chrono::milliseconds{5});
  }
  return out;
}

// Runs the context for `d`.
inline void run_for(asio::io_context& ctx, std::chrono::milliseconds d) {
  ctx.restart();
  const auto deadline = std::chrono::steady_clock::now() + d;
  while (std::chrono::steady_clock::now() < deadline) {
    ctx.run_one_until(deadline);
  }
}

// Runs `ctx` until `done()` holds or `limit` elapses; returns done(). Prefer this over run_for
// when a test needs N events, so loaded CI machines only make it slower, not flaky.
template <typename Pred>
bool run_until(asio::io_context& ctx, Pred done, std::chrono::milliseconds limit = std::chrono::seconds{5}) {
  ctx.restart();
  const auto deadline = std::chrono::steady_clock::now() + limit;
  while (!done() && std::chrono::steady_clock::now() < deadline) {
    ctx.run_one_until(deadline);
  }
  return done();
}

// Receives frames on `l` forever into `out` (with their arrival time).
struct capture {
  std::vector<openiec61850::byte_buffer> frames;
  std::vector<std::chrono::steady_clock::time_point> times;
};

inline asio::awaitable<void> capture_loop(std::shared_ptr<goose::link> l,
                                          std::shared_ptr<capture> out) {
  std::vector<std::uint8_t> buf(2048);
  for (;;) {
    auto n = co_await l->receive(buf);
    if (!n) co_return;
    out->frames.emplace_back(buf.begin(), buf.begin() + static_cast<std::ptrdiff_t>(*n));
    out->times.push_back(std::chrono::steady_clock::now());
  }
}

inline std::shared_ptr<capture> start_capture(asio::io_context& ctx,
                                              std::shared_ptr<goose::link> l) {
  auto c = std::make_shared<capture>();
  asio::co_spawn(ctx, capture_loop(std::move(l), c), asio::detached);
  return c;
}

}  // namespace goose_test
