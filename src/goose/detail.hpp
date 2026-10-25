#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <optional>
#include <utility>

#include <asio/any_io_executor.hpp>
#include <asio/as_tuple.hpp>
#include <asio/awaitable.hpp>
#include <asio/steady_timer.hpp>
#include <asio/strand.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>

#include "openiec61850/ber/reader.hpp"
#include "openiec61850/core/result.hpp"
#include "openiec61850/mms/data.hpp"
#include "openiec61850/transport/spawn.hpp"

namespace openiec61850::goose::detail {

using strand_type = asio::strand<asio::any_io_executor>;
using clock = std::chrono::steady_clock;

[[nodiscard]] result<std::uint32_t> read_u32(ber::reader& rd, ber::tag t) noexcept;
[[nodiscard]] result<mms::utc_time> read_utc_time(ber::reader& rd, ber::tag t) noexcept;
// An optional ANY element with context tag `number` (either form): its contents.
[[nodiscard]] result<std::optional<byte_view>> read_security(ber::reader& rd,
                                                             std::uint32_t number) noexcept;

// Runs `op` on `strand`, resuming the caller on its own executor.
template <typename T>
asio::awaitable<T> on_strand(strand_type strand, asio::awaitable<T> op) {
  const auto current = co_await asio::this_coro::executor;
  if (current == asio::any_io_executor(strand)) co_return co_await std::move(op);
  co_return co_await transport::run_on(strand, std::move(op));
}

// A bounded queue with one consumer coroutine, or a handler; lives on a strand. The oldest item
// is dropped on overflow and counted in the next item's dropped_before.
template <typename T>
class event_queue {
 public:
  explicit event_queue(const strand_type& s, std::size_t capacity)
      : timer_(s, clock::time_point::max()), capacity_(capacity == 0 ? 1 : capacity) {}

  // Returns true when an item was dropped.
  bool push(T v) {
    if (handler_) {
      handler_(v);
      return false;
    }
    bool dropped = false;
    if (items_.size() >= capacity_) {
      const auto lost = items_.front().dropped_before + 1;
      items_.pop_front();
      if (!items_.empty()) {
        items_.front().dropped_before += lost;
      } else {
        v.dropped_before += lost;
      }
      dropped = true;
    }
    items_.push_back(std::move(v));
    timer_.cancel();
    return dropped;
  }

  void set_handler(std::function<void(const T&)> h) {
    handler_ = std::move(h);
    if (handler_) {
      while (!items_.empty()) {
        auto v = std::move(items_.front());
        items_.pop_front();
        handler_(v);
      }
      timer_.cancel();
    }
  }
  [[nodiscard]] bool has_handler() const noexcept { return static_cast<bool>(handler_); }

  void close() {
    closed_ = true;
    timer_.cancel();
  }
  [[nodiscard]] bool closed() const noexcept { return closed_; }

  // Must run on the strand.
  asio::awaitable<result<T>> pop() {
    for (;;) {
      if (!items_.empty()) {
        auto v = std::move(items_.front());
        items_.pop_front();
        co_return result<T>(std::move(v));
      }
      if (closed_ || handler_ || waiting_) co_return result<T>(errc::invalid_state);
      waiting_ = true;
      timer_.expires_at(clock::time_point::max());
      auto [ec] = co_await timer_.async_wait(asio::as_tuple(asio::use_awaitable));
      waiting_ = false;
      (void)ec;
    }
  }

 private:
  asio::steady_timer timer_;
  std::deque<T> items_;
  std::size_t capacity_;
  std::function<void(const T&)> handler_;
  bool closed_ = false;
  bool waiting_ = false;
};

}  // namespace openiec61850::goose::detail
