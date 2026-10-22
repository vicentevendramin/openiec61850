#pragma once

#include <exception>
#include <optional>
#include <system_error>
#include <utility>

#include <asio/awaitable.hpp>
#include <asio/co_spawn.hpp>
#include <asio/use_awaitable.hpp>

#include "openiec61850/core/result.hpp"

namespace openiec61850::transport {

namespace detail {

// asio::co_spawn needs a default-constructible value type; result<T> is not.
template <typename T>
struct box {
  std::optional<T> value;
};

template <typename T>
asio::awaitable<box<T>> boxed(asio::awaitable<T> op) {
  co_return box<T>{std::optional<T>(co_await std::move(op))};
}

}  // namespace detail

// Bridges a coroutine returning result<T> to a plain completion handler: runs op on ex
// and calls handler(result<T>) on ex. An exception escaping op (only std::bad_alloc in
// this library) is reported as std::errc::not_enough_memory. The handler must not throw.
template <typename Executor, typename T, typename Handler>
void spawn(const Executor& ex, asio::awaitable<result<T>> op, Handler handler) {
  asio::co_spawn(ex, detail::boxed(std::move(op)),
                 [h = std::move(handler)](std::exception_ptr e, detail::box<result<T>> b) mutable {
                   if (e || !b.value) {
                     std::move(h)(result<T>(std::make_error_code(std::errc::not_enough_memory)));
                   } else {
                     std::move(h)(std::move(*b.value));
                   }
                 });
}

// Awaits op after running it on ex, resuming the caller on its own executor.
template <typename Executor, typename T>
asio::awaitable<T> run_on(const Executor& ex, asio::awaitable<T> op) {
  auto b = co_await asio::co_spawn(ex, detail::boxed(std::move(op)), asio::use_awaitable);
  co_return std::move(*b.value);
}

}  // namespace openiec61850::transport
