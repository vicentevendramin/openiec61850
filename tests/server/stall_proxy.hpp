#pragma once

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>

#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/write.hpp>

#include <malloc.h>

#if defined(__SANITIZE_ADDRESS__) || defined(__SANITIZE_THREAD__)
#define OPENIEC61850_TEST_SANITIZER 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer) || __has_feature(thread_sanitizer)
#define OPENIEC61850_TEST_SANITIZER 1
#endif
#endif
#ifdef OPENIEC61850_TEST_SANITIZER
#include <sanitizer/allocator_interface.h>
#endif

namespace server_test {

// Bytes the application holds, so that allocator caches and sanitizer quarantines do not count.
inline std::size_t live_bytes() {
#ifdef OPENIEC61850_TEST_SANITIZER
  return __sanitizer_get_current_allocated_bytes();
#else
  return mallinfo2().uordblks;
#endif
}

// A TCP relay between one client and a server, to play a peer that stops reading its socket: the
// client associates normally (plain or TLS, the relay does not care), and after stall() nothing
// more is read from the server, whose writes then block once the kernel buffers are full. What
// the client sends still goes through. It runs on its own thread, so that the stall is as
// independent of the library as a remote host would be.
class stall_proxy {
 public:
  explicit stall_proxy(asio::ip::tcp::endpoint server)
      : server_(server), acceptor_(io_, {asio::ip::address_v4::loopback(), 0}) {
    asio::co_spawn(io_, serve(), asio::detached);
    thread_ = std::thread([this] { io_.run(); });
  }
  ~stall_proxy() {
    io_.stop();
    thread_.join();
  }
  stall_proxy(const stall_proxy&) = delete;
  stall_proxy& operator=(const stall_proxy&) = delete;

  [[nodiscard]] std::uint16_t port() const { return acceptor_.local_endpoint().port(); }
  void stall() { stalled_ = true; }
  void resume() { stalled_ = false; }
  // The same towards the client: nothing more is read from it.
  void stall_client() { client_stalled_ = true; }
  // Bytes read from the server so far.
  [[nodiscard]] std::uint64_t delivered() const { return delivered_.load(); }

  // The last chunk the client sent: replaying it floods the server with that very request.
  [[nodiscard]] std::vector<std::uint8_t> last_request() const {
    const std::lock_guard lock(mutex_);
    return last_;
  }
  // Writes `bytes` to the server `times` times, as the client would, as fast as it takes them.
  void flood(std::vector<std::uint8_t> bytes, std::size_t times) {
    asio::co_spawn(io_, flood_op(up_, std::move(bytes), times), asio::detached);
  }
  // The last chunk the server sent, and the same flood towards the client.
  [[nodiscard]] std::vector<std::uint8_t> last_response() const {
    const std::lock_guard lock(mutex_);
    return last_response_;
  }
  void flood_client(std::vector<std::uint8_t> bytes, std::size_t times) {
    asio::co_spawn(io_, flood_op(down_, std::move(bytes), times), asio::detached);
  }
  // Copies of the request taken by the server's socket so far.
  [[nodiscard]] std::uint64_t flooded() const { return flooded_.load(); }
  // The server closed the connection (seen only when not stalled, or by a failed flood).
  [[nodiscard]] bool server_gone() const { return server_gone_.load(); }

 private:
  using tcp = asio::ip::tcp;
  static constexpr auto use_tuple = asio::as_tuple(asio::use_awaitable);

  asio::awaitable<void> serve() {
    auto [ec, down] = co_await acceptor_.async_accept(use_tuple);
    if (ec) co_return;
    down_ = std::move(down);
    std::error_code ignored;
    up_.open(tcp::v4(), ignored);
    up_.set_option(asio::socket_base::receive_buffer_size(4096), ignored);
    auto [cec] = co_await up_.async_connect(server_, use_tuple);
    if (cec) co_return;
    up_.set_option(tcp::no_delay(true), ignored);
    down_.set_option(tcp::no_delay(true), ignored);
    asio::co_spawn(io_, client_to_server(), asio::detached);
    asio::co_spawn(io_, server_to_client(), asio::detached);
  }

  asio::awaitable<void> client_to_server() {
    std::vector<std::uint8_t> buffer(65536);
    asio::steady_timer pause(io_);
    for (;;) {
      if (client_stalled_) {
        pause.expires_after(std::chrono::milliseconds(1));
        (void)co_await pause.async_wait(use_tuple);
        continue;
      }
      auto [ec, n] = co_await down_.async_read_some(asio::buffer(buffer), use_tuple);
      if (ec) break;
      {
        const std::lock_guard lock(mutex_);
        last_.assign(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(n));
      }
      auto [wec, w] = co_await asio::async_write(up_, asio::buffer(buffer, n), use_tuple);
      (void)w;
      if (wec) break;
    }
    std::error_code ignored;
    up_.shutdown(tcp::socket::shutdown_send, ignored);
  }

  asio::awaitable<void> server_to_client() {
    std::vector<std::uint8_t> buffer(65536);
    asio::steady_timer pause(io_);
    for (;;) {
      if (stalled_) {
        pause.expires_after(std::chrono::milliseconds(1));
        (void)co_await pause.async_wait(use_tuple);
        continue;
      }
      auto [ec, n] = co_await up_.async_read_some(asio::buffer(buffer), use_tuple);
      if (ec) break;
      delivered_.fetch_add(n);
      {
        const std::lock_guard lock(mutex_);
        last_response_.assign(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(n));
      }
      auto [wec, w] = co_await asio::async_write(down_, asio::buffer(buffer, n), use_tuple);
      (void)w;
      if (wec) break;
    }
    server_gone_ = true;
    std::error_code ignored;
    down_.close(ignored);
  }

  asio::awaitable<void> flood_op(tcp::socket& to, std::vector<std::uint8_t> bytes,
                                 std::size_t times) {
    for (std::size_t i = 0; i < times; ++i) {
      auto [ec, w] = co_await asio::async_write(to, asio::buffer(bytes), use_tuple);
      (void)w;
      if (ec) {
        server_gone_ = true;
        co_return;
      }
      flooded_.fetch_add(1);
    }
  }

  asio::io_context io_;
  asio::ip::tcp::endpoint server_;
  tcp::acceptor acceptor_;
  tcp::socket down_{io_};
  tcp::socket up_{io_};
  std::thread thread_;
  std::atomic<bool> stalled_{false};
  std::atomic<bool> client_stalled_{false};
  std::atomic<bool> server_gone_{false};
  std::atomic<std::uint64_t> delivered_{0};
  std::atomic<std::uint64_t> flooded_{0};
  mutable std::mutex mutex_;
  std::vector<std::uint8_t> last_;
  std::vector<std::uint8_t> last_response_;
};

}  // namespace server_test
