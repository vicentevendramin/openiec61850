#pragma once

#include <exception>
#include <mutex>
#include <optional>
#include <thread>

#include <asio/executor_work_guard.hpp>
#include <asio/io_context.hpp>

namespace openiec61850::transport {

// Owns an io_context and the single dedicated I/O thread that runs it (ADR 0004).
//
// Threading model:
// - Every I/O object created on get_executor() (channels, listeners, timers) is driven
//   only by the I/O thread; each channel/listener additionally serialises its state on
//   its own strand, so the model also holds if the context is ever run by more threads.
// - Work is handed to the I/O thread with asio::post/dispatch/co_spawn on get_executor(),
//   which are safe from any thread. Completions (coroutine resumptions and the callback
//   API of cotp_channel) run on the I/O thread, never on the caller's thread, so a
//   language binding can wait for them without holding its interpreter lock and only
//   re-acquire it inside the callback to hand the result over (e.g. to an event loop).
// - start(), join() and the destructor are meant for the owning thread; stop() is safe
//   from any thread, including from inside a handler on the I/O thread.
// - I/O objects must be destroyed (or at least closed) before the runtime. Handlers still
//   queued when the runtime is destroyed are destroyed without being invoked.
class io_runtime {
 public:
  using executor_type = asio::io_context::executor_type;

  io_runtime();
  // Stops and joins (detaches if destroyed from the I/O thread itself).
  ~io_runtime();

  io_runtime(const io_runtime&) = delete;
  io_runtime& operator=(const io_runtime&) = delete;

  // Starts the I/O thread. No-op while running; after stop() and join() it restarts
  // the context, keeping handlers that were posted in between.
  void start();

  // Stops the context: the I/O thread returns as soon as the current handler finishes,
  // pending handlers are abandoned. Idempotent.
  void stop() noexcept;

  // Waits for the I/O thread to exit. No-op if not started or called from the I/O thread.
  void join();

  [[nodiscard]] bool running() const noexcept;
  [[nodiscard]] bool running_in_this_thread() const noexcept;

  [[nodiscard]] executor_type get_executor() noexcept { return context_.get_executor(); }
  [[nodiscard]] asio::io_context& context() noexcept { return context_; }

  // A handler that threw does not kill the I/O thread: the first exception is kept here
  // and the thread keeps running. Returns and clears it.
  [[nodiscard]] std::exception_ptr take_exception();

 private:
  void run();

  mutable asio::io_context context_{1};
  mutable std::mutex mutex_;
  std::optional<asio::executor_work_guard<executor_type>> work_;
  std::thread thread_;
  bool stop_requested_ = false;
  std::exception_ptr exception_;
};

}  // namespace openiec61850::transport
