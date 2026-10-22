#include "openiec61850/transport/io_runtime.hpp"

#include <utility>

namespace openiec61850::transport {

io_runtime::io_runtime() = default;

io_runtime::~io_runtime() {
  stop();
  if (thread_.joinable()) {
    if (running_in_this_thread()) {
      thread_.detach();
    } else {
      thread_.join();
    }
  }
}

void io_runtime::start() {
  if (thread_.joinable()) {
    {
      const std::lock_guard lock(mutex_);
      if (!stop_requested_) return;
    }
    if (running_in_this_thread()) return;
    thread_.join();
  }
  const std::lock_guard lock(mutex_);
  context_.restart();
  work_.emplace(asio::make_work_guard(context_));
  stop_requested_ = false;
  thread_ = std::thread([this] { run(); });
}

void io_runtime::stop() noexcept {
  const std::lock_guard lock(mutex_);
  stop_requested_ = true;
  work_.reset();
  context_.stop();
}

void io_runtime::join() {
  if (!thread_.joinable() || running_in_this_thread()) return;
  thread_.join();
}

bool io_runtime::running() const noexcept {
  const std::lock_guard lock(mutex_);
  return thread_.joinable() && !stop_requested_;
}

bool io_runtime::running_in_this_thread() const noexcept {
  return context_.get_executor().running_in_this_thread();
}

std::exception_ptr io_runtime::take_exception() {
  const std::lock_guard lock(mutex_);
  return std::exchange(exception_, nullptr);
}

void io_runtime::run() {
  for (;;) {
    try {
      context_.run();
      return;
    } catch (...) {
      const std::lock_guard lock(mutex_);
      if (!exception_) exception_ = std::current_exception();
    }
  }
}

}  // namespace openiec61850::transport
