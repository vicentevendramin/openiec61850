#pragma once

#include <nanobind/nanobind.h>

#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <system_error>
#include <utility>
#include <vector>

#include "runtime.hpp"

// Push delivery of items produced on the I/O thread (GOOSE events, SV samples) to an asyncio loop,
// in batches and with flow control:
//
// - The producer (I/O thread, no GIL) appends to a bounded queue (the oldest item is dropped and
//   counted on overflow).
// - When the consumer has asked for items (request(), loop thread) and the queue is not empty, the
//   pending items (at most max_batch) are moved into a _Batch scheduled on the loop with
//   loop.call_soon_threadsafe(sink, batch). One batch at most is in flight: the consumer asks again
//   once it has used what it got, so a fast producer and a slow consumer give large batches and
//   few wake-ups, and a fast consumer gets every item as soon as it arrives.
// - The conversion to Python objects (_Batch.items()) runs on the loop thread; the I/O thread
//   holds the GIL only to schedule the batch.
// - Nothing is lost when the consumer gives up waiting (the items stay in the Python queue).

namespace openiec61850::python {

class batch_base {
 public:
  virtual ~batch_base() = default;
  // GIL held, loop thread.
  virtual nb::object items() = 0;
};

// Bound as _core._Batch.
struct py_batch {
  std::unique_ptr<batch_base> impl;
  bool ended = false;
  std::error_code error;
  std::uint64_t dropped = 0;  // items dropped by the pump queue so far

  nb::object items() {
    auto i = std::move(impl);
    if (!i) return nb::list();
    return i->items();
  }
};

template <typename Item, typename Convert>
class pump : public std::enable_shared_from_this<pump<Item, Convert>> {
 public:
  // GIL held, on a thread with a running loop.
  pump(nb::handle sink, std::size_t capacity, std::size_t max_batch, Convert convert)
      : sink_(sink),
        loop_(nb::module_::import_("asyncio").attr("get_running_loop")()),
        capacity_(capacity == 0 ? 1 : capacity),
        max_batch_(max_batch == 0 ? 1 : max_batch),
        convert_(std::move(convert)) {}

  // Any thread, without the GIL.
  void push(Item item) {
    std::unique_ptr<py_batch> b;
    {
      const std::lock_guard lock(mutex_);
      if (ended_) return;
      if (queue_.size() >= capacity_) {
        queue_.pop_front();
        ++dropped_;
      }
      queue_.push_back(std::move(item));
      if (armed_) b = take();
    }
    if (b) schedule(std::move(b), false);
  }

  // Ends the stream (after the queued items); `ec` empty: a clean end. Any thread, without the GIL.
  void end(std::error_code ec = {}) {
    std::unique_ptr<py_batch> b;
    {
      const std::lock_guard lock(mutex_);
      if (ended_) return;
      ended_ = true;
      error_ = ec;
      if (armed_) b = take();
    }
    if (b) schedule(std::move(b), false);
  }

  // The consumer wants more. GIL held, loop thread.
  void request() {
    std::unique_ptr<py_batch> b;
    {
      const std::lock_guard lock(mutex_);
      armed_ = true;
      if (!queue_.empty() || (ended_ && !end_sent_)) b = take();
    }
    if (b) schedule(std::move(b), true);
  }

  [[nodiscard]] std::uint64_t dropped() const {
    const std::lock_guard lock(mutex_);
    return dropped_;
  }

 private:
  class batch final : public batch_base {
   public:
    batch(std::vector<Item> v, Convert c) : v_(std::move(v)), c_(std::move(c)) {}
    nb::object items() override {
      nb::list out;
      for (auto& i : v_) out.append(c_(i));
      return out;
    }

   private:
    std::vector<Item> v_;
    Convert c_;
  };

  // Requires the mutex.
  std::unique_ptr<py_batch> take() {
    std::vector<Item> v;
    const std::size_t n = queue_.size() < max_batch_ ? queue_.size() : max_batch_;
    v.reserve(n);
    for (std::size_t i = 0; i < n; ++i) {
      v.push_back(std::move(queue_.front()));
      queue_.pop_front();
    }
    auto b = std::make_unique<py_batch>();
    b->impl = std::make_unique<batch>(std::move(v), convert_);
    b->dropped = dropped_;
    if (ended_ && queue_.empty()) {
      b->ended = true;
      b->error = error_;
      end_sent_ = true;
    }
    armed_ = false;
    return b;
  }

  void schedule(std::unique_ptr<py_batch> b, bool gil_held) {
    if (interpreter_finalizing()) {
      (void)b.release();
      return;
    }
    auto go = [&] {
      try {
        nb::object box = nb::cast(std::move(*b));
        nb::handle(loop_.get()).attr("call_soon_threadsafe")(nb::handle(sink_.get()), box);
      } catch (nb::python_error&) {
        // The loop is closed: nobody is listening any more.
      } catch (...) {
      }
    };
    if (gil_held) {
      go();
    } else {
      const nb::gil_scoped_acquire gil;
      go();
    }
  }

  py_ref sink_;
  py_ref loop_;
  const std::size_t capacity_;
  const std::size_t max_batch_;
  Convert convert_;

  mutable std::mutex mutex_;
  std::deque<Item> queue_;
  bool armed_ = true;
  bool ended_ = false;
  bool end_sent_ = false;
  std::error_code error_;
  std::uint64_t dropped_ = 0;
};

}  // namespace openiec61850::python
