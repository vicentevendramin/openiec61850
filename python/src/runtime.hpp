#pragma once

#include <nanobind/nanobind.h>

#include <exception>
#include <optional>
#include <type_traits>
#include <memory>
#include <system_error>
#include <utility>

#include <asio/bind_cancellation_slot.hpp>
#include <asio/bind_executor.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/co_spawn.hpp>
#include <asio/post.hpp>

#include "openiec61850/core/result.hpp"
#include "openiec61850/transport/io_runtime.hpp"
#include "openiec61850/transport/spawn.hpp"

// Threading model of the binding (ADR 0004):
//
// - One process-wide transport::io_runtime, started on first use, runs every client. Its thread
//   never runs Python code and holds the GIL only for the instant it takes to hand a finished
//   operation to the asyncio loop (loop.call_soon_threadsafe).
// - An operation started from Python creates an asyncio future on the running loop, then spawns
//   the C++ coroutine on the client's strand. Its completion handler (I/O thread) moves the
//   C++ result into a _Deferred box and schedules _complete(future, box) on the loop; the
//   conversion to Python objects runs there, on the loop thread.
// - Cancelling the future emits a terminal cancellation on the coroutine's cancellation slot (on
//   the strand); a result that arrives anyway is dropped.
// - Python references owned by C++ state (py_ref) may be released from any thread.

namespace openiec61850::python {

namespace nb = nanobind;

// The shared runtime, started lazily. Throws std::runtime_error after shutdown_runtime().
transport::io_runtime& runtime();
// Stops and joins the I/O thread (registered with atexit). The GIL is released while joining.
// The io_context is deliberately leaked: clients still referenced by Python post to it later.
void shutdown_runtime();

// True when the interpreter is gone or going (no Python API may be used).
bool interpreter_finalizing() noexcept;

// A strong reference that can be dropped from any thread (it takes the GIL to do so, or leaks
// the object once the interpreter is finalizing).
class py_ref {
 public:
  py_ref() noexcept = default;
  // GIL held.
  explicit py_ref(nb::handle h) noexcept : p_(h.ptr()) { Py_XINCREF(p_); }
  py_ref(py_ref&& o) noexcept : p_(std::exchange(o.p_, nullptr)) {}
  py_ref& operator=(py_ref&& o) noexcept {
    if (this != &o) {
      reset();
      p_ = std::exchange(o.p_, nullptr);
    }
    return *this;
  }
  py_ref(const py_ref&) = delete;
  py_ref& operator=(const py_ref&) = delete;
  ~py_ref() { reset(); }

  void reset() noexcept;
  [[nodiscard]] nb::handle get() const noexcept { return p_; }
  [[nodiscard]] explicit operator bool() const noexcept { return p_ != nullptr; }

 private:
  PyObject* p_ = nullptr;
};

// What _complete() does with a future: set_result(value) or set_exception(value).
struct outcome {
  bool ok = true;
  nb::object value;
};

// A finished C++ operation waiting to be converted on the loop thread.
class deferred_base {
 public:
  virtual ~deferred_base() = default;
  // GIL held, loop thread.
  virtual outcome produce() = 0;
};

// Bound as _core._Deferred.
struct deferred {
  std::unique_ptr<deferred_base> impl;
};

template <typename F>
class deferred_fn final : public deferred_base {
 public:
  explicit deferred_fn(F f) : f_(std::move(f)) {}
  outcome produce() override { return f_(); }

 private:
  F f_;
};

// An asyncio future plus its loop.
class completion {
 public:
  // GIL held, on a thread with a running loop (RuntimeError otherwise).
  completion();
  completion(const completion&) = delete;
  completion& operator=(const completion&) = delete;

  // GIL held.
  [[nodiscard]] nb::object future() const { return nb::borrow(future_.get()); }
  // Any thread, without the GIL. Schedules the conversion and resolution on the loop; dropped
  // when the loop is closed, the future already done or the interpreter finalizing.
  void resolve(std::unique_ptr<deferred_base> d) noexcept;

 private:
  py_ref loop_;
  py_ref future_;
};

// Called by the module init: the _complete function scheduled on the loops.
void set_complete_function(nb::handle fn);
// _complete(future, box).
void complete(nb::handle future, deferred& box);

// Builds the Python exception for an error code (via the factory installed from Python).
nb::object make_error(std::error_code ec);
void set_error_factory(nb::handle factory);

struct op_state {
  asio::cancellation_signal signal;
  bool done = false;  // strand only
};

// Starts `op` on `ex` (a strand) and returns an asyncio future resolved with convert(T&&)
// (called on the loop thread with the GIL held), or with the exception for the error.
template <typename Executor, typename T, typename Convert>
nb::object launch(const Executor& ex, asio::awaitable<result<T>> op, Convert convert) {
  auto c = std::make_shared<completion>();
  auto st = std::make_shared<op_state>();
  nb::object fut = c->future();

  auto on_done = nb::cpp_function([weak = std::weak_ptr<op_state>(st), ex](nb::handle f) {
    if (!nb::cast<bool>(f.attr("cancelled")())) return;
    if (auto s = weak.lock()) {
      asio::post(ex, [s] {
        if (!s->done) s->signal.emit(asio::cancellation_type::terminal);
      });
    }
  });
  fut.attr("add_done_callback")(on_done);

  auto handler = [c, st, convert = std::move(convert)](
                     std::exception_ptr e, transport::detail::box<result<T>> b) mutable {
    st->done = true;
    st->signal.slot().clear();
    std::optional<result<T>> r;
    if (e || !b.value) {
      r.emplace(std::make_error_code(std::errc::not_enough_memory));
    } else {
      r.emplace(std::move(*b.value));
    }
    auto fn = [r = std::move(r), convert = std::move(convert)]() mutable -> outcome {
      if (!r->has_value()) return {false, make_error(r->error())};
      if constexpr (std::is_void_v<T>) {
        return {true, convert()};
      } else {
        return {true, convert(std::move(r->value()))};
      }
    };
    c->resolve(std::make_unique<deferred_fn<decltype(fn)>>(std::move(fn)));
  };
  asio::co_spawn(ex, transport::detail::boxed(std::move(op)),
                 asio::bind_cancellation_slot(st->signal.slot(),
                                              asio::bind_executor(ex, std::move(handler))));
  return fut;
}

}  // namespace openiec61850::python
