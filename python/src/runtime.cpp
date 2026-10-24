#include "runtime.hpp"

#include <nanobind/stl/string.h>

#include <optional>

#include <mutex>
#include <stdexcept>
#include <string>

namespace openiec61850::python {

namespace {

std::mutex runtime_mutex;
transport::io_runtime* shared_runtime = nullptr;
bool runtime_shut_down = false;

// Leaked strong references, set once by the module init.
PyObject* complete_fn = nullptr;
PyObject* error_factory = nullptr;

}  // namespace

transport::io_runtime& runtime() {
  const std::lock_guard lock(runtime_mutex);
  if (runtime_shut_down) throw std::runtime_error("the openiec61850 runtime has been shut down");
  if (shared_runtime == nullptr) shared_runtime = new transport::io_runtime();  // NOLINT: leaked
  if (!shared_runtime->running()) shared_runtime->start();
  return *shared_runtime;
}

void shutdown_runtime() {
  transport::io_runtime* rt = nullptr;
  {
    const std::lock_guard lock(runtime_mutex);
    runtime_shut_down = true;
    rt = shared_runtime;
  }
  if (rt == nullptr) return;
  // A completion handler may be waiting for the GIL on the I/O thread.
  const nb::gil_scoped_release release;
  rt->stop();
  rt->join();
}

bool interpreter_finalizing() noexcept {
  if (Py_IsInitialized() == 0) return true;
#if PY_VERSION_HEX >= 0x030D0000
  return Py_IsFinalizing() != 0;
#else
  return _Py_IsFinalizing() != 0;
#endif
}

void py_ref::reset() noexcept {
  PyObject* p = std::exchange(p_, nullptr);
  if (p == nullptr || interpreter_finalizing()) return;
  const PyGILState_STATE s = PyGILState_Ensure();
  Py_DECREF(p);
  PyGILState_Release(s);
}

completion::completion() {
  nb::object loop = nb::module_::import_("asyncio").attr("get_running_loop")();
  nb::object fut = loop.attr("create_future")();
  loop_ = py_ref(loop);
  future_ = py_ref(fut);
}

void completion::resolve(std::unique_ptr<deferred_base> d) noexcept {
  if (interpreter_finalizing()) {
    // Leak rather than touch a dying interpreter.
    (void)d.release();
    return;
  }
  const nb::gil_scoped_acquire gil;
  try {
    nb::object box = nb::cast(deferred{std::move(d)});
    nb::handle(loop_.get()).attr("call_soon_threadsafe")(nb::handle(complete_fn),
                                                        nb::handle(future_.get()), box);
  } catch (nb::python_error&) {
    // The loop is closed: nobody is waiting any more.
  } catch (...) {
  }
  loop_.reset();
  future_.reset();
}

void set_complete_function(nb::handle fn) {
  Py_XINCREF(fn.ptr());
  complete_fn = fn.ptr();
}

void complete(nb::handle future, deferred& box) {
  auto impl = std::move(box.impl);
  if (!impl || nb::cast<bool>(future.attr("done")())) return;
  outcome o;
  try {
    o = impl->produce();
  } catch (nb::python_error& e) {
    o = {false, nb::borrow(e.value())};
  } catch (const std::exception& e) {
    o = {false, nb::handle(PyExc_RuntimeError)(nb::str(e.what()))};
  }
  // The future must be resolved whatever happens, or its awaiter would wait forever.
  try {
    future.attr(o.ok ? "set_result" : "set_exception")(o.value);
  } catch (nb::python_error& e) {
    future.attr("set_exception")(nb::borrow(e.value()));
  }
}

void set_error_factory(nb::handle factory) {
  Py_XINCREF(factory.ptr());
  Py_XDECREF(error_factory);
  error_factory = factory.ptr();
}

namespace {

template <typename T>
nb::object opt(const std::optional<T>& v) {
  return v ? nb::cast(*v) : nb::none();
}

}  // namespace

nb::object error_details_to_py(const client::error_details& d) {
  if (!d.from_server()) return nb::none();
  nb::dict o;
  o["error_class"] = d.service_error ? nb::cast(static_cast<int>(d.service_error->cls)) : nb::none();
  o["error_code"] = d.service_error ? nb::cast(d.service_error->code) : nb::none();
  o["additional_code"] = d.service_error ? opt(d.service_error->additional_code) : nb::none();
  o["additional_description"] =
      d.service_error ? opt(d.service_error->additional_description) : nb::none();
  o["modifier_position"] = opt(d.modifier_position);
  o["reject_type"] = d.reject ? nb::cast(static_cast<int>(d.reject->type)) : nb::none();
  o["reject_reason"] = d.reject ? nb::cast(d.reject->reason) : nb::none();
  o["original_invoke_id"] = d.reject ? opt(d.reject->original_invoke_id) : nb::none();
  if (d.last_appl_error) {
    const auto& e = *d.last_appl_error;
    const auto& id = e.origin.identifier;
    o["last_appl_error"] = nb::make_tuple(
        e.control_object, static_cast<int>(e.error),
        nb::make_tuple(static_cast<int>(e.origin.category),
                       nb::bytes(reinterpret_cast<const char*>(id.data()), id.size())),
        static_cast<int>(e.ctl_num), static_cast<int>(e.cause));
  } else {
    o["last_appl_error"] = nb::none();
  }
  return o;
}

nb::object make_error(std::error_code ec, const client::error_details* details) {
  const std::string category = ec.category().name();
  const std::string message = ec.message();
  if (error_factory == nullptr) {
    return nb::handle(PyExc_RuntimeError)(nb::str((category + ": " + message).c_str()));
  }
  return nb::handle(error_factory)(nb::str(category.c_str()), ec.value(), nb::str(message.c_str()),
                                   details != nullptr ? error_details_to_py(*details) : nb::none());
}

}  // namespace openiec61850::python
