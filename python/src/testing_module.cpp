// openiec61850._testing: the C++ fake server of tests/client exposed to the Python tests. Built
// only with OPENIEC61850_BUILD_PYTHON_TESTING=ON and never shipped in release wheels.
//
// The server runs on its own io_runtime (its own I/O thread), as a separate process would; every
// method is executed there and waited for with the GIL released.

#include <nanobind/nanobind.h>
#include <nanobind/stl/optional.h>
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>

#include <chrono>
#include <exception>
#include <future>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

#include <asio/post.hpp>

#include "convert.hpp"
#include "fake_server.hpp"
#include "openiec61850/iso/acse/apdu.hpp"
#include "openiec61850/transport/io_runtime.hpp"

namespace nb = nanobind;
namespace py = openiec61850::python;

namespace {

using openiec61850::mms::data;
namespace testing = openiec61850::testing;

class fake_server_host {
 public:
  fake_server_host(std::size_t name_list_page, std::optional<std::string> password) {
    runtime_.start();
    testing::fake_server_options o;
    o.name_list_page = name_list_page;
    if (password) {
      o.association.authorize = [pw = *password](const openiec61850::association::association_request& r,
                                                 openiec61850::mms::initiate_response&) {
        if (r.password == pw) return openiec61850::association::association_decision::accepted();
        return openiec61850::association::association_decision::rejected(
            openiec61850::iso::acse::service_user_diagnostic::authentication_failure);
      };
    }
    run([&] {
      server_ = std::make_unique<testing::fake_server>(runtime_.get_executor(), std::move(o));
      auto r = server_->start();
      if (!r) throw std::runtime_error("fake server: " + r.error().message());
    });
  }

  fake_server_host(const fake_server_host&) = delete;
  fake_server_host& operator=(const fake_server_host&) = delete;
  ~fake_server_host() { close(); }

  void close() {
    if (!server_) return;
    run([&] {
      server_->stop();
      server_.reset();
    });
    {
      // Let the aborted associations finish their coroutines before stopping the thread.
      const nb::gil_scoped_release release;
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
      runtime_.stop();
      runtime_.join();
    }
  }

  [[nodiscard]] std::uint16_t port() { return run([&] { return srv().port(); }); }
  void stop() {
    run([&] { srv().stop(); });
  }
  void drop_connections() {
    run([&] { srv().drop_connections(); });
  }
  std::size_t associations_accepted() { return run([&] { return srv().associations_accepted(); }); }
  std::size_t active_associations() { return run([&] { return srv().active_associations(); }); }
  std::size_t requests(int service) {
    return run([&] { return srv().requests(static_cast<openiec61850::mms::confirmed_service>(service)); });
  }
  std::vector<std::string> write_log() { return run([&] { return srv().write_log(); }); }
  void clear_write_log() {
    run([&] { srv().clear_write_log(); });
  }
  nb::object value(const std::string& domain, const std::string& item) {
    auto v = run([&] { return srv().value(domain, item); });
    if (!v) return nb::none();
    return py::data_to_py(*v);
  }
  bool set_value(const std::string& domain, const std::string& item, nb::handle value) {
    auto v = py::data_from_py(value);
    return run([&] { return srv().set_value(domain, item, std::move(v)); });
  }
  bool update(const std::string& item, nb::handle value, std::uint8_t reason) {
    auto v = py::data_from_py(value);
    const auto r = openiec61850::model::trigger_conditions::from_raw(reason);
    return run([&] { return srv().update(item, std::move(v), r); });
  }
  void send_report(nb::handle values) {
    std::vector<data> v;
    for (nb::handle h : values) v.push_back(py::data_from_py(h));
    run([&] { srv().send_report(std::move(v)); });
  }
  void hold_requests(bool on) {
    run([&] { srv().hold_requests(on); });
  }
  bool set_interlocked(const std::string& object, bool on) {
    return run([&] { return srv().set_interlocked(object, on); });
  }
  bool set_synchrocheck_blocked(const std::string& object, bool on) {
    return run([&] { return srv().set_synchrocheck_blocked(object, on); });
  }
  bool set_command_termination(const std::string& object, const std::string& mode,
                               std::int16_t add_cause, double delay) {
    using tm = testing::fake_server::termination_mode;
    tm m = tm::positive;
    if (mode == "negative") {
      m = tm::negative;
    } else if (mode == "none") {
      m = tm::none;
    } else if (mode != "positive") {
      throw nb::value_error("mode is 'positive', 'negative' or 'none'");
    }
    const auto ms = std::chrono::milliseconds(static_cast<std::int64_t>(delay * 1000.0));
    return run([&] { return srv().set_command_termination(object, m, add_cause, ms); });
  }
  std::size_t operations(const std::string& object) {
    return run([&] { return srv().operations(object); });
  }
  std::size_t cancellations(const std::string& object) {
    return run([&] { return srv().cancellations(object); });
  }
  bool selected(const std::string& object) {
    return run([&] { return srv().selected(object); });
  }
  nb::object last_control_request(const std::string& object) {
    auto v = run([&] { return srv().last_control_request(object); });
    if (!v) return nb::none();
    return py::data_to_py(*v);
  }
  // A Confirmed-ErrorPDU when error_class is given, else a RejectPDU with reject_reason.
  void fail_next(int service, std::optional<int> error_class, std::int64_t error_code,
                 std::optional<std::int64_t> additional_code,
                 std::optional<std::string> additional_description,
                 std::optional<std::uint32_t> modifier_position, std::int64_t reject_reason) {
    testing::fake_server::injected_failure f;
    if (error_class) {
      openiec61850::association::service_error_info e;
      e.cls = static_cast<openiec61850::mms::error_class>(*error_class);
      e.code = error_code;
      e.additional_code = additional_code;
      e.additional_description = std::move(additional_description);
      f.error = std::move(e);
      f.modifier_position = modifier_position;
    }
    f.reject_reason = reject_reason;
    run([&] {
      srv().fail_next(static_cast<openiec61850::mms::confirmed_service>(service), std::move(f));
    });
  }
  std::size_t buffered_entries(const std::string& brcb) {
    return run([&] { return srv().buffered_entries(brcb); });
  }
  bool rcb_enabled(const std::string& rcb) {
    return run([&] { return srv().rcb_enabled(rcb); });
  }

 private:
  testing::fake_server& srv() {
    if (!server_) throw std::runtime_error("fake server closed");
    return *server_;
  }

  // Runs f on the server thread and waits for it without holding the GIL.
  template <typename F>
  auto run(F f) -> std::invoke_result_t<F&> {
    using R = std::invoke_result_t<F&>;
    std::promise<R> p;
    auto done = p.get_future();
    asio::post(runtime_.get_executor(), [&] {
      try {
        if constexpr (std::is_void_v<R>) {
          f();
          p.set_value();
        } else {
          p.set_value(f());
        }
      } catch (...) {
        p.set_exception(std::current_exception());
      }
    });
    const nb::gil_scoped_release release;
    return done.get();
  }

  openiec61850::transport::io_runtime runtime_;
  std::unique_ptr<testing::fake_server> server_;
};

}  // namespace

NB_MODULE(_testing, m) {
  m.doc() = "Test-only fake IEC 61850 server (not part of the public API)";
  nb::class_<fake_server_host>(m, "FakeServer")
      .def(nb::init<std::size_t, std::optional<std::string>>(), nb::arg("name_list_page") = 0,
           nb::arg("password") = nb::none())
      .def("close", &fake_server_host::close)
      .def_prop_ro("port", &fake_server_host::port)
      .def("stop", &fake_server_host::stop)
      .def("drop_connections", &fake_server_host::drop_connections)
      .def_prop_ro("associations_accepted", &fake_server_host::associations_accepted)
      .def_prop_ro("active_associations", &fake_server_host::active_associations)
      .def("requests", &fake_server_host::requests, nb::arg("service"))
      .def("write_log", &fake_server_host::write_log)
      .def("clear_write_log", &fake_server_host::clear_write_log)
      .def("value", &fake_server_host::value, nb::arg("domain"), nb::arg("item"))
      .def("set_value", &fake_server_host::set_value, nb::arg("domain"), nb::arg("item"),
           nb::arg("value"))
      .def("update", &fake_server_host::update, nb::arg("item"), nb::arg("value"),
           nb::arg("reason") = 2)
      .def("send_report", &fake_server_host::send_report, nb::arg("values"))
      .def("hold_requests", &fake_server_host::hold_requests, nb::arg("on"))
      .def("set_interlocked", &fake_server_host::set_interlocked, nb::arg("object"), nb::arg("on"))
      .def("set_synchrocheck_blocked", &fake_server_host::set_synchrocheck_blocked, nb::arg("object"),
           nb::arg("on"))
      .def("set_command_termination", &fake_server_host::set_command_termination, nb::arg("object"),
           nb::arg("mode"), nb::arg("add_cause") = 16, nb::arg("delay") = 0.005)
      .def("operations", &fake_server_host::operations, nb::arg("object"))
      .def("cancellations", &fake_server_host::cancellations, nb::arg("object"))
      .def("selected", &fake_server_host::selected, nb::arg("object"))
      .def("last_control_request", &fake_server_host::last_control_request, nb::arg("object"))
      .def("fail_next", &fake_server_host::fail_next, nb::arg("service"), nb::arg("error_class") = nb::none(),
           nb::arg("error_code") = 0, nb::arg("additional_code") = nb::none(),
           nb::arg("additional_description") = nb::none(), nb::arg("modifier_position") = nb::none(),
           nb::arg("reject_reason") = 0)
      .def("buffered_entries", &fake_server_host::buffered_entries, nb::arg("brcb"))
      .def("rcb_enabled", &fake_server_host::rcb_enabled, nb::arg("rcb"));
}
