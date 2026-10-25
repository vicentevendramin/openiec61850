#include <nanobind/nanobind.h>
#include <nanobind/stl/string.h>

#include <string>

#include "bindings.hpp"
#include "convert.hpp"
#include "openiec61850/core/version.hpp"
#include "runtime.hpp"

namespace nb = nanobind;
namespace py = openiec61850::python;

NB_MODULE(_core, m) {
  m.doc() = "openiec61850 native core (internal; use the openiec61850 package)";
  m.attr("__version__") = std::string{openiec61850::version().string};
  // Operations still pending at exit keep their Python references on purpose (the stopped I/O
  // runtime is leaked rather than destroyed under a finalizing interpreter).
  nb::set_leak_warnings(false);

  nb::class_<py::deferred>(m, "_Deferred", "A finished native operation (internal).");
  m.def("_complete", &py::complete, nb::arg("future"), nb::arg("box"));
  py::set_complete_function(m.attr("_complete"));
  m.def("_set_error_factory", &py::set_error_factory, nb::arg("factory"),
        "Installs factory(category, value, message, details) -> BaseException.");
  m.def("_shutdown", &py::shutdown_runtime, "Stops the I/O thread (registered with atexit).");
  m.def(
      "_runtime_running", [] { return py::runtime().running(); },
      "Starts the I/O runtime if needed and reports whether it runs.");
  m.def(
      "_roundtrip", [](nb::handle v) { return py::data_to_py(py::data_from_py(v)); },
      nb::arg("value"), "Converts a tagged MMS value to native and back (testing aid).");
  m.def(
      "_encode", [](nb::handle v) {
        openiec61850::byte_buffer out;
        auto r = openiec61850::mms::encode_data(py::data_from_py(v), out);
        if (!r) throw nb::value_error(r.error().message().c_str());
        return py::to_bytes(out);
      },
      nb::arg("value"), "BER encoding of a tagged MMS value.");

  py::bind_model(m);
  py::bind_client(m);
  py::bind_server(m);

  nb::module_::import_("atexit").attr("register")(m.attr("_shutdown"));
}
