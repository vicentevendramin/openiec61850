// _core.Client: the native ACSI client. Every service returns an asyncio future (see runtime.hpp);
// arguments and results are the plain values of convert.hpp.

#include <nanobind/nanobind.h>
#include <nanobind/stl/optional.h>
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>

#include <string>
#include <utility>
#include <vector>

#include <asio/strand.hpp>

#include "bindings.hpp"
#include "convert.hpp"
#include "openiec61850/client/client.hpp"
#include "runtime.hpp"

namespace openiec61850::python {

namespace {

nb::object to_py_strings(std::vector<std::string> v) { return nb::cast(std::move(v)); }

nb::object read_results_to_py(std::vector<result<mms::data>> v) {
  nb::list out;
  for (auto& r : v) {
    if (r) {
      out.append(nb::make_tuple(true, data_to_py(*r)));
    } else {
      out.append(nb::make_tuple(false, make_error(r.error())));
    }
  }
  return out;
}

nb::object write_results_to_py(std::vector<result<void>> v) {
  nb::list out;
  for (auto& r : v) out.append(r ? nb::none() : make_error(r.error()));
  return out;
}

const char* state_name(client::connection_state s) {
  switch (s) {
    case client::connection_state::established: return "established";
    case client::connection_state::reconnecting: return "reconnecting";
    case client::connection_state::closing: return "closing";
    case client::connection_state::closed: return "closed";
  }
  return "closed";
}

struct closed_reason {
  std::error_code ec;
};

asio::awaitable<result<closed_reason>> wait_closed_op(asio::awaitable<std::error_code> op) {
  co_return closed_reason{co_await std::move(op)};
}

class native_client {
 public:
  explicit native_client(client::client c) : c_(std::move(c)) {
    parse_ = {model::name_limits::for_edition(c_.options().edition), false};
  }

  static nb::object connect(nb::handle options) {
    auto opts = client_options_from_py(options);
    auto ex = runtime().get_executor();
    auto strand = asio::make_strand(asio::any_io_executor(ex));
    return launch(strand, client::client::connect(ex, std::move(opts)),
                  [](client::client c) { return nb::cast(native_client(std::move(c))); });
  }

  nb::object release() {
    return launch(c_.get_executor(), c_.release(), [] { return nb::none(); });
  }
  void abort() noexcept { c_.abort(); }
  nb::object wait_closed() {
    return launch(c_.get_executor(), wait_closed_op(c_.wait_closed()),
                  [](closed_reason r) { return make_error(r.ec); });
  }
  [[nodiscard]] std::string state() const { return state_name(c_.state()); }
  [[nodiscard]] nb::object association_info() const {
    return association_info_to_py(c_.association_info());
  }
  [[nodiscard]] int edition() const { return static_cast<int>(c_.options().edition); }

  nb::object server_directory() {
    return launch(c_.get_executor(), c_.get_server_directory(), to_py_strings);
  }
  nb::object logical_device_directory(std::string ld) {
    return launch(c_.get_executor(), c_.get_logical_device_directory(std::move(ld)), to_py_strings);
  }
  nb::object logical_node_directory(nb::handle ln) {
    return launch(c_.get_executor(), c_.get_logical_node_directory(ref(ln)),
                  [](client::logical_node_directory d) { return directory_to_py(d); });
  }
  nb::object data_directory(nb::handle r) {
    return launch(c_.get_executor(), c_.get_data_directory(ref(r)),
                  [](std::vector<client::data_directory_entry> v) {
                    nb::list out;
                    for (const auto& e : v) {
                      nb::list fcs;
                      for (auto f : e.fcs) fcs.append(std::string(model::to_string(f)));
                      out.append(nb::make_tuple(e.name, fcs));
                    }
                    return nb::object(std::move(out));
                  });
  }
  nb::object data_definition(nb::handle r) {
    return launch(c_.get_executor(), c_.get_data_definition(ref(r)),
                  [](client::data_definition d) { return definition_to_py(d); });
  }
  nb::object name_list(int cls, std::string domain) {
    if (cls < 0 || cls > 11) throw nb::value_error("unknown MMS object class");
    return launch(c_.get_executor(),
                  c_.get_name_list(static_cast<mms::object_class>(cls), std::move(domain)),
                  to_py_strings);
  }

  nb::object read(nb::handle r) {
    return launch(c_.get_executor(), c_.read(ref(r)),
                  [](mms::data d) { return data_to_py(d); });
  }
  nb::object read_many(nb::handle refs) {
    return launch(c_.get_executor(), c_.read_many(refs_of(refs)), read_results_to_py);
  }
  nb::object write(nb::handle r, nb::handle value) {
    return launch(c_.get_executor(), c_.write(ref(r), data_from_py(value)),
                  [] { return nb::none(); });
  }
  nb::object write_many(nb::handle items) {
    std::vector<client::write_item> v;
    for (nb::handle it : items) {
      const auto t = nb::cast<nb::tuple>(it);
      v.push_back({ref(t[0]), data_from_py(t[1])});
    }
    return launch(c_.get_executor(), c_.write_many(std::move(v)), write_results_to_py);
  }

  nb::object data_set_directory(nb::handle ds) {
    return launch(c_.get_executor(), c_.get_data_set_directory(ref(ds)),
                  [](client::data_set_directory d) {
                    nb::list members;
                    for (const auto& m : d.members) members.append(ref_to_py(m));
                    return nb::object(nb::make_tuple(members, d.deletable));
                  });
  }
  nb::object create_data_set(nb::handle ds, nb::handle members) {
    return launch(c_.get_executor(), c_.create_data_set(ref(ds), refs_of(members)),
                  [] { return nb::none(); });
  }
  nb::object delete_data_set(nb::handle ds) {
    return launch(c_.get_executor(), c_.delete_data_set(ref(ds)), [] { return nb::none(); });
  }
  nb::object data_set_values(nb::handle ds) {
    return launch(c_.get_executor(), c_.get_data_set_values(ref(ds)), read_results_to_py);
  }
  nb::object set_data_set_values(nb::handle ds, nb::handle values) {
    std::vector<mms::data> v;
    for (nb::handle x : values) v.push_back(data_from_py(x));
    return launch(c_.get_executor(), c_.set_data_set_values(ref(ds), std::move(v)),
                  write_results_to_py);
  }

  nb::object rcb_values(nb::handle rcb) {
    return launch(c_.get_executor(), c_.get_rcb_values(ref(rcb)),
                  [](client::rcb_values v) { return rcb_values_to_py(v); });
  }
  nb::object set_rcb_values(nb::handle rcb, nb::handle settings) {
    return launch(c_.get_executor(), c_.set_rcb_values(ref(rcb), rcb_settings_from_py(settings, parse_)),
                  [] { return nb::none(); });
  }
  nb::object enable_reporting(nb::handle rcb, nb::handle settings) {
    return launch(c_.get_executor(),
                  c_.enable_reporting(ref(rcb), report_settings_from_py(settings, parse_)),
                  [](client::rcb_values v) { return rcb_values_to_py(v); });
  }
  nb::object disable_reporting(nb::handle rcb) {
    return launch(c_.get_executor(), c_.disable_reporting(ref(rcb)), [] { return nb::none(); });
  }
  nb::object trigger_gi(nb::handle rcb) {
    return launch(c_.get_executor(), c_.trigger_gi(ref(rcb)), [] { return nb::none(); });
  }
  nb::object last_entry_id(nb::handle rcb) {
    const auto id = c_.last_entry_id(ref(rcb));
    if (!id) return nb::none();
    return to_bytes(id->bytes());
  }
  nb::object next_report() {
    return launch(c_.get_executor(), c_.next_report(),
                  [](client::report r) { return report_to_py(r); });
  }
  [[nodiscard]] std::uint64_t reports_dropped() const noexcept { return c_.reports_dropped(); }
  nb::object next_event() {
    return launch(c_.get_executor(), c_.next_event(),
                  [](client::connection_event e) { return event_to_py(e); });
  }

 private:
  model::object_reference ref(nb::handle h) const { return ref_from_py(h, parse_); }
  std::vector<model::object_reference> refs_of(nb::handle seq) const {
    std::vector<model::object_reference> v;
    for (nb::handle h : seq) v.push_back(ref(h));
    return v;
  }

  client::client c_;
  model::parse_options parse_;
};

}  // namespace

void bind_client(nb::module_& m) {
  nb::class_<native_client>(m, "Client",
                            "Native ACSI client. Use openiec61850.Client instead; every service "
                            "returns an asyncio future.")
      .def_static("connect", &native_client::connect, nb::arg("options"))
      .def("release", &native_client::release)
      .def("abort", &native_client::abort)
      .def("wait_closed", &native_client::wait_closed)
      .def_prop_ro("state", &native_client::state)
      .def_prop_ro("edition", &native_client::edition)
      .def("association_info", &native_client::association_info)
      .def("server_directory", &native_client::server_directory)
      .def("logical_device_directory", &native_client::logical_device_directory, nb::arg("ld"))
      .def("logical_node_directory", &native_client::logical_node_directory, nb::arg("ln"))
      .def("data_directory", &native_client::data_directory, nb::arg("ref"))
      .def("data_definition", &native_client::data_definition, nb::arg("ref"))
      .def("name_list", &native_client::name_list, nb::arg("object_class"), nb::arg("domain") = "")
      .def("read", &native_client::read, nb::arg("ref"))
      .def("read_many", &native_client::read_many, nb::arg("refs"))
      .def("write", &native_client::write, nb::arg("ref"), nb::arg("value"))
      .def("write_many", &native_client::write_many, nb::arg("items"))
      .def("data_set_directory", &native_client::data_set_directory, nb::arg("data_set"))
      .def("create_data_set", &native_client::create_data_set, nb::arg("data_set"), nb::arg("members"))
      .def("delete_data_set", &native_client::delete_data_set, nb::arg("data_set"))
      .def("data_set_values", &native_client::data_set_values, nb::arg("data_set"))
      .def("set_data_set_values", &native_client::set_data_set_values, nb::arg("data_set"),
           nb::arg("values"))
      .def("rcb_values", &native_client::rcb_values, nb::arg("rcb"))
      .def("set_rcb_values", &native_client::set_rcb_values, nb::arg("rcb"), nb::arg("settings"))
      .def("enable_reporting", &native_client::enable_reporting, nb::arg("rcb"), nb::arg("settings"))
      .def("disable_reporting", &native_client::disable_reporting, nb::arg("rcb"))
      .def("trigger_gi", &native_client::trigger_gi, nb::arg("rcb"))
      .def("last_entry_id", &native_client::last_entry_id, nb::arg("rcb"))
      .def("next_report", &native_client::next_report)
      .def_prop_ro("reports_dropped", &native_client::reports_dropped)
      .def("next_event", &native_client::next_event);
}

}  // namespace openiec61850::python
