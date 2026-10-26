// _core.Client: the native ACSI client. Every service returns an asyncio future (see runtime.hpp);
// arguments and results are the plain values of convert.hpp.

#include <nanobind/nanobind.h>
#include <nanobind/stl/optional.h>
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>

#include <memory>
#include <optional>
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

std::shared_ptr<client::error_details> details() { return std::make_shared<client::error_details>(); }

// A type_description in the shape of a data definition dict (what _values.spec_from_definition
// reads).
nb::object type_to_py(const mms::type_description& t, const std::string& name) {
  nb::dict o;
  o["name"] = name;
  o["mms_type"] = static_cast<int>(t.type);
  o["basic_type"] = t.type == mms::data_type::floating_point && t.format_width == 64
                        ? nb::object(nb::str("FLOAT64"))
                        : nb::none();
  o["size"] = t.size < 0 ? -t.size : t.size;
  nb::list children;
  for (const auto& c : t.components) children.append(type_to_py(c.type, c.name));
  o["children"] = children;
  return o;
}

const mms::type_description* ctl_val_of(const client::control& c) {
  const auto& st = c.structure();
  if (!st) return nullptr;
  for (const char* svc : {"Oper", "SBOw", "Cancel"}) {
    for (const auto& comp : st->components) {
      if (comp.name != svc) continue;
      for (const auto& f : comp.type.components) {
        if (f.name == "ctlVal") return &f.type;
      }
    }
  }
  return nullptr;
}

nb::object last_appl_error_to_py(const std::optional<client::last_appl_error>& e) {
  if (!e) return nb::none();
  client::error_details d;
  d.last_appl_error = e;
  return nb::borrow(error_details_to_py(d)["last_appl_error"]);
}

// Keys: origin (orCat, orIdent bytes), test, synchro_check, interlock_check, oper_time (tagged
// utc-time or None), ctl_num (int or None), termination_timeout (seconds).
client::control_options control_options_from_py(nb::handle h) {
  client::control_options o;
  if (h.is_none()) return o;
  const auto d = nb::cast<nb::dict>(h);
  auto get = [&](const char* k) -> nb::object {
    if (!d.contains(k)) return nb::none();
    return nb::borrow(d[k]);
  };
  if (auto v = get("origin"); !v.is_none()) {
    const auto t = nb::cast<nb::tuple>(v);
    const auto cat = nb::cast<int>(t[0]);
    if (cat < 0 || cat > 255) throw nb::value_error("orCat out of range");
    o.origin.category = static_cast<model::orcat>(cat);
    o.origin.identifier = bytes_from_py(t[1]);
    if (o.origin.identifier.size() > 64) throw nb::value_error("orIdent is limited to 64 octets");
  }
  if (auto v = get("test"); !v.is_none()) o.test = nb::cast<bool>(v);
  if (auto v = get("synchro_check"); !v.is_none()) o.check.set_synchrocheck(nb::cast<bool>(v));
  if (auto v = get("interlock_check"); !v.is_none()) o.check.set_interlock_check(nb::cast<bool>(v));
  if (auto v = get("oper_time"); !v.is_none()) {
    const auto data = data_from_py(v);
    auto ts = model::timestamp::from_mms(data);
    if (!ts) throw nb::type_error("oper_time must be a Timestamp");
    o.oper_time = *ts;
  }
  if (auto v = get("ctl_num"); !v.is_none()) {
    const auto n = nb::cast<int>(v);
    if (n < 0 || n > 255) throw nb::value_error("ctl_num must be in 0..255");
    o.ctl_num = static_cast<std::uint8_t>(n);
  }
  if (auto v = get("termination_timeout"); !v.is_none()) o.termination_timeout = seconds_from_py(v);
  return o;
}

client::control_config control_config_from_py(nb::handle ctl_model, bool read_sbo_timeout,
                                               bool read_structure) {
  client::control_config c;
  if (!ctl_model.is_none()) {
    const auto m = nb::cast<int>(ctl_model);
    if (m < 0 || m > 4) throw nb::value_error("unknown ctlModel");
    c.ctl_model = static_cast<model::ctl_model>(m);
  }
  c.read_sbo_timeout = read_sbo_timeout;
  c.read_structure = read_structure;
  return c;
}

class native_control {
 public:
  native_control(client::control c, client::client::executor_type ex)
      : c_(std::move(c)), ex_(std::move(ex)) {}

  [[nodiscard]] std::string reference() const { return c_.reference().to_string(); }
  [[nodiscard]] int ctl_model() const { return static_cast<int>(c_.ctl_model()); }
  [[nodiscard]] nb::object sbo_timeout() const {
    const auto t = c_.sbo_timeout();
    if (!t) return nb::none();
    return nb::cast(static_cast<double>(t->count()) / 1000.0);
  }
  [[nodiscard]] int ctl_num() const { return c_.ctl_num(); }
  [[nodiscard]] bool selected() const { return c_.selected(); }
  [[nodiscard]] nb::object has_oper_time() const {
    const auto v = c_.has_oper_time();
    return v ? nb::cast(*v) : nb::none();
  }
  [[nodiscard]] nb::object ctl_val_type() const {
    const auto* t = ctl_val_of(c_);
    return t != nullptr ? type_to_py(*t, "ctlVal") : nb::none();
  }
  [[nodiscard]] nb::object last_error() const { return last_appl_error_to_py(c_.last_error()); }

  nb::object select(nb::handle options) {
    auto det = details();
    return launch(c_executor(), c_.select(control_options_from_py(options), *det),
                  [] { return nb::none(); }, det);
  }
  nb::object select_with_value(nb::handle value, nb::handle options) {
    auto det = details();
    return launch(c_executor(),
                  c_.select_with_value(data_from_py(value), control_options_from_py(options), *det),
                  [] { return nb::none(); }, det);
  }
  nb::object operate(nb::handle value, nb::handle options) {
    auto det = details();
    return launch(c_executor(),
                  c_.operate(data_from_py(value), control_options_from_py(options), *det),
                  [] { return nb::none(); }, det);
  }
  nb::object cancel(nb::handle options) {
    auto det = details();
    return launch(c_executor(), c_.cancel(control_options_from_py(options), *det),
                  [] { return nb::none(); }, det);
  }


 private:
  [[nodiscard]] const client::client::executor_type& c_executor() const { return ex_; }

  client::control c_;
  client::client::executor_type ex_;
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
    auto det = details();
    return launch(c_.get_executor(), c_.get_server_directory(*det), to_py_strings, det);
  }
  nb::object logical_device_directory(std::string ld) {
    auto det = details();
    return launch(c_.get_executor(), c_.get_logical_device_directory(std::move(ld), *det), to_py_strings, det);
  }
  nb::object logical_node_directory(nb::handle ln) {
    auto det = details();
    return launch(c_.get_executor(), c_.get_logical_node_directory(ref(ln), *det),
                  [](client::logical_node_directory d) { return directory_to_py(d); }, det);
  }
  nb::object data_directory(nb::handle r) {
    auto det = details();
    return launch(c_.get_executor(), c_.get_data_directory(ref(r), *det),
                  [](std::vector<client::data_directory_entry> v) {
                    nb::list out;
                    for (const auto& e : v) {
                      nb::list fcs;
                      for (auto f : e.fcs) fcs.append(std::string(model::to_string(f)));
                      out.append(nb::make_tuple(e.name, fcs));
                    }
                    return nb::object(std::move(out));
                  }, det);
  }
  nb::object data_definition(nb::handle r) {
    auto det = details();
    return launch(c_.get_executor(), c_.get_data_definition(ref(r), *det),
                  [](client::data_definition d) { return definition_to_py(d); }, det);
  }
  nb::object name_list(int cls, std::string domain) {
    if (cls < 0 || cls > 11) throw nb::value_error("unknown MMS object class");
    auto det = details();
    return launch(c_.get_executor(),
                  c_.get_name_list(static_cast<mms::object_class>(cls), std::move(domain), *det),
                  to_py_strings, det);
  }

  nb::object read(nb::handle r) {
    auto det = details();
    return launch(c_.get_executor(), c_.read(ref(r), *det),
                  [](mms::data d) { return data_to_py(d); }, det);
  }
  nb::object read_many(nb::handle refs) {
    auto det = details();
    return launch(c_.get_executor(), c_.read_many(refs_of(refs), *det), read_results_to_py, det);
  }
  nb::object write(nb::handle r, nb::handle value) {
    auto det = details();
    return launch(c_.get_executor(), c_.write(ref(r), data_from_py(value), *det),
                  [] { return nb::none(); }, det);
  }
  nb::object write_many(nb::handle items) {
    std::vector<client::write_item> v;
    for (nb::handle it : items) {
      const auto t = nb::cast<nb::tuple>(it);
      v.push_back({ref(t[0]), data_from_py(t[1])});
    }
    auto det = details();
    return launch(c_.get_executor(), c_.write_many(std::move(v), *det), write_results_to_py, det);
  }

  nb::object data_set_directory(nb::handle ds) {
    auto det = details();
    return launch(c_.get_executor(), c_.get_data_set_directory(ref(ds), *det),
                  [](client::data_set_directory d) {
                    nb::list members;
                    for (const auto& m : d.members) members.append(ref_to_py(m));
                    return nb::object(nb::make_tuple(members, d.deletable));
                  }, det);
  }
  nb::object create_data_set(nb::handle ds, nb::handle members) {
    auto det = details();
    return launch(c_.get_executor(), c_.create_data_set(ref(ds), refs_of(members), *det),
                  [] { return nb::none(); }, det);
  }
  nb::object delete_data_set(nb::handle ds) {
    auto det = details();
    return launch(c_.get_executor(), c_.delete_data_set(ref(ds), *det), [] { return nb::none(); }, det);
  }
  nb::object data_set_values(nb::handle ds) {
    auto det = details();
    return launch(c_.get_executor(), c_.get_data_set_values(ref(ds), *det), read_results_to_py, det);
  }
  nb::object set_data_set_values(nb::handle ds, nb::handle values) {
    std::vector<mms::data> v;
    for (nb::handle x : values) v.push_back(data_from_py(x));
    auto det = details();
    return launch(c_.get_executor(), c_.set_data_set_values(ref(ds), std::move(v), *det),
                  write_results_to_py, det);
  }

  nb::object rcb_values(nb::handle rcb) {
    auto det = details();
    return launch(c_.get_executor(), c_.get_rcb_values(ref(rcb), *det),
                  [](client::rcb_values v) { return rcb_values_to_py(v); }, det);
  }
  nb::object set_rcb_values(nb::handle rcb, nb::handle settings) {
    auto det = details();
    return launch(c_.get_executor(), c_.set_rcb_values(ref(rcb), rcb_settings_from_py(settings, parse_), *det),
                  [] { return nb::none(); }, det);
  }
  nb::object enable_reporting(nb::handle rcb, nb::handle settings) {
    auto det = details();
    return launch(c_.get_executor(),
                  c_.enable_reporting(ref(rcb), report_settings_from_py(settings, parse_), *det),
                  [](client::rcb_values v) { return rcb_values_to_py(v); }, det);
  }
  nb::object disable_reporting(nb::handle rcb) {
    auto det = details();
    return launch(c_.get_executor(), c_.disable_reporting(ref(rcb), *det), [] { return nb::none(); }, det);
  }
  nb::object trigger_gi(nb::handle rcb) {
    auto det = details();
    return launch(c_.get_executor(), c_.trigger_gi(ref(rcb), *det), [] { return nb::none(); }, det);
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
  nb::object control(nb::handle object, nb::handle ctl_model, bool read_sbo_timeout,
                     bool read_structure) {
    auto det = details();
    return launch(c_.get_executor(),
                  c_.get_control(ref(object),
                                 control_config_from_py(ctl_model, read_sbo_timeout, read_structure),
                                 *det),
                  [ex = c_.get_executor()](client::control c) {
                    return nb::cast(native_control(std::move(c), ex));
                  },
                  det);
  }
  nb::object operate(nb::handle object, nb::handle value, nb::handle options) {
    auto det = details();
    return launch(c_.get_executor(),
                  c_.operate(ref(object), data_from_py(value), control_options_from_py(options), *det),
                  [] { return nb::none(); }, det);
  }
  // --- setting groups

  nb::object sgcb_values(std::string ld) {
    auto det = details();
    return launch(c_.get_executor(), c_.get_sgcb_values(std::move(ld), *det),
                  [](client::sgcb_values v) { return sgcb_values_to_py(v); }, det);
  }
  nb::object select_active_sg(std::string ld, int sg) {
    auto det = details();
    return launch(c_.get_executor(), c_.select_active_sg(std::move(ld), group(sg), *det),
                  [] { return nb::none(); }, det);
  }
  nb::object select_edit_sg(std::string ld, int sg) {
    auto det = details();
    return launch(c_.get_executor(), c_.select_edit_sg(std::move(ld), group(sg), *det),
                  [] { return nb::none(); }, det);
  }
  nb::object set_edit_sg_value(nb::handle r, nb::handle value) {
    auto det = details();
    return launch(c_.get_executor(), c_.set_edit_sg_value(ref(r), data_from_py(value), *det),
                  [] { return nb::none(); }, det);
  }
  nb::object confirm_edit_sg_values(std::string ld) {
    auto det = details();
    return launch(c_.get_executor(), c_.confirm_edit_sg_values(std::move(ld), *det),
                  [] { return nb::none(); }, det);
  }
  nb::object edit_sg_value(nb::handle r) {
    auto det = details();
    return launch(c_.get_executor(), c_.get_edit_sg_value(ref(r), *det),
                  [](mms::data d) { return data_to_py(d); }, det);
  }

  // --- logs

  nb::object lcb_values(nb::handle lcb) {
    auto det = details();
    return launch(c_.get_executor(), c_.get_lcb_values(ref(lcb), *det),
                  [](client::lcb_values v) { return lcb_values_to_py(v); }, det);
  }
  nb::object set_lcb_values(nb::handle lcb, nb::handle settings) {
    auto det = details();
    return launch(c_.get_executor(),
                  c_.set_lcb_values(ref(lcb), lcb_settings_from_py(settings, parse_), *det),
                  [] { return nb::none(); }, det);
  }
  nb::object query_log_by_time(nb::handle log, nb::handle start, nb::handle stop) {
    std::optional<model::entry_time> from;
    std::optional<model::entry_time> to;
    if (!start.is_none()) from = entry_time_from_py(start);
    if (!stop.is_none()) to = entry_time_from_py(stop);
    auto det = details();
    return launch(c_.get_executor(), c_.query_log_by_time(ref(log), from, to, *det), log_entries_to_py,
                  det);
  }
  nb::object query_log_after(nb::handle log, nb::handle time, nb::handle entry) {
    auto det = details();
    return launch(c_.get_executor(),
                  c_.query_log_after(ref(log), entry_time_from_py(time), entry_id_from_py(entry), *det),
                  log_entries_to_py, det);
  }
  nb::object log_status(nb::handle log) {
    auto det = details();
    return launch(c_.get_executor(), c_.get_log_status(ref(log), *det),
                  [](std::uint32_t n) { return nb::cast(n); }, det);
  }

  // --- files

  nb::object file_directory(std::string path) {
    auto det = details();
    return launch(c_.get_executor(), c_.get_file_directory(std::move(path), *det),
                  [](std::vector<client::file_entry> v) {
                    nb::list out;
                    for (const auto& e : v) out.append(file_entry_to_py(e));
                    return nb::object(std::move(out));
                  }, det);
  }
  nb::object get_file(std::string name) {
    auto det = details();
    return launch(c_.get_executor(), c_.get_file(std::move(name), *det),
                  [](byte_buffer b) { return nb::object(to_bytes(b)); }, det);
  }
  // Streaming GetFile: every chunk is handed to on_chunk(bytes) on the asyncio loop (scheduled with
  // call_soon_threadsafe from the client strand, in order and before the future resolves). The
  // I/O thread holds the GIL only to schedule a chunk; nothing waits for the loop.
  nb::object get_file_stream(std::string name, nb::handle on_chunk) {
    auto loop = std::make_shared<py_ref>(nb::module_::import_("asyncio").attr("get_running_loop")());
    auto cb = std::make_shared<py_ref>(on_chunk);
    auto sink = [loop, cb](byte_buffer b) {
      if (interpreter_finalizing()) return;
      const nb::gil_scoped_acquire gil;
      try {
        nb::handle(loop->get()).attr("call_soon_threadsafe")(nb::handle(cb->get()), to_bytes(b));
      } catch (nb::python_error&) {
        // The loop is closed.
      } catch (...) {
      }
    };
    auto det = details();
    return launch(c_.get_executor(), c_.get_file(std::move(name), std::move(sink), *det),
                  [](std::uint64_t n) { return nb::cast(n); }, det);
  }
  nb::object delete_file(std::string name) {
    auto det = details();
    return launch(c_.get_executor(), c_.delete_file(std::move(name), *det), [] { return nb::none(); },
                  det);
  }
  nb::object rename_file(std::string from, std::string to) {
    auto det = details();
    return launch(c_.get_executor(), c_.rename_file(std::move(from), std::move(to), *det),
                  [] { return nb::none(); }, det);
  }

  // --- GOOSE control blocks

  nb::object gocb_values(nb::handle gocb) {
    auto det = details();
    return launch(c_.get_executor(), c_.get_gocb_values(ref(gocb), *det),
                  [](client::gocb_values v) { return gocb_values_to_py(v); }, det);
  }
  nb::object set_gocb_values(nb::handle gocb, nb::handle settings) {
    auto det = details();
    return launch(c_.get_executor(),
                  c_.set_gocb_values(ref(gocb), gocb_settings_from_py(settings, parse_), *det),
                  [] { return nb::none(); }, det);
  }

  [[nodiscard]] std::uint64_t reports_dropped() const noexcept { return c_.reports_dropped(); }
  nb::object next_event() {
    return launch(c_.get_executor(), c_.next_event(),
                  [](client::connection_event e) { return event_to_py(e); });
  }

 private:
  static std::uint8_t group(int sg) {
    if (sg < 0 || sg > 255) throw nb::value_error("setting group out of range");
    return static_cast<std::uint8_t>(sg);
  }
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
      .def("next_event", &native_client::next_event)
      .def("control", &native_client::control, nb::arg("object"), nb::arg("ctl_model") = nb::none(),
           nb::arg("read_sbo_timeout") = true, nb::arg("read_structure") = true)
      .def("operate", &native_client::operate, nb::arg("object"), nb::arg("value"),
           nb::arg("options") = nb::none())
      .def("sgcb_values", &native_client::sgcb_values, nb::arg("ld"))
      .def("select_active_sg", &native_client::select_active_sg, nb::arg("ld"), nb::arg("sg"))
      .def("select_edit_sg", &native_client::select_edit_sg, nb::arg("ld"), nb::arg("sg"))
      .def("set_edit_sg_value", &native_client::set_edit_sg_value, nb::arg("ref"), nb::arg("value"))
      .def("confirm_edit_sg_values", &native_client::confirm_edit_sg_values, nb::arg("ld"))
      .def("edit_sg_value", &native_client::edit_sg_value, nb::arg("ref"))
      .def("lcb_values", &native_client::lcb_values, nb::arg("lcb"))
      .def("set_lcb_values", &native_client::set_lcb_values, nb::arg("lcb"), nb::arg("settings"))
      .def("query_log_by_time", &native_client::query_log_by_time, nb::arg("log"),
           nb::arg("start").none(), nb::arg("stop").none())
      .def("query_log_after", &native_client::query_log_after, nb::arg("log"), nb::arg("time"),
           nb::arg("entry_id"))
      .def("log_status", &native_client::log_status, nb::arg("log"))
      .def("file_directory", &native_client::file_directory, nb::arg("path") = "")
      .def("get_file", &native_client::get_file, nb::arg("name"))
      .def("get_file_stream", &native_client::get_file_stream, nb::arg("name"), nb::arg("on_chunk"))
      .def("delete_file", &native_client::delete_file, nb::arg("name"))
      .def("rename_file", &native_client::rename_file, nb::arg("from_"), nb::arg("to"))
      .def("gocb_values", &native_client::gocb_values, nb::arg("gocb"))
      .def("set_gocb_values", &native_client::set_gocb_values, nb::arg("gocb"), nb::arg("settings"));

  nb::class_<native_control>(m, "Control",
                             "Native control handle. Use openiec61850.Control instead.")
      .def_prop_ro("reference", &native_control::reference)
      .def_prop_ro("ctl_model", &native_control::ctl_model)
      .def_prop_ro("sbo_timeout", &native_control::sbo_timeout)
      .def_prop_ro("ctl_num", &native_control::ctl_num)
      .def_prop_ro("selected", &native_control::selected)
      .def_prop_ro("has_oper_time", &native_control::has_oper_time)
      .def_prop_ro("ctl_val_type", &native_control::ctl_val_type)
      .def_prop_ro("last_error", &native_control::last_error)
      .def("select", &native_control::select, nb::arg("options") = nb::none())
      .def("select_with_value", &native_control::select_with_value, nb::arg("value"),
           nb::arg("options") = nb::none())
      .def("operate", &native_control::operate, nb::arg("value"), nb::arg("options") = nb::none())
      .def("cancel", &native_control::cancel, nb::arg("options") = nb::none());
}

}  // namespace openiec61850::python
