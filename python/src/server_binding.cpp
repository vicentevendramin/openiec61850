// _core.ModelBuilder, _core.Model and _core.Server: the IEC 61850 server (server/model.hpp,
// server/scl_model.hpp, server/server.hpp). Values are the tagged tuples of convert.hpp and object
// references their string form; the pure Python layer (openiec61850/_server.py) builds the public
// API on top.
//
// Application hooks (on_write, on_control, authorize, on_setting_group, on_goose_control) and
// Python file stores. The C++ server calls them on its strand, that is on the I/O thread, and
// needs their answer at once (a pending Operate excepted: it is completed later through
// _ControlCompletion, from any thread). The binding therefore calls the
// Python dispatcher synchronously on the I/O thread, holding the GIL only for that call; the
// Python layer keeps the hooks short and moves asynchronous work (an awaitable returned for an
// Operate) to the asyncio loop. Nothing here waits for the loop, so a busy or blocked loop
// delays a hook only by the GIL switch interval.

#include <nanobind/nanobind.h>
#include <nanobind/stl/optional.h>
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <span>
#include <string_view>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include <asio/ip/address.hpp>
#include <asio/ip/tcp.hpp>

#include "bindings.hpp"
#include "convert.hpp"
#include "openiec61850/iso/acse/apdu.hpp"
#include "openiec61850/scl/load.hpp"
#include "openiec61850/server/scl_model.hpp"
#include "openiec61850/server/server.hpp"
#include "runtime.hpp"

namespace openiec61850::python {

namespace {

using model::fc;
using server::node;
using server::node_id;
using server::node_kind;

[[noreturn]] void raise_error(std::error_code ec) {
  nb::object e = make_error(ec);
  PyErr_SetObject(reinterpret_cast<PyObject*>(Py_TYPE(e.ptr())), e.ptr());
  throw nb::python_error();
}

model::edition edition_from(int e) {
  if (e < 1 || e > 3) throw nb::value_error("unknown edition");
  return static_cast<model::edition>(e);
}

model::basic_type basic_type_from(const std::string& name) {
  for (int i = 0; i <= static_cast<int>(model::basic_type::optional_fields); ++i) {
    const auto t = static_cast<model::basic_type>(i);
    if (model::to_string(t) == name) return t;
  }
  throw nb::value_error(("unknown basic type '" + name + "'").c_str());
}

fc fc_from(const std::string& s) {
  const auto f = model::parse_functional_constraint(s);
  if (!f || *f == fc::XX) throw nb::value_error(("unknown functional constraint '" + s + "'").c_str());
  return *f;
}

nb::object fc_name(std::optional<fc> f) {
  if (!f) return nb::none();
  return nb::str(std::string(model::to_string(*f)).c_str());
}

const char* kind_name(node_kind k) {
  switch (k) {
    case node_kind::logical_device: return "logical_device";
    case node_kind::logical_node: return "logical_node";
    case node_kind::data_object: return "data_object";
    case node_kind::control_block: return "control_block";
    case node_kind::data_attribute: return "data_attribute";
  }
  return "data_attribute";
}

model::parse_options lenient_options(model::edition e) {
  return {model::name_limits::for_edition(e), false};
}

// ---------------------------------------------------------------------------------------------
// Data definitions (the dict shape of client data definitions, see _client.DataDefinition)

nb::dict make_def(const std::string& name, std::optional<fc> f, const char* kind, int mms_type,
                  nb::object basic, std::int32_t size, bool variable, std::uint32_t array_size,
                  nb::list children) {
  nb::dict o;
  o["name"] = name;
  o["fc"] = fc_name(f);
  o["kind"] = kind;
  o["mms_type"] = mms_type;
  o["basic_type"] = std::move(basic);
  o["size"] = size;
  o["variable_length"] = variable;
  o["array_size"] = array_size;
  o["children"] = std::move(children);
  return o;
}

nb::dict basic_def(model::basic_type type, std::int32_t size, model::edition e, const std::string& name,
                   std::optional<fc> f) {
  auto t = model::to_mms_type(type, size, e);
  if (!t) raise_error(t.error());
  const std::int32_t width =
      t->type == mms::data_type::floating_point ? std::int32_t{t->format_width} : std::abs(t->size);
  return make_def(name, f, "basic", static_cast<int>(t->type),
                  nb::str(std::string(model::to_string(type)).c_str()), width, t->size < 0, 0,
                  nb::list());
}

// The definition of node `id` seen under `f`; `element`: one element of an array attribute.
nb::dict def_of(const server::data_model& m, node_id id, std::optional<fc> f, bool element) {
  const node& n = m.at(id);
  const std::optional<fc> nf = n.fc ? n.fc : f;
  if (n.is_attribute()) {
    if (n.count > 0 && !element) {
      nb::list ch;
      ch.append(def_of(m, id, f, true));
      return make_def(n.name, nf, "array", static_cast<int>(mms::data_type::array), nb::none(), 0,
                      false, n.count, ch);
    }
    const std::string name = element ? std::string() : n.name;
    if (n.type) return basic_def(*n.type, n.size, m.edition(), name, nf);
    nb::list ch;
    for (const node_id c : n.children) ch.append(def_of(m, c, f, false));
    return make_def(name, nf, "structure", static_cast<int>(mms::data_type::structure), nb::none(), 0,
                    false, 0, ch);
  }
  nb::list ch;
  if (n.kind == node_kind::logical_node && !f) {
    for (std::size_t i = 0; i < model::functional_constraint_count; ++i) {
      const auto fi = static_cast<fc>(i);
      if (fi == fc::XX || !n.has_fc(fi)) continue;
      nb::dict d = def_of(m, id, fi, false);
      d["name"] = std::string(model::to_string(fi));
      ch.append(d);
    }
  } else {
    for (const node_id c : n.children) {
      if (f && !m.at(c).has_fc(*f)) continue;
      ch.append(def_of(m, c, f, false));
    }
  }
  return make_def(n.name, f, "structure", static_cast<int>(mms::data_type::structure), nb::none(), 0,
                  false, 0, ch);
}

struct resolved {
  node_id id = server::no_node;
  std::optional<fc> f;
  bool element = false;
};

// Mirrors the server's resolution of an application reference (FC optional for a data
// attribute, array elements and their components by index).
std::optional<resolved> resolve(const server::data_model& m, const model::object_reference& ref) {
  if (ref.empty() || ref.is_association_specific() || !ref.has_ln()) return std::nullopt;
  const node_id ld = m.find_logical_device(ref.ld());
  if (ld == server::no_node) return std::nullopt;
  const node_id ln = m.find_child(ld, ref.ln());
  if (ln == server::no_node || m.at(ln).kind != node_kind::logical_node) return std::nullopt;
  auto f = ref.fc();
  if (f && *f == fc::XX) return std::nullopt;
  node_id cur = ln;
  bool in_value = false;
  bool element = false;
  for (const auto pe : ref.path()) {
    const node& n = m.at(cur);
    if (!in_value) {
      if (n.holds_value()) return std::nullopt;
      const node_id child = m.find_child(cur, pe.name);
      if (child == server::no_node) return std::nullopt;
      if (!n.is_attribute() && f && !m.at(child).has_fc(*f)) return std::nullopt;
      cur = child;
    } else {
      if ((!element && n.count > 0) || n.type) return std::nullopt;
      const node_id child = m.find_child(cur, pe.name);
      if (child == server::no_node) return std::nullopt;
      cur = child;
    }
    element = false;
    if (pe.index) {
      if (m.at(cur).count == 0 || *pe.index >= m.at(cur).count) return std::nullopt;
      in_value = true;
      element = true;
    }
  }
  if (!f) {
    if (cur == ln) return resolved{ln, std::nullopt, false};
    if (!m.at(cur).fc) return std::nullopt;
    f = m.at(cur).fc;
  }
  if (!m.at(cur).has_fc(*f)) return std::nullopt;
  return resolved{cur, f, element};
}

nb::object diagnostics_to_py(const scl::diagnostics& diags) {
  nb::list out;
  for (const auto& d : diags) {
    out.append(nb::make_tuple(std::string(scl::to_string(d.level)), std::string(scl::to_string(d.code)),
                              d.line, d.message));
  }
  return out;
}

// ---------------------------------------------------------------------------------------------
// Model

class native_model {
 public:
  explicit native_model(server::data_model m)
      : m_(std::make_shared<const server::data_model>(std::move(m))),
        parse_(lenient_options(m_->edition())) {}

  [[nodiscard]] const server::data_model& get() const noexcept { return *m_; }
  [[nodiscard]] int edition() const noexcept { return static_cast<int>(m_->edition()); }
  [[nodiscard]] std::size_t node_count() const noexcept { return m_->nodes().size(); }
  [[nodiscard]] std::vector<node_id> logical_devices() const {
    return {m_->logical_devices().begin(), m_->logical_devices().end()};
  }

  // (name, kind, parent | None, children, fc | None, basic_type | None, size, count,
  //  (dchg, qchg, dupd))
  [[nodiscard]] nb::object node_info(node_id id) const {
    const node& n = at(id);
    return nb::make_tuple(n.name, kind_name(n.kind),
                          n.parent == server::no_node ? nb::none() : nb::cast(n.parent),
                          std::vector<node_id>(n.children.begin(), n.children.end()), fc_name(n.fc),
                          n.type ? nb::cast(std::string(model::to_string(*n.type))) : nb::none(),
                          n.size, n.count,
                          nb::make_tuple(n.triggers.dchg, n.triggers.qchg, n.triggers.dupd));
  }
  [[nodiscard]] nb::object initial_value(node_id id) const {
    const node& n = at(id);
    if (!n.holds_value()) return nb::none();
    return data_to_py(n.value);
  }
  [[nodiscard]] std::string reference_of(node_id id) const {
    (void)at(id);
    return m_->reference_of(id);
  }

  // The node of a reference without index (None when absent).
  [[nodiscard]] nb::object find(nb::handle ref) const {
    auto r = m_->find(ref_from_py(ref, parse_));
    if (!r) return nb::none();
    return nb::cast(*r);
  }

  [[nodiscard]] nb::object definition(nb::handle ref) const {
    const auto r = resolve(*m_, ref_from_py(ref, parse_));
    if (!r) raise_error(server::make_error_code(server::errc::object_not_found));
    return def_of(*m_, r->id, r->f, r->element);
  }
  [[nodiscard]] nb::object node_definition(node_id id, std::optional<std::string> f) const {
    (void)at(id);
    std::optional<fc> fv;
    if (f) fv = fc_from(*f);
    return def_of(*m_, id, fv, false);
  }

  // [(ln reference, name, [members])]
  [[nodiscard]] nb::object data_sets() const {
    nb::list out;
    for (const auto& ds : m_->data_sets()) {
      std::vector<std::string> members;
      for (const auto& mb : ds.members) members.push_back(mb.to_string());
      out.append(nb::make_tuple(m_->reference_of(ds.ln), ds.name, members));
    }
    return out;
  }
  // [(ln reference, num_of_sgs, act_sg, resv_tms)]
  [[nodiscard]] nb::object setting_group_controls() const {
    nb::list out;
    for (const auto& sg : m_->setting_group_controls()) {
      out.append(nb::make_tuple(m_->reference_of(sg.ln), sg.settings.num_of_sgs, sg.settings.act_sg,
                                sg.settings.resv_tms));
    }
    return out;
  }
  // [(ln reference, name)]
  [[nodiscard]] nb::object logs() const {
    nb::list out;
    for (const auto& l : m_->logs()) out.append(nb::make_tuple(m_->reference_of(l.ln), l.name));
    return out;
  }
  [[nodiscard]] nb::object log_controls() const {
    nb::list out;
    for (const auto& lc : m_->log_controls()) {
      const auto& s = lc.settings;
      nb::dict d;
      d["ln"] = m_->reference_of(lc.ln);
      d["name"] = s.name;
      d["data_set"] = s.data_set;
      d["log_name"] = s.log_name;
      d["log_ln"] = s.log_ln;
      d["log_ena"] = s.log_ena;
      d["trg_ops"] = s.trg_ops.raw();
      d["intg_pd"] = s.intg_pd;
      out.append(d);
    }
    return out;
  }
  [[nodiscard]] nb::object goose_controls() const {
    nb::list out;
    for (const auto& gc : m_->goose_controls()) {
      const auto& s = gc.settings;
      nb::dict d;
      d["ln"] = m_->reference_of(gc.ln);
      d["name"] = s.name;
      d["go_id"] = s.go_id;
      d["data_set"] = s.data_set;
      d["conf_rev"] = s.conf_rev;
      d["go_ena"] = s.go_ena;
      d["dst_mac"] = nb::bytes(s.dst_mac.data(), s.dst_mac.size());
      d["vlan_priority"] = s.vlan_priority;
      d["vlan_id"] = s.vlan_id;
      d["app_id"] = s.app_id;
      d["min_time"] = s.min_time;
      d["max_time"] = s.max_time;
      d["fixed_offs"] = s.fixed_offs;
      out.append(d);
    }
    return out;
  }
  [[nodiscard]] nb::object report_controls() const {
    nb::list out;
    for (const auto& rc : m_->report_controls()) {
      const auto& s = rc.settings;
      nb::dict d;
      d["ln"] = m_->reference_of(rc.ln);
      d["name"] = s.name;
      d["buffered"] = s.buffered;
      d["rpt_id"] = s.rpt_id;
      d["data_set"] = s.data_set;
      d["conf_rev"] = s.conf_rev;
      d["opt_flds"] = s.opt_flds.raw();
      d["buf_tm"] = s.buf_tm;
      d["trg_ops"] = s.trg_ops.raw();
      d["intg_pd"] = s.intg_pd;
      out.append(d);
    }
    return out;
  }

 private:
  [[nodiscard]] const node& at(node_id id) const {
    if (id >= m_->nodes().size()) throw nb::index_error("no such node");
    return m_->at(id);
  }

  std::shared_ptr<const server::data_model> m_;
  model::parse_options parse_;
};

// (Model | None, diagnostics, error | None)
nb::object load_scl(const std::string& source, bool is_text, const std::string& ied,
                    const std::string& access_point, bool strict, std::uint32_t setting_group) {
  server::scl_load_options o;
  o.strict = strict;
  o.load.strict = strict;
  o.instantiate.strict = strict;
  o.setting_group = setting_group;
  scl::diagnostics diags;
  std::optional<result<server::data_model>> r;
  {
    const nb::gil_scoped_release release;
    if (is_text) {
      auto loaded = scl::load_string(source, o.load);
      diags.merge(loaded.diags);
      if (!loaded.ok()) {
        r.emplace(loaded.doc.error());
      } else {
        r.emplace(server::load_model(*loaded.doc, ied, access_point, o, &diags));
      }
    } else {
      r.emplace(server::load_model_file(std::filesystem::path(source), ied, access_point, o, &diags));
    }
  }
  if (!*r) return nb::make_tuple(nb::none(), diagnostics_to_py(diags), make_error(r->error()));
  return nb::make_tuple(nb::cast(native_model(std::move(**r))), diagnostics_to_py(diags), nb::none());
}

// ---------------------------------------------------------------------------------------------
// Builder

class native_builder {
 public:
  explicit native_builder(int edition)
      : b_(std::make_unique<server::model_builder>(edition_from(edition))),
        parse_(lenient_options(edition_from(edition))) {}

  node_id logical_device(const std::string& name) {
    auto& b = usable();
    auto h = b.logical_device(name);
    check();
    lds_.insert_or_assign(h.id(), h);
    return h.id();
  }
  node_id logical_node(node_id ld, const std::string& name) {
    auto& b = usable();
    (void)b;
    const auto it = lds_.find(ld);
    if (it == lds_.end()) throw nb::value_error("not a logical device of this builder");
    const auto id = it->second.logical_node(name).id();
    check();
    return id;
  }
  node_id data_object(node_id ln, const std::string& name) {
    const auto id = usable().logical_node_handle(ln).data_object(name).id();
    check();
    return id;
  }
  node_id sub_object(node_id parent, const std::string& name) {
    const auto id = usable().data_object_handle(parent).sub_object(name).id();
    check();
    return id;
  }
  // parent: a data object (fc given) or a constructed attribute (fc None).
  node_id attribute(node_id parent, bool under_object, const std::string& name,
                    std::optional<std::string> f, std::optional<std::string> type, std::int32_t size,
                    std::uint32_t count, nb::handle triggers, nb::handle value) {
    auto& b = usable();
    server::attribute_options o;
    o.size = size;
    o.count = count;
    if (!triggers.is_none()) {
      const auto t = nb::cast<nb::tuple>(triggers);
      o.triggers = {nb::cast<bool>(t[0]), nb::cast<bool>(t[1]), nb::cast<bool>(t[2])};
    }
    if (!value.is_none()) o.value = data_from_py(value);
    node_id id = server::no_node;
    if (under_object) {
      if (!f) throw nb::value_error("an attribute of a data object needs a functional constraint");
      auto h = b.data_object_handle(parent);
      id = type ? h.attribute(name, fc_from(*f), basic_type_from(*type), std::move(o)).id()
                : h.structure(name, fc_from(*f), std::move(o)).id();
    } else {
      auto h = b.attribute_handle(parent);
      id = type ? h.attribute(name, basic_type_from(*type), std::move(o)).id()
                : h.structure(name, std::move(o)).id();
    }
    check();
    return id;
  }
  void set_value(node_id da, nb::handle value) {
    usable().attribute_handle(da).value(data_from_py(value));
    check();
  }
  void data_set(node_id ln, const std::string& name, nb::handle members) {
    std::vector<model::object_reference> refs;
    for (nb::handle h : members) refs.push_back(ref_from_py(h, parse_));
    usable().logical_node_handle(ln).data_set(name, std::move(refs));
    check();
  }
  void report_control(node_id ln, nb::dict d) {
    server::report_control_settings s;
    s.name = nb::cast<std::string>(d["name"]);
    s.buffered = nb::cast<bool>(d["buffered"]);
    s.rpt_id = nb::cast<std::string>(d["rpt_id"]);
    s.data_set = nb::cast<std::string>(d["data_set"]);
    s.conf_rev = nb::cast<std::uint32_t>(d["conf_rev"]);
    s.opt_flds = model::optional_fields::from_raw(nb::cast<std::uint16_t>(d["opt_flds"]));
    s.buf_tm = nb::cast<std::uint32_t>(d["buf_tm"]);
    s.trg_ops = model::trigger_conditions::from_raw(nb::cast<std::uint8_t>(d["trg_ops"]));
    s.intg_pd = nb::cast<std::uint32_t>(d["intg_pd"]);
    usable().logical_node_handle(ln).report_control(std::move(s));
    check();
  }
  void setting_group_control(node_id ln, int num_of_sgs, int act_sg, int resv_tms) {
    if (num_of_sgs < 1 || num_of_sgs > 255 || act_sg < 1 || act_sg > 255) {
      throw nb::value_error("NumOfSG and ActSG must be in 1..255");
    }
    if (resv_tms < 0 || resv_tms > 65535) throw nb::value_error("ResvTms must be in 0..65535");
    server::setting_group_settings sg;
    sg.num_of_sgs = static_cast<std::uint8_t>(num_of_sgs);
    sg.act_sg = static_cast<std::uint8_t>(act_sg);
    sg.resv_tms = static_cast<std::uint16_t>(resv_tms);
    usable().logical_node_handle(ln).setting_group_control(sg);
    check();
  }
  void log(node_id ln, const std::string& name) {
    usable().logical_node_handle(ln).log(name);
    check();
  }
  void log_control(node_id ln, nb::dict d) {
    server::log_control_settings s;
    s.name = nb::cast<std::string>(d["name"]);
    s.data_set = nb::cast<std::string>(d["data_set"]);
    s.log_name = nb::cast<std::string>(d["log_name"]);
    s.log_ln = nb::cast<std::string>(d["log_ln"]);
    s.log_ena = nb::cast<bool>(d["log_ena"]);
    s.trg_ops = model::trigger_conditions::from_raw(nb::cast<std::uint8_t>(d["trg_ops"]));
    s.intg_pd = nb::cast<std::uint32_t>(d["intg_pd"]);
    usable().logical_node_handle(ln).log_control(std::move(s));
    check();
  }
  void goose_control(node_id ln, nb::dict d) {
    server::goose_control_settings s;
    s.name = nb::cast<std::string>(d["name"]);
    s.go_id = nb::cast<std::string>(d["go_id"]);
    s.data_set = nb::cast<std::string>(d["data_set"]);
    s.conf_rev = nb::cast<std::uint32_t>(d["conf_rev"]);
    s.go_ena = nb::cast<bool>(d["go_ena"]);
    const auto mac = bytes_from_py(d["dst_mac"]);
    if (mac.size() != 6) throw nb::value_error("a MAC address has 6 octets");
    std::copy(mac.begin(), mac.end(), s.dst_mac.begin());
    s.vlan_priority = nb::cast<std::uint8_t>(d["vlan_priority"]);
    s.vlan_id = nb::cast<std::uint16_t>(d["vlan_id"]);
    s.app_id = nb::cast<std::uint16_t>(d["app_id"]);
    s.min_time = nb::cast<std::uint32_t>(d["min_time"]);
    s.max_time = nb::cast<std::uint32_t>(d["max_time"]);
    s.fixed_offs = nb::cast<bool>(d["fixed_offs"]);
    usable().logical_node_handle(ln).goose_control(std::move(s));
    check();
  }
  void group_value(node_id da, std::uint32_t sg, nb::handle value) {
    usable().attribute_handle(da).group_value(sg, data_from_py(value));
    check();
  }
  native_model build() {
    auto& b = usable();
    auto m = b.build();
    b_.reset();
    lds_.clear();
    if (!m) raise_error(m.error());
    return native_model(std::move(*m));
  }

 private:
  server::model_builder& usable() {
    if (!b_) throw nb::value_error("the model was already built");
    if (b_->error()) raise_error(b_->error());
    return *b_;
  }
  void check() {
    if (b_->error()) raise_error(b_->error());
  }

  std::unique_ptr<server::model_builder> b_;
  std::unordered_map<node_id, server::ld_handle> lds_;
  model::parse_options parse_;
};

// ---------------------------------------------------------------------------------------------
// File stores (server/files.hpp)
//
// The native stores (memory, directory) are used directly. A Python store is reached through an
// adapter object (openiec61850._server._FileStoreAdapter) whose methods return (code, value):
// code 0 on success, a file_errc value, or -1 for an unexpected failure (already logged). The
// server calls a store synchronously on its strand, i.e. on the I/O thread; the GIL is held only
// for each call.

using file_clock = std::chrono::system_clock;

nb::object mtime_to_py(const std::optional<file_clock::time_point>& t) {
  if (!t) return nb::none();
  return nb::cast(std::chrono::duration_cast<std::chrono::duration<double>>(t->time_since_epoch()).count());
}

std::optional<file_clock::time_point> mtime_from_py(nb::handle h) {
  if (h.is_none()) return std::nullopt;
  const auto secs = nb::cast<double>(h);
  if (!std::isfinite(secs)) throw nb::value_error("invalid modification time");
  return file_clock::time_point(
      std::chrono::duration_cast<file_clock::duration>(std::chrono::duration<double>(secs)));
}

nb::object file_info_to_py(const server::file_info& f) {
  return nb::make_tuple(f.name, f.size, mtime_to_py(f.last_modified));
}

server::file_info file_info_from_py(nb::handle h) {
  const auto t = nb::cast<nb::tuple>(h);
  if (t.size() != 3) throw nb::type_error("expected (name, size, mtime)");
  return {nb::cast<std::string>(t[0]), nb::cast<std::uint64_t>(t[1]), mtime_from_py(t[2])};
}

template <typename T>
T value_or_raise(result<T> r) {
  if (!r) raise_error(r.error());
  return std::move(*r);
}

class native_file_store {
 public:
  static native_file_store memory() {
    native_file_store s;
    s.mem_ = std::make_shared<server::memory_file_store>();
    s.store_ = s.mem_;
    return s;
  }
  static native_file_store directory(const std::string& root) {
    std::optional<result<std::shared_ptr<server::directory_file_store>>> r;
    {
      const nb::gil_scoped_release release;
      r.emplace(server::directory_file_store::open(std::filesystem::path(root)));
    }
    native_file_store s;
    s.dir_ = value_or_raise(std::move(*r));
    s.store_ = s.dir_;
    return s;
  }

  [[nodiscard]] const std::shared_ptr<server::file_store>& store() const noexcept { return store_; }
  [[nodiscard]] nb::object root() const {
    if (!dir_) return nb::none();
    return nb::cast(dir_->root().string());
  }

  void put(const std::string& path, nb::handle content, nb::handle mtime) {
    auto& m = memory_only();
    auto data = bytes_from_py(content);
    const auto t = mtime_from_py(mtime);
    std::optional<result<void>> r;
    {
      const nb::gil_scoped_release release;
      r.emplace(m.put(path, std::move(data), t));
    }
    if (!*r) raise_error(r->error());
  }
  nb::object get(const std::string& path) {
    auto& m = memory_only();
    std::optional<byte_buffer> b;
    {
      const nb::gil_scoped_release release;
      b = m.get(path);
    }
    if (!b) return nb::none();
    return to_bytes(*b);
  }
  nb::object list(const std::string& directory) {
    std::optional<result<std::vector<server::file_info>>> r;
    {
      const nb::gil_scoped_release release;
      r.emplace(store_->list(directory));
    }
    nb::list out;
    for (const auto& f : value_or_raise(std::move(*r))) out.append(file_info_to_py(f));
    return out;
  }
  nb::object stat(const std::string& path) {
    std::optional<result<server::file_info>> r;
    {
      const nb::gil_scoped_release release;
      r.emplace(store_->stat(path));
    }
    return file_info_to_py(value_or_raise(std::move(*r)));
  }
  nb::object read(const std::string& path, std::uint64_t offset, std::size_t size) {
    byte_buffer buf(size);
    std::optional<result<std::size_t>> r;
    {
      const nb::gil_scoped_release release;
      r.emplace(store_->read(path, offset, buf));
    }
    buf.resize(value_or_raise(std::move(*r)));
    return to_bytes(buf);
  }
  void remove(const std::string& path) {
    std::optional<result<void>> r;
    {
      const nb::gil_scoped_release release;
      r.emplace(store_->remove(path));
    }
    if (!*r) raise_error(r->error());
  }
  void rename(const std::string& from, const std::string& to) {
    std::optional<result<void>> r;
    {
      const nb::gil_scoped_release release;
      r.emplace(store_->rename(from, to));
    }
    if (!*r) raise_error(r->error());
  }

 private:
  server::memory_file_store& memory_only() {
    if (!mem_) throw nb::type_error("only a memory file store has put() / get()");
    return *mem_;
  }

  std::shared_ptr<server::file_store> store_;
  std::shared_ptr<server::memory_file_store> mem_;
  std::shared_ptr<server::directory_file_store> dir_;
};

class py_file_store final : public server::file_store {
 public:
  explicit py_file_store(nb::handle adapter) : adapter_(std::make_shared<py_ref>(adapter)) {}

  result<std::vector<server::file_info>> list(std::string_view directory) override {
    return call<std::vector<server::file_info>>("list", [](nb::handle v) {
      std::vector<server::file_info> out;
      for (nb::handle f : v) out.push_back(file_info_from_py(f));
      return out;
    }, std::string(directory));
  }
  result<server::file_info> stat(std::string_view path) override {
    return call<server::file_info>("stat", [](nb::handle v) { return file_info_from_py(v); },
                                   std::string(path));
  }
  result<std::size_t> read(std::string_view path, std::uint64_t offset,
                           std::span<std::uint8_t> out) override {
    return call<std::size_t>(
        "read",
        [out](nb::handle v) -> std::size_t {
          const auto b = bytes_from_py(v);
          const std::size_t n = b.size() < out.size() ? b.size() : out.size();
          std::copy_n(b.begin(), n, out.begin());
          return n;
        },
        std::string(path), offset, out.size());
  }
  result<void> remove(std::string_view path) override {
    return status(call<bool>("remove", [](nb::handle) { return true; }, std::string(path)));
  }
  result<void> rename(std::string_view from, std::string_view to) override {
    return status(call<bool>("rename", [](nb::handle) { return true; }, std::string(from),
                             std::string(to)));
  }

 private:
  static result<void> status(const result<bool>& r) {
    if (!r) return r.error();
    return {};
  }

  // The adapter answers (code, value). The arguments are C++ values: Python objects may only be
  // created once the GIL is held.
  template <typename T, typename Convert, typename... Args>
  result<T> call(const char* method, Convert convert, const Args&... args) {
    const auto failure = std::make_error_code(std::errc::io_error);
    if (interpreter_finalizing()) return failure;
    const nb::gil_scoped_acquire gil;
    try {
      nb::object r = nb::handle(adapter_->get()).attr(method)(nb::cast(args)...);
      const auto t = nb::cast<nb::tuple>(r);
      const int code = nb::cast<int>(t[0]);
      if (code == 0) return convert(t[1]);
      if (code > 0 && code <= static_cast<int>(server::file_errc::no_space)) {
        return server::make_error_code(static_cast<server::file_errc>(code));
      }
    } catch (nb::python_error& e) {
      e.discard_as_unraisable("openiec61850 file store");
    } catch (...) {
    }
    return failure;
  }

  std::shared_ptr<py_ref> adapter_;
};

std::shared_ptr<server::file_store> file_store_from_py(nb::handle h) {
  if (h.is_none()) return nullptr;
  if (nb::isinstance<native_file_store>(h)) return nb::cast<native_file_store&>(h).store();
  return std::make_shared<py_file_store>(h);
}

// ---------------------------------------------------------------------------------------------
// Server

struct native_completion {
  server::control_completion c;

  [[nodiscard]] bool valid() const noexcept { return c.valid(); }
  bool complete(int kind, int cause) const {
    if (kind < 0 || kind > 2) throw nb::value_error("unknown control result kind");
    if (cause < 0 || cause > 255) throw nb::value_error("AddCause out of range");
    const server::control_result r{static_cast<server::control_result::kind>(kind),
                                   static_cast<server::add_cause>(cause)};
    const nb::gil_scoped_release release;
    return c.complete(r);
  }
};

nb::object opt_timestamp(const std::optional<model::timestamp>& t) {
  return t ? data_to_py(t->to_mms()) : nb::none();
}

nb::dict control_request_to_py(const server::control_request& r) {
  nb::dict d;
  d["association"] = r.association;
  d["action"] = static_cast<int>(r.action);
  d["object"] = r.object.to_string();
  d["ctl_model"] = static_cast<int>(r.ctl_model);
  d["ctl_val"] = r.ctl_val.valid() ? data_to_py(r.ctl_val) : nb::none();
  d["oper_time"] = opt_timestamp(r.oper_time);
  d["or_cat"] = r.or_cat ? nb::cast(static_cast<int>(*r.or_cat)) : nb::none();
  d["or_ident"] = to_bytes(r.or_ident);
  d["ctl_num"] = r.ctl_num;
  d["t"] = opt_timestamp(r.t);
  d["test"] = r.test;
  d["synchro_check"] = r.check.synchrocheck();
  d["interlock_check"] = r.check.interlock_check();
  return d;
}

nb::object opt_oid(const std::optional<ber::oid>& o) {
  return o ? nb::cast(o->to_string()) : nb::none();
}

nb::dict association_request_to_py(const association::association_request& r) {
  nb::dict d;
  d["password"] = r.password ? nb::cast(*r.password) : nb::none();
  d["calling_ap_title"] = opt_oid(r.calling_ap_title);
  d["calling_ae_qualifier"] = r.calling_ae_qualifier ? nb::cast(*r.calling_ae_qualifier) : nb::none();
  d["called_ap_title"] = opt_oid(r.called_ap_title);
  d["called_ae_qualifier"] = r.called_ae_qualifier ? nb::cast(*r.called_ae_qualifier) : nb::none();
  d["remote"] = nb::make_tuple(r.remote_endpoint.address().to_string(), r.remote_endpoint.port());
  return d;
}

nb::dict goose_state_to_py(const server::goose_control_state& g) {
  nb::dict d;
  d["reference"] = g.reference.to_string();
  d["go_ena"] = g.go_ena;
  d["go_id"] = g.go_id;
  d["dat_set"] = g.dat_set;
  std::vector<std::string> members;
  for (const auto& m : g.members) members.push_back(m.to_string());
  d["members"] = members;
  d["conf_rev"] = g.conf_rev;
  d["nds_com"] = g.nds_com;
  d["dst_mac"] = nb::bytes(g.dst_mac.data(), g.dst_mac.size());
  d["vlan_priority"] = g.vlan_priority;
  d["vlan_id"] = g.vlan_id;
  d["app_id"] = g.app_id;
  d["min_time"] = g.min_time;
  d["max_time"] = g.max_time;
  d["fixed_offs"] = g.fixed_offs;
  return d;
}

using hook = std::shared_ptr<py_ref>;

hook make_hook(nb::handle fn) {
  if (fn.is_none()) return nullptr;
  return std::make_shared<py_ref>(fn);
}

void report_unraisable(nb::python_error& e, const char* where) {
  e.discard_as_unraisable(where);
}

server::server_options server_options_from_py(nb::dict d, hook on_write, hook on_control,
                                              hook authorize, hook on_setting_group,
                                              hook on_goose_control) {
  server::server_options o;
  auto given = [&](const char* k) { return d.contains(k) && !d[k].is_none(); };
  if (given("max_associations")) o.max_associations = nb::cast<std::size_t>(d["max_associations"]);
  if (given("vendor")) o.ident.vendor = nb::cast<std::string>(d["vendor"]);
  if (given("model")) o.ident.model = nb::cast<std::string>(d["model"]);
  if (given("revision")) o.ident.revision = nb::cast<std::string>(d["revision"]);
  if (given("brcb_buffer_capacity")) o.brcb_buffer_capacity = nb::cast<std::size_t>(d["brcb_buffer_capacity"]);
  if (given("max_data_set_members")) o.max_data_set_members = nb::cast<std::size_t>(d["max_data_set_members"]);
  if (given("max_persistent_data_sets")) {
    o.max_persistent_data_sets = nb::cast<std::size_t>(d["max_persistent_data_sets"]);
  }
  if (given("max_association_data_sets")) {
    o.max_association_data_sets = nb::cast<std::size_t>(d["max_association_data_sets"]);
  }
  if (given("max_names_per_response")) {
    o.max_names_per_response = nb::cast<std::size_t>(d["max_names_per_response"]);
  }
  if (given("auto_timestamp")) o.auto_timestamp = nb::cast<bool>(d["auto_timestamp"]);
  if (given("default_sbo_timeout")) o.default_sbo_timeout = seconds_from_py(d["default_sbo_timeout"]);
  if (given("operate_timeout")) o.operate_timeout = seconds_from_py(d["operate_timeout"]);
  if (given("check_test_mode")) o.check_test_mode = nb::cast<bool>(d["check_test_mode"]);
  if (given("association_timeout")) o.association.association_timeout = seconds_from_py(d["association_timeout"]);
  if (given("handshake_timeout")) o.association.transport.handshake_timeout = seconds_from_py(d["handshake_timeout"]);
  if (given("log_capacity")) o.log_capacity = nb::cast<std::size_t>(d["log_capacity"]);
  if (given("max_open_files")) o.max_open_files = nb::cast<std::size_t>(d["max_open_files"]);
  if (d.contains("files")) o.files = file_store_from_py(d["files"]);

  std::optional<std::string> password;
  if (given("password")) password = nb::cast<std::string>(d["password"]);

  if (on_write) {
    o.on_write = [fn = std::move(on_write)](const server::write_event& e)
        -> std::optional<mms::data_access_error> {
      using dae = mms::data_access_error;
      if (interpreter_finalizing()) return dae::temporarily_unavailable;
      const nb::gil_scoped_acquire gil;
      try {
        nb::object r = nb::handle(fn->get())(e.association, e.reference.to_string(), data_to_py(e.value));
        const int code = nb::cast<int>(r);
        if (code < 0) return std::nullopt;
        if (code > static_cast<int>(dae::object_value_invalid)) return dae::object_access_denied;
        return static_cast<dae>(code);
      } catch (nb::python_error& err) {
        report_unraisable(err, "openiec61850 on_write");
      } catch (...) {
      }
      return dae::object_access_denied;
    };
  }
  if (on_control) {
    o.on_control = [fn = std::move(on_control)](const server::control_request& r) {
      const auto refused = server::control_result::refused(server::add_cause::unknown);
      if (interpreter_finalizing()) return refused;
      const nb::gil_scoped_acquire gil;
      try {
        nb::object res = nb::handle(fn->get())(control_request_to_py(r),
                                               nb::cast(native_completion{r.completion}));
        const auto t = nb::cast<nb::tuple>(res);
        const int kind = nb::cast<int>(t[0]);
        const int cause = nb::cast<int>(t[1]);
        if (kind < 0 || kind > 2 || cause < 0 || cause > 255) return refused;
        return server::control_result{static_cast<server::control_result::kind>(kind),
                                      static_cast<server::add_cause>(cause)};
      } catch (nb::python_error& err) {
        report_unraisable(err, "openiec61850 on_control");
      } catch (...) {
      }
      return refused;
    };
  }
  if (on_setting_group) {
    o.on_setting_group = [fn = std::move(on_setting_group)](const server::setting_group_event& e)
        -> std::optional<mms::data_access_error> {
      using dae = mms::data_access_error;
      if (interpreter_finalizing()) return dae::temporarily_unavailable;
      const nb::gil_scoped_acquire gil;
      try {
        nb::object r = nb::handle(fn->get())(e.association, e.logical_device, static_cast<int>(e.action),
                                             e.group);
        const int code = nb::cast<int>(r);
        if (code < 0) return std::nullopt;
        if (code > static_cast<int>(dae::object_value_invalid)) return dae::object_access_denied;
        return static_cast<dae>(code);
      } catch (nb::python_error& err) {
        report_unraisable(err, "openiec61850 on_setting_group");
      } catch (...) {
      }
      return dae::object_access_denied;
    };
  }
  if (on_goose_control) {
    o.on_goose_control = [fn = std::move(on_goose_control)](const server::goose_control_event& e) {
      if (interpreter_finalizing()) return;
      const nb::gil_scoped_acquire gil;
      try {
        nb::handle(fn->get())(e.association, goose_state_to_py(e.state));
      } catch (nb::python_error& err) {
        report_unraisable(err, "openiec61850 on_goose_control");
      } catch (...) {
      }
    };
  }
  if (authorize || password) {
    o.association.authorize = [fn = std::move(authorize), password = std::move(password)](
                                  const association::association_request& r,
                                  mms::initiate_response&) {
      using association::association_decision;
      const auto denied =
          association_decision::rejected(iso::acse::service_user_diagnostic::authentication_failure);
      if (password && r.password != password) return denied;
      if (!fn) return association_decision::accepted();
      if (interpreter_finalizing()) return denied;
      const nb::gil_scoped_acquire gil;
      try {
        if (nb::cast<bool>(nb::handle(fn->get())(association_request_to_py(r)))) {
          return association_decision::accepted();
        }
      } catch (nb::python_error& err) {
        report_unraisable(err, "openiec61850 authorize");
      } catch (...) {
      }
      return denied;
    };
  }
  return o;
}

asio::awaitable<result<bool>> wait_stopped_op(std::shared_ptr<server::server> s) {
  co_await s->wait_stopped();
  co_return true;
}

asio::awaitable<result<mms::data>> read_op(std::shared_ptr<server::server> s, model::object_reference r) {
  co_return co_await s->read(std::move(r));
}

asio::awaitable<result<mms::data>> read_sg_op(std::shared_ptr<server::server> s, model::object_reference r,
                                               std::uint8_t sg) {
  co_return co_await s->read_setting_group(std::move(r), sg);
}

asio::awaitable<result<server::goose_control_state>> goose_control_op(std::shared_ptr<server::server> s,
                                                                      model::object_reference r) {
  co_return co_await s->goose_control(std::move(r));
}

asio::awaitable<result<std::vector<server::goose_control_state>>> goose_controls_op(
    std::shared_ptr<server::server> s) {
  co_return co_await s->goose_controls();
}

server::data_update update_from_py(nb::handle ref, nb::handle value, nb::handle quality,
                                   nb::handle timestamp, const model::parse_options& opts) {
  server::data_update u{ref_from_py(ref, opts), data_from_py(value), std::nullopt, std::nullopt};
  if (!quality.is_none()) u.quality = model::quality::from_raw(nb::cast<std::uint16_t>(quality));
  if (!timestamp.is_none()) {
    const auto t = data_from_py(timestamp);
    const auto utc = t.as_utc_time();
    if (!utc) throw nb::type_error("timestamp must be a tagged utc-time");
    u.timestamp = model::timestamp(*utc);
  }
  return u;
}

class native_server {
 public:
  static native_server start(const native_model& m, const std::string& host, int port, nb::dict options,
                             nb::handle on_write, nb::handle on_control, nb::handle authorize,
                             nb::handle on_setting_group, nb::handle on_goose_control) {
    if (port < 0 || port > 65535) throw nb::value_error("port out of range");
    std::error_code ec;
    const auto address = asio::ip::make_address(host, ec);
    if (ec) throw nb::value_error(("invalid listen address '" + host + "'").c_str());
    auto o = server_options_from_py(options, make_hook(on_write), make_hook(on_control),
                                    make_hook(authorize), make_hook(on_setting_group),
                                    make_hook(on_goose_control));
    server::data_model copy = m.get();
    const asio::ip::tcp::endpoint ep{address, static_cast<std::uint16_t>(port)};
    std::optional<result<server::server>> r;
    {
      const nb::gil_scoped_release release;
      r.emplace(server::server::start(runtime().get_executor(), std::move(copy), ep, std::move(o)));
    }
    if (!*r) raise_error(r->error());
    return native_server(std::make_shared<server::server>(std::move(**r)), m.get().edition());
  }

  native_server(native_server&&) noexcept = default;
  native_server& operator=(native_server&&) = delete;
  native_server(const native_server&) = delete;
  native_server& operator=(const native_server&) = delete;
  ~native_server() {
    if (s_) s_->stop();
  }

  void stop() {
    const nb::gil_scoped_release release;
    s_->stop();
  }
  nb::object wait_stopped() {
    return launch(s_->get_executor(), wait_stopped_op(s_), [](bool) { return nb::none(); });
  }
  [[nodiscard]] std::size_t association_count() const noexcept { return s_->association_count(); }
  [[nodiscard]] nb::object local_endpoint() const {
    const auto& e = s_->local_endpoint();
    return nb::make_tuple(e.address().to_string(), e.port());
  }

  void update(nb::handle ref, nb::handle value, nb::handle quality, nb::handle timestamp) {
    auto u = update_from_py(ref, value, quality, timestamp, parse_);
    std::optional<result<void>> r;
    {
      const nb::gil_scoped_release release;
      r.emplace(s_->update(u.reference, std::move(u.value), u.quality, u.timestamp));
    }
    if (!*r) raise_error(r->error());
  }
  // items: iterable of (ref, value, quality, timestamp)
  void update_many(nb::handle items) {
    std::vector<server::data_update> batch;
    for (nb::handle it : items) {
      const auto t = nb::cast<nb::tuple>(it);
      if (t.size() != 4) throw nb::type_error("expected (ref, value, quality, timestamp)");
      batch.push_back(update_from_py(t[0], t[1], t[2], t[3], parse_));
    }
    std::optional<result<void>> r;
    {
      const nb::gil_scoped_release release;
      r.emplace(s_->update(std::move(batch)));
    }
    if (!*r) raise_error(r->error());
  }
  nb::object read(nb::handle ref) {
    return launch(s_->get_executor(), read_op(s_, ref_from_py(ref, parse_)),
                  [](mms::data d) { return data_to_py(d); });
  }
  void select_active_setting_group(const std::string& ld, int sg) {
    if (sg < 0 || sg > 255) throw nb::value_error("setting group out of range");
    std::optional<result<void>> r;
    {
      const nb::gil_scoped_release release;
      r.emplace(s_->select_active_setting_group(ld, static_cast<std::uint8_t>(sg)));
    }
    if (!*r) raise_error(r->error());
  }
  nb::object read_setting_group(nb::handle ref, int sg) {
    if (sg < 0 || sg > 255) throw nb::value_error("setting group out of range");
    return launch(s_->get_executor(), read_sg_op(s_, ref_from_py(ref, parse_), static_cast<std::uint8_t>(sg)),
                  [](mms::data d) { return data_to_py(d); });
  }
  nb::object goose_control(nb::handle ref) {
    return launch(s_->get_executor(), goose_control_op(s_, ref_from_py(ref, parse_)),
                  [](server::goose_control_state g) { return nb::object(goose_state_to_py(g)); });
  }
  nb::object goose_controls() {
    return launch(s_->get_executor(), goose_controls_op(s_),
                  [](std::vector<server::goose_control_state> v) {
                    nb::list out;
                    for (const auto& g : v) out.append(goose_state_to_py(g));
                    return nb::object(std::move(out));
                  });
  }

 private:
  native_server(std::shared_ptr<server::server> s, model::edition e)
      : s_(std::move(s)), parse_(lenient_options(e)) {}

  std::shared_ptr<server::server> s_;
  model::parse_options parse_;
};

}  // namespace

void bind_server(nb::module_& m) {
  m.def(
      "type_definition",
      [](const std::string& type, std::int32_t size, std::uint32_t count, int edition) -> nb::object {
        const auto t = basic_type_from(type);
        nb::dict d = basic_def(t, size, edition_from(edition), "", std::nullopt);
        if (count == 0) return d;
        nb::list ch;
        ch.append(d);
        return make_def("", std::nullopt, "array", static_cast<int>(mms::data_type::array), nb::none(), 0,
                        false, count, ch);
      },
      nb::arg("basic_type"), nb::arg("size") = 0, nb::arg("count") = 0, nb::arg("edition") = 2,
      "The data definition dict of a basic type (an array of it when count > 0).");

  nb::class_<native_model>(m, "Model", "Native immutable server data model. Use openiec61850.Model.")
      .def_prop_ro("edition", &native_model::edition)
      .def_prop_ro("node_count", &native_model::node_count)
      .def("logical_devices", &native_model::logical_devices)
      .def("node", &native_model::node_info, nb::arg("id"),
           "(name, kind, parent, children, fc, basic_type, size, count, (dchg, qchg, dupd))")
      .def("initial_value", &native_model::initial_value, nb::arg("id"))
      .def("reference_of", &native_model::reference_of, nb::arg("id"))
      .def("find", &native_model::find, nb::arg("ref"))
      .def("definition", &native_model::definition, nb::arg("ref"))
      .def("node_definition", &native_model::node_definition, nb::arg("id"), nb::arg("fc") = nb::none())
      .def("data_sets", &native_model::data_sets)
      .def("report_controls", &native_model::report_controls)
      .def("setting_group_controls", &native_model::setting_group_controls)
      .def("logs", &native_model::logs)
      .def("log_controls", &native_model::log_controls)
      .def("goose_controls", &native_model::goose_controls)
      .def_static("load_scl", &load_scl, nb::arg("source"), nb::arg("is_text"), nb::arg("ied") = "",
                  nb::arg("access_point") = "", nb::arg("strict") = false,
                  nb::arg("setting_group") = 0,
                  "Returns (Model | None, [(level, code, line, message)], error | None).");

  nb::class_<native_builder>(m, "ModelBuilder", "Native model builder. Use openiec61850.ModelBuilder.")
      .def(nb::init<int>(), nb::arg("edition") = 2)
      .def("logical_device", &native_builder::logical_device, nb::arg("name"))
      .def("logical_node", &native_builder::logical_node, nb::arg("ld"), nb::arg("name"))
      .def("data_object", &native_builder::data_object, nb::arg("ln"), nb::arg("name"))
      .def("sub_object", &native_builder::sub_object, nb::arg("parent"), nb::arg("name"))
      .def("attribute", &native_builder::attribute, nb::arg("parent"), nb::arg("under_object"),
           nb::arg("name"), nb::arg("fc").none(), nb::arg("basic_type").none(), nb::arg("size") = 0,
           nb::arg("count") = 0, nb::arg("triggers") = nb::none(), nb::arg("value") = nb::none())
      .def("set_value", &native_builder::set_value, nb::arg("da"), nb::arg("value"))
      .def("data_set", &native_builder::data_set, nb::arg("ln"), nb::arg("name"), nb::arg("members"))
      .def("report_control", &native_builder::report_control, nb::arg("ln"), nb::arg("settings"))
      .def("setting_group_control", &native_builder::setting_group_control, nb::arg("ln"),
           nb::arg("num_of_sgs"), nb::arg("act_sg"), nb::arg("resv_tms"))
      .def("log", &native_builder::log, nb::arg("ln"), nb::arg("name"))
      .def("log_control", &native_builder::log_control, nb::arg("ln"), nb::arg("settings"))
      .def("goose_control", &native_builder::goose_control, nb::arg("ln"), nb::arg("settings"))
      .def("group_value", &native_builder::group_value, nb::arg("da"), nb::arg("sg"), nb::arg("value"))
      .def("build", &native_builder::build);

  nb::class_<native_completion>(m, "_ControlCompletion", "Completes a pending Operate (internal).")
      .def_prop_ro("valid", &native_completion::valid)
      .def("complete", &native_completion::complete, nb::arg("kind"), nb::arg("cause") = 0);

  nb::class_<native_server>(m, "Server", "Native IEC 61850 server. Use openiec61850.Server.")
      .def_static("start", &native_server::start, nb::arg("model"), nb::arg("host"), nb::arg("port"),
                  nb::arg("options"), nb::arg("on_write").none(), nb::arg("on_control").none(),
                  nb::arg("authorize").none(), nb::arg("on_setting_group").none() = nb::none(),
                  nb::arg("on_goose_control").none() = nb::none())
      .def("stop", &native_server::stop)
      .def("wait_stopped", &native_server::wait_stopped)
      .def_prop_ro("association_count", &native_server::association_count)
      .def_prop_ro("local_endpoint", &native_server::local_endpoint)
      .def("update", &native_server::update, nb::arg("ref"), nb::arg("value"),
           nb::arg("quality").none() = nb::none(), nb::arg("timestamp").none() = nb::none())
      .def("update_many", &native_server::update_many, nb::arg("items"))
      .def("read", &native_server::read, nb::arg("ref"))
      .def("select_active_setting_group", &native_server::select_active_setting_group, nb::arg("ld"),
           nb::arg("sg"))
      .def("read_setting_group", &native_server::read_setting_group, nb::arg("ref"), nb::arg("sg"))
      .def("goose_control", &native_server::goose_control, nb::arg("ref"))
      .def("goose_controls", &native_server::goose_controls);

  nb::class_<native_file_store>(m, "FileStore", "Native file store. Use openiec61850.MemoryFileStore / DirectoryFileStore.")
      .def_static("memory", &native_file_store::memory)
      .def_static("directory", &native_file_store::directory, nb::arg("root"))
      .def_prop_ro("root", &native_file_store::root)
      .def("put", &native_file_store::put, nb::arg("path"), nb::arg("content"), nb::arg("mtime").none() = nb::none())
      .def("get", &native_file_store::get, nb::arg("path"))
      .def("list", &native_file_store::list, nb::arg("directory") = "")
      .def("stat", &native_file_store::stat, nb::arg("path"))
      .def("read", &native_file_store::read, nb::arg("path"), nb::arg("offset"), nb::arg("size"))
      .def("remove", &native_file_store::remove, nb::arg("path"))
      .def("rename", &native_file_store::rename, nb::arg("from_"), nb::arg("to"));
}

}  // namespace openiec61850::python
