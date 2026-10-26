#include "convert.hpp"

#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>

#include <cmath>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "openiec61850/model/basic_type.hpp"
#include "openiec61850/model/functional_constraint.hpp"
#include "runtime.hpp"

namespace openiec61850::python {

namespace {

using dt = mms::data_type;

nb::object none() { return nb::none(); }

template <typename T>
nb::object opt_to_py(const std::optional<T>& v) {
  if (!v) return none();
  return nb::cast(*v);
}

// Character strings are decoded leniently (surrogateescape) so any octets survive a round trip.
nb::object text_to_py(std::string_view s) {
  PyObject* o = PyUnicode_DecodeUTF8(s.data(), static_cast<Py_ssize_t>(s.size()), "surrogateescape");
  if (o == nullptr) throw nb::python_error();
  return nb::steal(o);
}

std::string text_from_py(nb::handle h) {
  if (!PyUnicode_Check(h.ptr())) throw nb::type_error("expected str");
  PyObject* b = PyUnicode_AsEncodedString(h.ptr(), "utf-8", "surrogateescape");
  if (b == nullptr) throw nb::python_error();
  nb::object owner = nb::steal(b);
  return {PyBytes_AS_STRING(b), static_cast<std::size_t>(PyBytes_GET_SIZE(b))};
}

nb::object bits_to_py(nb::int_ tag, const ber::bit_string_view& b) {
  return nb::make_tuple(tag, to_bytes(b.bytes), b.bit_count);
}

const char* kind_name(client::data_definition::kind k) {
  switch (k) {
    case client::data_definition::kind::structure: return "structure";
    case client::data_definition::kind::array: return "array";
    case client::data_definition::kind::basic: return "basic";
  }
  return "basic";
}

const char* event_name(client::connection_event::kind k) {
  using kind = client::connection_event::kind;
  switch (k) {
    case kind::lost: return "lost";
    case kind::reconnecting: return "reconnecting";
    case kind::restored: return "restored";
    case kind::failed: return "failed";
  }
  return "lost";
}

nb::object fc_to_py(const std::optional<model::functional_constraint>& f) {
  if (!f) return none();
  return nb::cast(std::string(model::to_string(*f)));
}

nb::object support_to_py(const mms::support_options& s) {
  return nb::make_tuple(to_bytes(s.bytes()), s.bit_count());
}

nb::object endpoint_to_py(const asio::ip::tcp::endpoint& e) {
  return nb::make_tuple(e.address().to_string(), e.port());
}

[[noreturn]] void raise_invalid_reference(const std::string& text, const std::string& why) {
  nb::object cls = nb::module_::import_("openiec61850._errors").attr("InvalidReference");
  nb::object exc = cls("invalid object reference '" + text + "': " + why);
  PyErr_SetObject(cls.ptr(), exc.ptr());
  throw nb::python_error();
}

std::optional<ber::oid> oid_from_py(nb::handle h) {
  if (h.is_none()) return std::nullopt;
  const auto text = nb::cast<std::string>(h);
  auto o = ber::oid::from_string(text);
  if (!o) throw nb::value_error(("invalid object identifier '" + text + "'").c_str());
  return *o;
}

}  // namespace

nb::bytes to_bytes(byte_view b) { return nb::bytes(b.data(), b.size()); }

byte_buffer bytes_from_py(nb::handle h) {
  nb::object owner;
  if (!PyBytes_Check(h.ptr())) {
    owner = nb::steal(PyBytes_FromObject(h.ptr()));
    if (!owner.is_valid()) throw nb::python_error();
    h = owner;
  }
  const auto* p = reinterpret_cast<const std::uint8_t*>(PyBytes_AS_STRING(h.ptr()));
  return {p, p + PyBytes_GET_SIZE(h.ptr())};
}

nb::object data_to_py(const mms::data& d) {
  const nb::int_ tag(static_cast<int>(d.type()));
  switch (d.type()) {
    case dt::array:
    case dt::structure: {
      nb::list l;
      for (const auto& e : d.elements()) l.append(data_to_py(e));
      return nb::make_tuple(tag, l);
    }
    case dt::boolean: return nb::make_tuple(tag, nb::bool_(*d.as_boolean()));
    case dt::bit_string: return bits_to_py(tag, *d.as_bit_string());
    case dt::boolean_array: return bits_to_py(tag, *d.as_boolean_array());
    case dt::integer: return nb::make_tuple(tag, *d.as_int64());
    case dt::unsigned_: return nb::make_tuple(tag, *d.as_uint64());
    case dt::floating_point: return nb::make_tuple(tag, *d.as_double(), nb::bool_(d.is_double()));
    case dt::octet_string: return nb::make_tuple(tag, to_bytes(*d.as_octet_string()));
    case dt::visible_string: return nb::make_tuple(tag, text_to_py(*d.as_visible_string()));
    case dt::generalized_time: return nb::make_tuple(tag, text_to_py(*d.as_generalized_time()));
    case dt::mms_string: return nb::make_tuple(tag, text_to_py(*d.as_mms_string()));
    case dt::binary_time: {
      const auto t = *d.as_binary_time();
      return nb::make_tuple(tag, t.ms_of_day, opt_to_py(t.days));
    }
    case dt::bcd: return nb::make_tuple(tag, *d.as_bcd());
    case dt::obj_id: {
      const auto o = *d.as_obj_id();
      nb::list arcs;
      for (auto a : o) arcs.append(a);
      return nb::make_tuple(tag, nb::tuple(arcs));
    }
    case dt::utc_time: {
      const auto t = *d.as_utc_time();
      return nb::make_tuple(tag, t.seconds, t.fraction, t.quality);
    }
    case dt::invalid: break;
  }
  return nb::make_tuple(tag);
}

mms::data data_from_py(nb::handle h) {
  if (!PyTuple_Check(h.ptr()) || PyTuple_GET_SIZE(h.ptr()) < 2) {
    throw nb::type_error("expected a tagged MMS value tuple");
  }
  const auto t = nb::borrow<nb::tuple>(h);
  const auto n = t.size();
  const auto tag = static_cast<dt>(nb::cast<std::uint8_t>(t[0]));
  const auto need = [&](std::size_t k) {
    if (n < k) throw nb::type_error("tagged MMS value tuple too short");
  };
  switch (tag) {
    case dt::array:
    case dt::structure: {
      std::vector<mms::data> elements;
      for (nb::handle e : t[1]) elements.push_back(data_from_py(e));
      return tag == dt::array ? mms::data::array(std::move(elements))
                              : mms::data::structure(std::move(elements));
    }
    case dt::boolean: return mms::data::boolean(nb::cast<bool>(t[1]));
    case dt::bit_string:
    case dt::boolean_array: {
      need(3);
      const auto bytes = bytes_from_py(t[1]);
      const auto bits = nb::cast<std::size_t>(t[2]);
      if ((bits + 7) / 8 > bytes.size()) throw nb::value_error("bit string shorter than its bit count");
      return tag == dt::bit_string ? mms::data::bit_string(bytes, bits)
                                   : mms::data::boolean_array(bytes, bits);
    }
    case dt::integer: return mms::data::integer(nb::cast<std::int64_t>(t[1]));
    case dt::unsigned_: return mms::data::unsigned_integer(nb::cast<std::uint64_t>(t[1]));
    case dt::floating_point: {
      const auto v = nb::cast<double>(t[1]);
      const bool dbl = n > 2 && nb::cast<bool>(t[2]);
      if (dbl) return mms::data::floating_point(v);
      return mms::data::floating_point(static_cast<float>(v));
    }
    case dt::octet_string: return mms::data::octet_string(bytes_from_py(t[1]));
    case dt::visible_string: return mms::data::visible_string(text_from_py(t[1]));
    case dt::generalized_time: return mms::data::generalized_time(text_from_py(t[1]));
    case dt::mms_string: return mms::data::mms_string(text_from_py(t[1]));
    case dt::binary_time: {
      need(3);
      mms::binary_time bt;
      bt.ms_of_day = nb::cast<std::uint32_t>(t[1]);
      if (!t[2].is_none()) bt.days = nb::cast<std::uint16_t>(t[2]);
      return mms::data::binary_time(bt);
    }
    case dt::bcd: return mms::data::bcd(nb::cast<std::uint64_t>(t[1]));
    case dt::obj_id: {
      ber::oid o;
      for (nb::handle a : t[1]) {
        if (!o.push_back(nb::cast<std::uint32_t>(a))) throw nb::value_error("too many OID arcs");
      }
      if (!o.valid()) throw nb::value_error("invalid object identifier");
      return mms::data::obj_id(o);
    }
    case dt::utc_time: {
      need(4);
      mms::utc_time u;
      u.seconds = nb::cast<std::uint32_t>(t[1]);
      u.fraction = nb::cast<std::uint32_t>(t[2]) & 0xFFFFFFU;
      u.quality = nb::cast<std::uint8_t>(t[3]);
      return mms::data::utc_time(u);
    }
    case dt::invalid: break;
  }
  throw nb::value_error("unknown MMS data tag");
}

model::object_reference ref_from_py(nb::handle h, const model::parse_options& opts) {
  const auto text = nb::cast<std::string>(nb::str(h));
  auto r = model::object_reference::parse(text, opts);
  if (!r) raise_invalid_reference(text, r.error().message());
  return std::move(*r);
}

nb::object ref_to_py(const model::object_reference& r) { return nb::cast(r.to_string()); }

nb::object opt_ref_to_py(const std::optional<model::object_reference>& r) {
  if (!r) return none();
  return ref_to_py(*r);
}

std::chrono::milliseconds seconds_from_py(nb::handle h) {
  const auto s = nb::cast<double>(h);
  if (!std::isfinite(s) || s < 0) throw nb::value_error("durations must be finite and non-negative");
  return std::chrono::milliseconds{static_cast<std::int64_t>(std::llround(s * 1000.0))};
}

nb::object entry_time_to_py(const model::entry_time& t) {
  return nb::make_tuple(t.ms_of_day, opt_to_py(t.days));
}

model::entry_time entry_time_from_py(nb::handle h) {
  const auto t = nb::cast<nb::tuple>(h);
  model::entry_time e;
  e.ms_of_day = nb::cast<std::uint32_t>(t[0]);
  if (!t[1].is_none()) e.days = nb::cast<std::uint16_t>(t[1]);
  return e;
}

model::entry_id entry_id_from_py(nb::handle h) {
  const auto b = bytes_from_py(h);
  auto id = model::entry_id::from_bytes(b);
  if (!id) throw nb::value_error("an EntryID has exactly 8 octets");
  return *id;
}

nb::object directory_to_py(const client::logical_node_directory& d) {
  nb::dict o;
  o["data_objects"] = nb::cast(d.data_objects);
  o["data_sets"] = nb::cast(d.data_sets);
  o["brcbs"] = nb::cast(d.brcbs);
  o["urcbs"] = nb::cast(d.urcbs);
  o["lcbs"] = nb::cast(d.lcbs);
  o["gocbs"] = nb::cast(d.gocbs);
  o["msvcbs"] = nb::cast(d.msvcbs);
  o["usvcbs"] = nb::cast(d.usvcbs);
  o["sgcb"] = d.sgcb;
  return o;
}

nb::object definition_to_py(const client::data_definition& d) {
  nb::dict o;
  o["name"] = d.name;
  o["fc"] = fc_to_py(d.fc);
  o["kind"] = kind_name(d.type);
  o["mms_type"] = static_cast<int>(d.mms_type);
  o["basic_type"] = d.basic_type ? nb::cast(std::string(model::to_string(*d.basic_type))) : none();
  o["size"] = d.size;
  o["variable_length"] = d.variable_length;
  o["array_size"] = d.array_size;
  nb::list children;
  for (const auto& c : d.children) children.append(definition_to_py(c));
  o["children"] = children;
  return o;
}

nb::object rcb_values_to_py(const client::rcb_values& v) {
  nb::dict o;
  o["rpt_id"] = opt_to_py(v.rpt_id);
  o["rpt_ena"] = opt_to_py(v.rpt_ena);
  o["resv"] = opt_to_py(v.resv);
  o["dat_set"] = opt_to_py(v.dat_set);
  o["conf_rev"] = opt_to_py(v.conf_rev);
  o["opt_flds"] = v.opt_flds ? nb::cast(v.opt_flds->raw()) : none();
  o["buf_tm"] = opt_to_py(v.buf_tm);
  o["sq_num"] = opt_to_py(v.sq_num);
  o["trg_ops"] = v.trg_ops ? nb::cast(v.trg_ops->raw()) : none();
  o["intg_pd"] = opt_to_py(v.intg_pd);
  o["gi"] = opt_to_py(v.gi);
  o["purge_buf"] = opt_to_py(v.purge_buf);
  o["entry_id"] = v.entry_id ? nb::object(to_bytes(v.entry_id->bytes())) : none();
  o["time_of_entry"] = v.time_of_entry ? entry_time_to_py(*v.time_of_entry) : none();
  o["resv_tms"] = opt_to_py(v.resv_tms);
  o["owner"] = v.owner ? nb::object(to_bytes(*v.owner)) : none();
  return o;
}

nb::object report_to_py(const client::report& r) {
  nb::dict o;
  o["rpt_id"] = text_to_py(r.rpt_id);
  o["opt_flds"] = r.opt_flds.raw();
  o["seq_num"] = opt_to_py(r.seq_num);
  o["time_of_entry"] = r.time_of_entry ? entry_time_to_py(*r.time_of_entry) : none();
  o["data_set"] = r.data_set ? text_to_py(*r.data_set) : none();
  o["buffer_overflow"] = opt_to_py(r.buffer_overflow);
  o["entry_id"] = r.entry_id ? nb::object(to_bytes(r.entry_id->bytes())) : none();
  o["conf_rev"] = opt_to_py(r.conf_rev);
  o["sub_seq_num"] = opt_to_py(r.sub_seq_num);
  o["more_segments_follow"] = opt_to_py(r.more_segments_follow);
  nb::list inclusion;
  for (bool b : r.inclusion) inclusion.append(nb::bool_(b));
  o["inclusion"] = inclusion;
  nb::list entries;
  for (const auto& e : r.entries) {
    nb::dict x;
    x["index"] = e.index;
    x["data_reference"] = text_to_py(e.data_reference);
    x["reference"] = opt_ref_to_py(e.reference);
    x["value"] = data_to_py(e.value);
    x["reason"] = e.reason ? nb::cast(e.reason->raw()) : none();
    entries.append(x);
  }
  o["entries"] = entries;
  o["rcb"] = opt_ref_to_py(r.rcb);
  o["lost_before"] = r.lost_before;
  return o;
}

nb::object event_to_py(const client::connection_event& e) {
  nb::dict o;
  o["kind"] = event_name(e.type);
  o["error"] = e.error ? make_error(e.error) : none();
  o["attempt"] = e.attempt;
  nb::list errors;
  for (const auto& x : e.rcb_errors) errors.append(nb::make_tuple(ref_to_py(x.rcb), make_error(x.error)));
  o["rcb_errors"] = errors;
  return o;
}

nb::object association_info_to_py(const association::association_info& i) {
  const auto& n = i.negotiated;
  nb::dict neg;
  neg["local_detail_calling"] = opt_to_py(n.local_detail_calling);
  neg["local_detail_called"] = opt_to_py(n.local_detail_called);
  neg["max_serv_outstanding_calling"] = n.max_serv_outstanding_calling;
  neg["max_serv_outstanding_called"] = n.max_serv_outstanding_called;
  neg["data_structure_nesting_level"] =
      n.data_structure_nesting_level ? nb::cast(static_cast<int>(*n.data_structure_nesting_level))
                                     : none();
  neg["version_number"] = n.version_number;
  neg["parameter_cbb"] = support_to_py(n.parameter_cbb);
  neg["services_supported_calling"] = support_to_py(n.services_supported_calling);
  neg["services_supported_called"] = support_to_py(n.services_supported_called);
  nb::dict o;
  o["negotiated"] = neg;
  o["peer_ap_title"] = i.peer_ap_title ? nb::cast(i.peer_ap_title->to_string()) : none();
  o["peer_ae_qualifier"] = opt_to_py(i.peer_ae_qualifier);
  o["local_endpoint"] = endpoint_to_py(i.local_endpoint);
  o["remote_endpoint"] = endpoint_to_py(i.remote_endpoint);
  return o;
}

nb::object timestamp_to_py(const std::optional<model::timestamp>& t) {
  return t ? data_to_py(t->to_mms()) : none();
}

nb::object sgcb_values_to_py(const client::sgcb_values& v) {
  nb::dict o;
  o["num_of_sgs"] = v.num_of_sgs;
  o["act_sg"] = v.act_sg;
  o["edit_sg"] = v.edit_sg;
  o["cnf_edit"] = v.cnf_edit;
  o["lact_tm"] = timestamp_to_py(v.lact_tm);
  o["resv_tms"] = opt_to_py(v.resv_tms);
  return o;
}

nb::object lcb_values_to_py(const client::lcb_values& v) {
  nb::dict o;
  o["log_ena"] = opt_to_py(v.log_ena);
  o["log_ref"] = v.log_ref ? text_to_py(*v.log_ref) : none();
  o["dat_set"] = v.dat_set ? text_to_py(*v.dat_set) : none();
  o["old_entr_tm"] = v.old_entr_tm ? entry_time_to_py(*v.old_entr_tm) : none();
  o["new_entr_tm"] = v.new_entr_tm ? entry_time_to_py(*v.new_entr_tm) : none();
  o["old_ent"] = v.old_ent ? nb::object(to_bytes(v.old_ent->bytes())) : none();
  o["new_ent"] = v.new_ent ? nb::object(to_bytes(v.new_ent->bytes())) : none();
  o["trg_ops"] = v.trg_ops ? nb::cast(v.trg_ops->raw()) : none();
  o["intg_pd"] = opt_to_py(v.intg_pd);
  return o;
}

nb::object log_entries_to_py(std::vector<client::log_entry> v) {
  nb::list out;
  for (const auto& e : v) {
    nb::list data;
    for (const auto& d : e.data) {
      data.append(nb::make_tuple(text_to_py(d.reference), data_to_py(d.value),
                                 d.reason ? nb::cast(d.reason->raw()) : none()));
    }
    out.append(nb::make_tuple(to_bytes(e.entry_id.bytes()), entry_time_to_py(e.time), data));
  }
  return out;
}

nb::object file_entry_to_py(const client::file_entry& e) {
  nb::object mtime = none();
  if (e.last_modified) {
    const auto d = std::chrono::duration_cast<std::chrono::duration<double>>(
        e.last_modified->time_since_epoch());
    mtime = nb::cast(d.count());
  }
  return nb::make_tuple(text_to_py(e.name), e.size, mtime);
}

nb::object gocb_values_to_py(const client::gocb_values& v) {
  nb::dict o;
  o["go_ena"] = opt_to_py(v.go_ena);
  o["go_id"] = v.go_id ? text_to_py(*v.go_id) : none();
  o["dat_set"] = v.dat_set ? text_to_py(*v.dat_set) : none();
  o["conf_rev"] = opt_to_py(v.conf_rev);
  o["nds_com"] = opt_to_py(v.nds_com);
  if (v.dst_address) {
    const auto& a = *v.dst_address;
    o["dst_address"] = nb::make_tuple(to_bytes(a.mac), a.priority, a.vid, a.app_id);
  } else {
    o["dst_address"] = none();
  }
  o["min_time"] = opt_to_py(v.min_time);
  o["max_time"] = opt_to_py(v.max_time);
  o["fixed_offs"] = opt_to_py(v.fixed_offs);
  return o;
}

namespace {

struct dict_reader {
  nb::dict d;

  [[nodiscard]] bool has(const char* k) const { return d.contains(k); }
  // Set and not None.
  [[nodiscard]] bool given(const char* k) const { return d.contains(k) && !d[k].is_none(); }
  [[nodiscard]] nb::object at(const char* k) const { return d[k]; }
  template <typename T>
  void read(const char* k, T& out) const {
    if (given(k)) out = nb::cast<T>(at(k));
  }
  template <typename T>
  void read_opt(const char* k, std::optional<T>& out) const {
    if (given(k)) out = nb::cast<T>(at(k));
  }
};

dict_reader reader(nb::handle h) {
  if (!PyDict_Check(h.ptr())) throw nb::type_error("expected a dict");
  return {nb::borrow<nb::dict>(h)};
}

}  // namespace

client::report_settings report_settings_from_py(nb::handle h, const model::parse_options& opts) {
  const auto d = reader(h);
  client::report_settings s;
  d.read_opt("rpt_id", s.rpt_id);
  if (d.given("data_set")) s.data_set = ref_from_py(d.at("data_set"), opts);
  if (d.given("opt_flds")) s.opt_flds = model::optional_fields::from_raw(nb::cast<std::uint16_t>(d.at("opt_flds")));
  if (d.given("trg_ops")) s.trg_ops = model::trigger_conditions::from_raw(nb::cast<std::uint8_t>(d.at("trg_ops")));
  d.read_opt("buf_tm", s.buf_tm);
  d.read_opt("intg_pd", s.intg_pd);
  d.read("reserve", s.reserve);
  d.read_opt("resv_tms", s.resv_tms);
  if (d.given("entry_id")) s.entry_id = entry_id_from_py(d.at("entry_id"));
  d.read("purge_buffer", s.purge_buffer);
  d.read("general_interrogation", s.general_interrogation);
  return s;
}

client::rcb_settings rcb_settings_from_py(nb::handle h, const model::parse_options& opts) {
  const auto d = reader(h);
  client::rcb_settings s;
  d.read_opt("resv", s.resv);
  d.read_opt("resv_tms", s.resv_tms);
  d.read_opt("rpt_id", s.rpt_id);
  if (d.given("dat_set")) s.dat_set = ref_from_py(d.at("dat_set"), opts);
  if (d.given("opt_flds")) s.opt_flds = model::optional_fields::from_raw(nb::cast<std::uint16_t>(d.at("opt_flds")));
  d.read_opt("buf_tm", s.buf_tm);
  if (d.given("trg_ops")) s.trg_ops = model::trigger_conditions::from_raw(nb::cast<std::uint8_t>(d.at("trg_ops")));
  d.read_opt("intg_pd", s.intg_pd);
  d.read_opt("purge_buf", s.purge_buf);
  if (d.given("entry_id")) s.entry_id = entry_id_from_py(d.at("entry_id"));
  d.read_opt("rpt_ena", s.rpt_ena);
  d.read_opt("gi", s.gi);
  return s;
}

client::client_options client_options_from_py(nb::handle h) {
  const auto d = reader(h);
  client::client_options o;
  auto& a = o.association;
  d.read("host", a.host);
  d.read("port", a.port);
  d.read_opt("password", a.password);
  // AP titles: absent keeps the default, None omits the field.
  if (d.has("calling_ap_title")) a.calling_ap_title = oid_from_py(d.at("calling_ap_title"));
  if (d.has("calling_ae_qualifier")) {
    a.calling_ae_qualifier = d.given("calling_ae_qualifier")
                                 ? std::optional<std::int64_t>(nb::cast<std::int64_t>(d.at("calling_ae_qualifier")))
                                 : std::nullopt;
  }
  if (d.has("called_ap_title")) a.called_ap_title = oid_from_py(d.at("called_ap_title"));
  if (d.has("called_ae_qualifier")) {
    a.called_ae_qualifier = d.given("called_ae_qualifier")
                                ? std::optional<std::int64_t>(nb::cast<std::int64_t>(d.at("called_ae_qualifier")))
                                : std::nullopt;
  }
  if (d.given("connect_timeout")) a.transport.connect_timeout = seconds_from_py(d.at("connect_timeout"));
  if (d.given("handshake_timeout")) a.transport.handshake_timeout = seconds_from_py(d.at("handshake_timeout"));
  if (d.given("association_timeout")) a.association_timeout = seconds_from_py(d.at("association_timeout"));
  if (d.given("request_timeout")) a.request_timeout = seconds_from_py(d.at("request_timeout"));
  if (d.given("release_timeout")) a.release_timeout = seconds_from_py(d.at("release_timeout"));
  if (d.given("calling_tsap")) a.transport.cotp.calling_tsap = bytes_from_py(d.at("calling_tsap"));
  if (d.given("called_tsap")) a.transport.cotp.called_tsap = bytes_from_py(d.at("called_tsap"));
  if (d.given("max_tpdu_size")) a.transport.cotp.max_tpdu_size = nb::cast<std::size_t>(d.at("max_tpdu_size"));
  if (d.given("calling_session_selector")) a.calling_session_selector = bytes_from_py(d.at("calling_session_selector"));
  if (d.given("called_session_selector")) a.called_session_selector = bytes_from_py(d.at("called_session_selector"));
  if (d.given("calling_presentation_selector")) {
    a.calling_presentation_selector = bytes_from_py(d.at("calling_presentation_selector"));
  }
  if (d.given("called_presentation_selector")) {
    a.called_presentation_selector = bytes_from_py(d.at("called_presentation_selector"));
  }
  if (d.has("local_detail")) {
    a.initiate.local_detail_calling = d.given("local_detail")
                                          ? std::optional<std::int32_t>(nb::cast<std::int32_t>(d.at("local_detail")))
                                          : std::nullopt;
  }
  d.read("max_serv_outstanding_calling", a.initiate.max_serv_outstanding_calling);
  d.read("max_serv_outstanding_called", a.initiate.max_serv_outstanding_called);
  if (d.has("nesting_level")) {
    a.initiate.data_structure_nesting_level =
        d.given("nesting_level") ? std::optional<std::int8_t>(nb::cast<std::int8_t>(d.at("nesting_level")))
                                 : std::nullopt;
  }
  d.read("unconfirmed_queue_capacity", a.unconfirmed_queue_capacity);
  d.read("max_nesting", a.decode.max_nesting);
  d.read("keep_alive", a.transport.keep_alive);
  d.read("no_delay", a.transport.no_delay);
  if (d.given("edition")) o.edition = static_cast<model::edition>(nb::cast<std::uint8_t>(d.at("edition")));
  d.read("strict_ln_names", o.strict_ln_names);
  if (d.given("recovery")) {
    const auto r = reader(d.at("recovery"));
    o.recovery.enabled = true;
    r.read("enabled", o.recovery.enabled);
    if (r.given("backoff")) {
      o.recovery.backoff.clear();
      for (nb::handle s : r.at("backoff")) o.recovery.backoff.push_back(seconds_from_py(s));
    }
    r.read("max_attempts", o.recovery.max_attempts);
  }
  d.read("report_queue_capacity", o.report_queue_capacity);
  d.read("event_queue_capacity", o.event_queue_capacity);
  return o;
}

client::lcb_settings lcb_settings_from_py(nb::handle h, const model::parse_options& opts) {
  const auto d = reader(h);
  client::lcb_settings s;
  if (d.given("dat_set")) s.dat_set = ref_from_py(d.at("dat_set"), opts);
  if (d.given("trg_ops")) s.trg_ops = model::trigger_conditions::from_raw(nb::cast<std::uint8_t>(d.at("trg_ops")));
  d.read_opt("intg_pd", s.intg_pd);
  d.read_opt("log_ena", s.log_ena);
  return s;
}

client::gocb_settings gocb_settings_from_py(nb::handle h, const model::parse_options& opts) {
  const auto d = reader(h);
  client::gocb_settings s;
  d.read_opt("go_id", s.go_id);
  if (d.given("dat_set")) s.dat_set = ref_from_py(d.at("dat_set"), opts);
  d.read_opt("go_ena", s.go_ena);
  return s;
}

}  // namespace openiec61850::python
