// ACSI services mapped onto MMS (IEC 61850-8-1 §9 - §17).

#include <algorithm>
#include <array>
#include <limits>
#include <string_view>
#include <utility>
#include <variant>

#include "detail.hpp"

namespace openiec61850::client::detail {

using asio::awaitable;
using model::fc;

namespace {

constexpr auto violation = openiec61850::errc::protocol_violation;
constexpr auto misuse = openiec61850::errc::invalid_state;

std::error_code err(errc e) noexcept { return make_error_code(e); }

template <typename R>
const R* response_as(const association::service_response& r) noexcept {
  return std::get_if<R>(&r.service());
}

awaitable<result<association::service_response>> call(assoc_ptr a,
                                                       mms::confirmed_service_request svc) {
  auto r = co_await a->request(std::move(svc));
  if (!r) {
    a.record(r.failure());
    co_return request_error_code(r.failure());
  }
  co_return std::move(*r);
}

std::vector<mms::variable_spec> specs_of(const std::vector<model::mms_variable>& vars) {
  std::vector<mms::variable_spec> specs;
  specs.reserve(vars.size());
  for (const auto& v : vars) specs.push_back(v.spec());
  return specs;
}

// --- name lists

}  // namespace

awaitable<result<std::vector<std::string>>> name_list_on(assoc_ptr a, mms::object_class cls,
                                                          std::string domain) {
  std::vector<std::string> out;
  std::optional<std::string> after;
  for (;;) {
    mms::get_name_list_request req;
    req.cls = cls;
    req.scope = domain.empty() ? mms::object_scope::vmd_specific : mms::object_scope::domain_specific;
    req.domain_id = domain;
    if (after) req.continue_after = std::string_view(*after);
    auto r = co_await call(a, req);
    if (!r) co_return r.error();
    const auto* nl = response_as<mms::get_name_list_response>(*r);
    if (nl == nullptr) co_return violation;
    std::size_t n = 0;
    for (const auto id : nl->identifiers) {
      out.emplace_back(id);
      ++n;
    }
    if (!nl->more_follows) break;
    // ISO 9506-1 §10.5: continueAfter is the last name received; an empty page would loop.
    if (n == 0) co_return violation;
    after = out.back();
  }
  co_return out;
}

namespace {

// --- data access

awaitable<result<std::vector<result<mms::data>>>> read_on(assoc_ptr a,
                                                          mms::variable_access_specification spec,
                                                          std::optional<std::size_t> expected) {
  auto r = co_await call(a, mms::read_request{false, spec});
  if (!r) co_return r.error();
  const auto* rr = response_as<mms::read_response>(*r);
  if (rr == nullptr) co_return violation;
  std::vector<result<mms::data>> out;
  for (const auto ar : rr->results) {
    if (ar.failure) {
      out.emplace_back(err(to_errc(*ar.failure)));
      continue;
    }
    auto d = mms::data::from_view(ar.value.view());
    if (!d) co_return violation;
    out.emplace_back(std::move(*d));
  }
  if (expected && out.size() != *expected) co_return violation;
  co_return out;
}

awaitable<result<std::vector<result<void>>>> write_on(assoc_ptr a,
                                                      mms::variable_access_specification spec,
                                                      const std::vector<mms::data>& values,
                                                      std::optional<std::size_t> expected) {
  const std::vector<mms::data_ref> refs(values.begin(), values.end());
  auto r = co_await call(a, mms::write_request{spec, refs});
  if (!r) co_return r.error();
  const auto* wr = response_as<mms::write_response>(*r);
  if (wr == nullptr) co_return violation;
  std::vector<result<void>> out;
  for (const auto res : wr->results) {
    if (res.failure) {
      out.emplace_back(err(to_errc(*res.failure)));
    } else {
      out.emplace_back();
    }
  }
  if (expected && out.size() != *expected) co_return violation;
  co_return out;
}

awaitable<result<void>> write_one(assoc_ptr a, const model::mms_variable& var, mms::data value) {
  const std::vector<mms::variable_spec> specs{var.spec()};
  const std::vector<mms::data> values{std::move(value)};
  auto r = co_await write_on(a, mms::variable_access_specification::list(specs), values, 1);
  if (!r) co_return r.error();
  co_return (*r)[0];
}

// --- type descriptions

awaitable<result<mms::type_description>> type_on(assoc_ptr a, std::string domain,
                                                 std::string item) {
  mms::get_variable_access_attributes_request req{mms::object_name::domain(domain, item)};
  auto r = co_await call(a, req);
  if (!r) co_return r.error();
  const auto* t = response_as<mms::get_variable_access_attributes_response>(*r);
  if (t == nullptr) co_return violation;
  co_return t->type;
}

const mms::type_description* find_component(const mms::type_description& t,
                                             std::string_view name) noexcept {
  if (t.type != mms::data_type::structure) return nullptr;
  for (const auto& c : t.components) {
    if (c.name == name) return &c.type;
  }
  return nullptr;
}

bool is_string_type(mms::data_type t) noexcept {
  return t == mms::data_type::octet_string || t == mms::data_type::visible_string ||
         t == mms::data_type::mms_string || t == mms::data_type::bit_string;
}

// The bit-string and octet-string types that deduce_basic_type cannot tell apart, recognised by
// the attribute names of IEC 61850-7-2 / 7-3.
std::optional<model::basic_type> refine(std::string_view name, const mms::type_description& t) {
  if (t.type == mms::data_type::bit_string) {
    if (name == "OptFlds" && t.size == 10) return model::basic_type::optional_fields;
    if ((name == "TrgOps" || name == "TrgOp") && t.size == 6) {
      return model::basic_type::trigger_conditions;
    }
    if (name == "stVal" && t.size == 2) return model::basic_type::dbpos;
    if (name == "ctlVal" && t.size == 2) return model::basic_type::tcmd;
    if (name == "Check" && t.size == 2) return model::basic_type::check;
  }
  if (t.type == mms::data_type::octet_string && name == "EntryID" && t.size == 8) {
    return model::basic_type::entry_id;
  }
  if (t.type == mms::data_type::visible_string && (name == "DatSet" || name == "LogRef") &&
      (t.size == -129 || t.size == -65)) {
    return model::basic_type::object_reference;
  }
  return model::deduce_basic_type(t);
}

data_definition convert(const mms::type_description& t, std::string name,
                        std::optional<model::functional_constraint> f) {
  data_definition d;
  d.name = std::move(name);
  d.fc = f;
  d.mms_type = t.type;
  switch (t.type) {
    case mms::data_type::structure:
      d.type = data_definition::kind::structure;
      d.children.reserve(t.components.size());
      for (const auto& c : t.components) d.children.push_back(convert(c.type, c.name, f));
      break;
    case mms::data_type::array:
      d.type = data_definition::kind::array;
      d.array_size = t.number_of_elements;
      if (!t.components.empty()) d.children.push_back(convert(t.components.front().type, {}, f));
      break;
    default:
      d.type = data_definition::kind::basic;
      d.basic_type = refine(d.name, t);
      if (is_string_type(t.type) && t.size < 0) {
        d.size = t.size == std::numeric_limits<std::int32_t>::min()
                     ? std::numeric_limits<std::int32_t>::max()
                     : -t.size;
        d.variable_length = true;
      } else {
        d.size = t.size;
      }
      break;
  }
  return d;
}

// Merges `src` (the same node under another FC) into `dst`.
void merge(data_definition& dst, data_definition src) {
  if (dst.fc != src.fc) dst.fc.reset();
  for (auto& c : src.children) {
    auto it = std::find_if(dst.children.begin(), dst.children.end(),
                           [&](const data_definition& x) { return x.name == c.name; });
    if (it != dst.children.end() && it->type == data_definition::kind::structure &&
        c.type == data_definition::kind::structure) {
      merge(*it, std::move(c));
    } else {
      dst.children.push_back(std::move(c));
    }
  }
}

void collect_fcs(const data_definition& d, std::vector<model::functional_constraint>& out) {
  if (d.fc) {
    out.push_back(*d.fc);
    return;
  }
  for (const auto& c : d.children) collect_fcs(c, out);
}

void add_unique(std::vector<std::string>& v, std::string_view name) {
  if (std::find(v.begin(), v.end(), name) == v.end()) v.emplace_back(name);
}

result<model::functional_constraint> rcb_kind(const model::object_reference& rcb) {
  if (!rcb.has_ln() || rcb.path().empty() || !rcb.fc()) return misuse;
  if (*rcb.fc() != fc::BR && *rcb.fc() != fc::RP) return misuse;
  return *rcb.fc();
}

constexpr std::array<std::string_view, 15> brcb_attributes{
    "RptID", "RptEna", "DatSet",   "ConfRev", "OptFlds",     "BufTm",   "SqNum", "TrgOps",
    "IntgPd", "GI",    "PurgeBuf", "EntryID", "TimeOfEntry", "ResvTms", "Owner"};
constexpr std::array<std::string_view, 12> urcb_attributes{
    "RptID", "RptEna", "Resv",  "DatSet", "ConfRev", "OptFlds",
    "BufTm", "SqNum",  "TrgOps", "IntgPd", "GI",     "Owner"};

result<std::uint32_t> to_u32(const mms::data& d) {
  auto v = to_uint64(d);
  if (!v) return v.error();
  if (*v > std::numeric_limits<std::uint32_t>::max()) return openiec61850::errc::value_out_of_range;
  return static_cast<std::uint32_t>(*v);
}

template <typename T, typename F>
std::error_code set_from(std::optional<T>& field, F&& convert_fn) {
  auto v = convert_fn();
  if (!v) {
    return v.error() == openiec61850::errc::invalid_state ? err(errc::type_mismatch) : v.error();
  }
  field = std::move(*v);
  return {};
}

std::error_code assign(rcb_values& out, std::string_view name, const mms::data& d) {
  if (name == "RptID") return set_from(out.rpt_id, [&] { return to_string(d); });
  if (name == "RptEna") return set_from(out.rpt_ena, [&] { return to_bool(d); });
  if (name == "Resv") return set_from(out.resv, [&] { return to_bool(d); });
  if (name == "DatSet") return set_from(out.dat_set, [&] { return to_string(d); });
  if (name == "ConfRev") return set_from(out.conf_rev, [&] { return to_u32(d); });
  if (name == "OptFlds") return set_from(out.opt_flds, [&] { return model::optional_fields::from_mms(d); });
  if (name == "BufTm") return set_from(out.buf_tm, [&] { return to_u32(d); });
  if (name == "SqNum") return set_from(out.sq_num, [&] { return to_u32(d); });
  if (name == "TrgOps") {
    return set_from(out.trg_ops, [&] { return model::trigger_conditions::from_mms(d); });
  }
  if (name == "IntgPd") return set_from(out.intg_pd, [&] { return to_u32(d); });
  if (name == "GI") return set_from(out.gi, [&] { return to_bool(d); });
  if (name == "PurgeBuf") return set_from(out.purge_buf, [&] { return to_bool(d); });
  if (name == "EntryID") return set_from(out.entry_id, [&] { return to_entry_id(d); });
  if (name == "TimeOfEntry") return set_from(out.time_of_entry, [&] { return to_entry_time(d); });
  if (name == "ResvTms") {
    return set_from(out.resv_tms, [&]() -> result<std::int32_t> {
      auto v = to_int64(d);
      if (!v) return v.error();
      if (*v < std::numeric_limits<std::int32_t>::min() ||
          *v > std::numeric_limits<std::int32_t>::max()) {
        return openiec61850::errc::value_out_of_range;
      }
      return static_cast<std::int32_t>(*v);
    });
  }
  if (name == "Owner") return set_from(out.owner, [&] { return to_bytes(d); });
  return {};
}

result<model::mms_variable> attribute(const client_state& s, const model::object_reference& rcb,
                                      std::string_view name) {
  auto c = rcb.child(name, std::nullopt, s.parse);
  if (!c) return c.error();
  return model::to_mms_variable(*c, s.limits);
}

awaitable<result<void>> write_attribute(std::shared_ptr<client_state> s, assoc_ptr a,
                                        model::object_reference rcb, std::string_view name,
                                        mms::data value) {
  auto v = attribute(*s, rcb, name);
  if (!v) co_return v.error();
  co_return co_await write_one(a, *v, std::move(value));
}

awaitable<result<rcb_values>> get_rcb_values_on(std::shared_ptr<client_state> s, assoc_ptr a,
                                                model::object_reference rcb) {
  auto kind = rcb_kind(rcb);
  if (!kind) co_return kind.error();
  const std::span<const std::string_view> names =
      *kind == fc::BR ? std::span<const std::string_view>(brcb_attributes)
                      : std::span<const std::string_view>(urcb_attributes);
  std::vector<model::mms_variable> vars;
  for (const auto n : names) {
    auto v = attribute(*s, rcb, n);
    if (!v) co_return v.error();
    vars.push_back(std::move(*v));
  }
  const auto specs = specs_of(vars);
  auto values = co_await read_on(a, mms::variable_access_specification::list(specs), vars.size());
  if (!values) co_return values.error();
  rcb_values out;
  std::error_code first;
  bool any = false;
  for (std::size_t i = 0; i < names.size(); ++i) {
    const auto& v = (*values)[i];
    if (!v) {
      if (!first) first = v.error();
      continue;
    }
    any = true;
    if (auto ec = assign(out, names[i], *v)) co_return ec;
  }
  if (!any) co_return first;
  co_return out;
}

awaitable<result<void>> set_rcb_values_on(std::shared_ptr<client_state> s, assoc_ptr a,
                                          model::object_reference rcb, rcb_settings w) {
  if (auto kind = rcb_kind(rcb); !kind) co_return kind.error();
  std::vector<std::pair<std::string_view, mms::data>> writes;
  if (w.resv) writes.emplace_back("Resv", mms::data::boolean(*w.resv));
  if (w.resv_tms) writes.emplace_back("ResvTms", mms::data::integer(*w.resv_tms));
  if (w.rpt_id) writes.emplace_back("RptID", mms::data::visible_string(*w.rpt_id));
  if (w.dat_set) {
    auto text = model::to_mms_data_set_reference(*w.dat_set, s->limits);
    if (!text) co_return text.error();
    writes.emplace_back("DatSet", mms::data::visible_string(*text));
  }
  if (w.opt_flds) writes.emplace_back("OptFlds", w.opt_flds->to_mms());
  if (w.buf_tm) writes.emplace_back("BufTm", mms::data::unsigned_integer(*w.buf_tm));
  if (w.trg_ops) writes.emplace_back("TrgOps", w.trg_ops->to_mms());
  if (w.intg_pd) writes.emplace_back("IntgPd", mms::data::unsigned_integer(*w.intg_pd));
  if (w.purge_buf) writes.emplace_back("PurgeBuf", mms::data::boolean(*w.purge_buf));
  if (w.entry_id) writes.emplace_back("EntryID", w.entry_id->to_mms());
  if (w.rpt_ena) writes.emplace_back("RptEna", mms::data::boolean(*w.rpt_ena));
  if (w.gi) writes.emplace_back("GI", mms::data::boolean(*w.gi));
  for (auto& [name, value] : writes) {
    auto r = co_await write_attribute(s, a, rcb, name, std::move(value));
    if (!r) co_return r;
  }
  co_return result<void>{};
}

awaitable<result<data_set_directory>> data_set_directory_on(std::shared_ptr<client_state> s,
                                                            assoc_ptr a,
                                                            model::object_reference ds) {
  auto name = model::to_mms_named_variable_list(ds, s->limits);
  if (!name) co_return name.error();
  auto r = co_await call(a, mms::get_named_variable_list_attributes_request{name->view()});
  if (!r) co_return r.error();
  const auto* nvl = response_as<mms::get_named_variable_list_attributes_response>(*r);
  if (nvl == nullptr) co_return violation;
  data_set_directory out;
  out.deletable = nvl->mms_deletable;
  for (const auto spec : nvl->variables) {
    auto m = model::from_mms_variable(spec.name, spec.alternate_access, s->parse);
    if (!m) co_return violation;
    out.members.push_back(std::move(*m));
  }
  co_return out;
}

struct enable_mode {
  std::optional<model::entry_id> entry;
  bool purge = false;
  bool gi = false;
  bool restore = false;
};

awaitable<result<rcb_values>> enable_on(std::shared_ptr<client_state> s, assoc_ptr a,
                                        model::object_reference rcb, report_settings settings,
                                        enable_mode mode) {
  auto kind = rcb_kind(rcb);
  if (!kind) co_return kind.error();
  const bool buffered = *kind == fc::BR;

  rcb_settings w;
  if (!buffered && settings.reserve) w.resv = true;
  if (buffered) w.resv_tms = settings.resv_tms;
  w.rpt_id = settings.rpt_id;
  w.dat_set = settings.data_set;
  if (settings.opt_flds) w.opt_flds = settings.opt_flds->configurable(buffered);
  w.trg_ops = settings.trg_ops;
  w.buf_tm = settings.buf_tm;
  w.intg_pd = settings.intg_pd;
  if (buffered) {
    if (mode.purge) w.purge_buf = true;
    // 7-2 §17.2.2.13: EntryID written before RptEna resumes after that entry.
    w.entry_id = mode.entry;
  }
  if (auto r = co_await set_rcb_values_on(s, a, rcb, w); !r) co_return r.error();

  auto values = co_await get_rcb_values_on(s, a, rcb);
  if (!values) co_return values.error();

  subscription sub;
  sub.rcb = rcb;
  sub.buffered = buffered;
  sub.settings = settings;
  sub.rpt_id = values->rpt_id.value_or(std::string{});
  sub.data_set = values->dat_set;
  sub.reserved = w.resv.value_or(false);
  if (auto text = model::to_mms_reference(rcb, s->limits)) sub.mms_reference = std::move(*text);
  if (auto ds = values->data_set(s->parse)) {
    auto dir = co_await data_set_directory_on(s, a, *ds);
    if (!dir) co_return dir.error();
    sub.members = std::move(dir->members);
  }
  const auto key = rcb.to_string();
  if (mode.restore && !s->subscriptions.contains(key)) {
    co_return err(errc::not_connected);  // disabled meanwhile
  }
  sub.last_entry_id = mode.entry;
  if (auto it = s->subscriptions.find(key); it != s->subscriptions.end() && !sub.last_entry_id) {
    sub.last_entry_id = it->second.last_entry_id;
  }
  s->subscriptions.insert_or_assign(key, std::move(sub));

  auto enabled = co_await write_attribute(s, a, rcb, "RptEna", mms::data::boolean(true));
  if (!enabled) {
    if (!mode.restore) s->subscriptions.erase(key);
    co_return enabled.error();
  }
  if (mode.gi) {
    auto gi = co_await write_attribute(s, a, rcb, "GI", mms::data::boolean(true));
    if (!gi) co_return gi.error();
  }
  co_return std::move(*values);
}

}  // namespace

std::error_code request_error_code(const association::request_error& e) {
  if (e.code == association::errc::service_error && e.service_error) {
    namespace ec = mms::error_code;
    const auto& se = *e.service_error;
    if (se.cls == mms::error_class::definition) {
      if (se.code == ec::definition::object_undefined) return err(errc::object_not_found);
      if (se.code == ec::definition::object_exists) return err(errc::object_exists);
    }
    if (se.cls == mms::error_class::access) {
      if (se.code == ec::access::object_non_existent) return err(errc::object_not_found);
      if (se.code == ec::access::object_access_denied) return err(errc::access_denied);
    }
  }
  return e.code;
}

// --- directory and definition

awaitable<result<std::vector<std::string>>> get_name_list_op(std::shared_ptr<client_state> s, error_details* d,
                                                              mms::object_class cls,
                                                              std::string domain) {
  auto a = s->current(d);
  if (!a) co_return a.error();
  co_return co_await name_list_on(*a, cls, std::move(domain));
}

awaitable<result<std::vector<std::string>>> get_server_directory_op(std::shared_ptr<client_state> s, error_details* d) {
  co_return co_await get_name_list_op(s, d, mms::object_class::domain, {});
}

awaitable<result<std::vector<std::string>>> get_logical_device_directory_op(
    std::shared_ptr<client_state> s, error_details* d, std::string ld) {
  if (ld.empty()) co_return misuse;
  auto names = co_await get_name_list_op(s, d, mms::object_class::named_variable, std::move(ld));
  if (!names) co_return names.error();
  std::vector<std::string> out;
  for (auto& n : *names) {
    if (n.find('$') == std::string::npos) out.push_back(std::move(n));
  }
  co_return out;
}

awaitable<result<logical_node_directory>> get_logical_node_directory_op(
    std::shared_ptr<client_state> s, error_details* d, model::object_reference ln) {
  if (!ln.has_ln() || !ln.path().empty()) co_return misuse;
  auto a = s->current(d);
  if (!a) co_return a.error();
  const std::string ld(ln.ld());
  const std::string name(ln.ln());
  auto t = co_await type_on(*a, ld, name);
  if (!t) co_return t.error();
  if (t->type != mms::data_type::structure) co_return violation;

  logical_node_directory out;
  for (const auto& comp : t->components) {
    const auto f = model::parse_functional_constraint(comp.name);
    if (!f) continue;
    for (const auto& item : comp.type.components) {
      switch (*f) {
        case fc::BR: add_unique(out.brcbs, item.name); break;
        case fc::RP: add_unique(out.urcbs, item.name); break;
        case fc::LG: add_unique(out.lcbs, item.name); break;
        case fc::GO: add_unique(out.gocbs, item.name); break;
        case fc::MS: add_unique(out.msvcbs, item.name); break;
        case fc::US: add_unique(out.usvcbs, item.name); break;
        case fc::GS: break;
        case fc::SP:
          if (item.name == "SGCB") {
            out.sgcb = true;
            break;
          }
          add_unique(out.data_objects, item.name);
          break;
        default: add_unique(out.data_objects, item.name); break;
      }
    }
  }

  auto lists = co_await name_list_on(*a, mms::object_class::named_variable_list, ld);
  if (!lists) co_return lists.error();
  const std::string prefix = name + "$";
  for (const auto& item : *lists) {
    if (item.starts_with(prefix) && item.find('$', prefix.size()) == std::string::npos) {
      out.data_sets.push_back(item.substr(prefix.size()));
    }
  }
  co_return out;
}

awaitable<result<data_definition>> get_data_definition_op(std::shared_ptr<client_state> s, error_details* d,
                                                          model::object_reference ref) {
  if (!ref.has_ln() || ref.has_index()) co_return misuse;
  if (ref.fc() == fc::XX) co_return misuse;
  auto a = s->current(d);
  if (!a) co_return a.error();
  const std::string ld(ref.ld());
  const std::string ln(ref.ln());
  const auto leaf = ref.leaf();
  std::string name = leaf ? std::string(leaf->name) : ln;

  if (ref.fc()) {
    auto item = model::to_mms_item_id(ref, s->limits);
    if (!item) co_return item.error();
    auto t = co_await type_on(*a, ld, std::move(*item));
    if (!t) co_return t.error();
    co_return convert(*t, std::move(name), ref.fc());
  }

  // Without an FC: the LN's TypeDescription, whose components are the FCs (8-1 §9).
  auto t = co_await type_on(*a, ld, ln);
  if (!t) co_return t.error();
  if (t->type != mms::data_type::structure) co_return violation;
  const bool ln_level = ref.path().empty();
  std::optional<data_definition> out;
  for (const auto& comp : t->components) {
    const auto f = model::parse_functional_constraint(comp.name);
    if (!f) continue;
    const mms::type_description* node = &comp.type;
    for (const auto pe : ref.path()) {
      node = find_component(*node, pe.name);
      if (node == nullptr) break;
    }
    if (node == nullptr) continue;
    auto conv = convert(*node, name, *f);
    if (!out) {
      out = std::move(conv);
      if (ln_level) out->fc.reset();
    } else {
      merge(*out, std::move(conv));
    }
  }
  if (!out) co_return err(errc::object_not_found);
  co_return std::move(*out);
}

awaitable<result<std::vector<data_directory_entry>>> get_data_directory_op(
    std::shared_ptr<client_state> s, error_details* d, model::object_reference ref) {
  auto def = co_await get_data_definition_op(s, d, std::move(ref));
  if (!def) co_return def.error();
  std::vector<data_directory_entry> out;
  if (def->type != data_definition::kind::structure) co_return out;
  for (const auto& c : def->children) {
    data_directory_entry e;
    e.name = c.name;
    collect_fcs(c, e.fcs);
    std::sort(e.fcs.begin(), e.fcs.end());
    e.fcs.erase(std::unique(e.fcs.begin(), e.fcs.end()), e.fcs.end());
    out.push_back(std::move(e));
  }
  co_return out;
}

// --- data access

awaitable<result<mms::data>> read_op(std::shared_ptr<client_state> s, error_details* d, model::object_reference ref) {
  std::vector<model::object_reference> refs;
  refs.push_back(std::move(ref));
  auto r = co_await read_many_op(s, d, std::move(refs));
  if (!r) co_return r.error();
  co_return std::move((*r)[0]);
}

awaitable<result<std::vector<result<mms::data>>>> read_many_op(
    std::shared_ptr<client_state> s, error_details* d, std::vector<model::object_reference> refs) {
  if (refs.empty()) co_return misuse;
  std::vector<model::mms_variable> vars;
  vars.reserve(refs.size());
  for (const auto& ref : refs) {
    auto v = model::to_mms_variable(ref, s->limits);
    if (!v) co_return v.error();
    vars.push_back(std::move(*v));
  }
  auto a = s->current(d);
  if (!a) co_return a.error();
  const auto specs = specs_of(vars);
  co_return co_await read_on(*a, mms::variable_access_specification::list(specs), vars.size());
}

awaitable<result<void>> write_op(std::shared_ptr<client_state> s, error_details* d, model::object_reference ref,
                                 mms::data value) {
  std::vector<write_item> items;
  items.push_back({std::move(ref), std::move(value)});
  auto r = co_await write_many_op(s, d, std::move(items));
  if (!r) co_return r.error();
  co_return (*r)[0];
}

awaitable<result<std::vector<result<void>>>> write_many_op(std::shared_ptr<client_state> s, error_details* d,
                                                           std::vector<write_item> items) {
  if (items.empty()) co_return misuse;
  std::vector<model::mms_variable> vars;
  std::vector<mms::data> values;
  for (auto& item : items) {
    if (!item.value.valid()) co_return misuse;
    auto v = model::to_mms_variable(item.reference, s->limits);
    if (!v) co_return v.error();
    vars.push_back(std::move(*v));
    values.push_back(std::move(item.value));
  }
  auto a = s->current(d);
  if (!a) co_return a.error();
  const auto specs = specs_of(vars);
  co_return co_await write_on(*a, mms::variable_access_specification::list(specs), values,
                              vars.size());
}

// --- data sets

awaitable<result<data_set_directory>> get_data_set_directory_op(std::shared_ptr<client_state> s, error_details* d,
                                                                model::object_reference ds) {
  auto a = s->current(d);
  if (!a) co_return a.error();
  co_return co_await data_set_directory_on(s, *a, std::move(ds));
}

awaitable<result<void>> create_data_set_op(std::shared_ptr<client_state> s, error_details* d,
                                           model::object_reference ds,
                                           std::vector<model::object_reference> members) {
  if (members.empty()) co_return misuse;
  auto name = model::to_mms_named_variable_list(ds, s->limits);
  if (!name) co_return name.error();
  std::vector<model::mms_variable> vars;
  for (const auto& m : members) {
    auto v = model::to_mms_variable(m, s->limits);
    if (!v) co_return v.error();
    vars.push_back(std::move(*v));
  }
  auto a = s->current(d);
  if (!a) co_return a.error();
  const auto specs = specs_of(vars);
  auto r = co_await call(*a, mms::define_named_variable_list_request{name->view(), specs});
  if (!r) co_return r.error();
  if (response_as<mms::define_named_variable_list_response>(*r) == nullptr) co_return violation;
  co_return result<void>{};
}

awaitable<result<void>> delete_data_set_op(std::shared_ptr<client_state> s, error_details* d,
                                           model::object_reference ds) {
  auto name = model::to_mms_named_variable_list(ds, s->limits);
  if (!name) co_return name.error();
  auto a = s->current(d);
  if (!a) co_return a.error();
  const std::vector<mms::object_name> names{name->view()};
  auto r = co_await call(*a, mms::delete_named_variable_list_request{mms::delete_scope::specific,
                                                                     names, std::nullopt});
  if (!r) co_return r.error();
  const auto* resp = response_as<mms::delete_named_variable_list_response>(*r);
  if (resp == nullptr) co_return violation;
  if (resp->number_deleted == 0) {
    co_return err(resp->number_matched == 0 ? errc::object_not_found : errc::not_deleted);
  }
  co_return result<void>{};
}

awaitable<result<std::vector<result<mms::data>>>> get_data_set_values_op(
    std::shared_ptr<client_state> s, error_details* d, model::object_reference ds) {
  auto name = model::to_mms_named_variable_list(ds, s->limits);
  if (!name) co_return name.error();
  auto a = s->current(d);
  if (!a) co_return a.error();
  co_return co_await read_on(*a, mms::variable_access_specification::named(name->view()),
                             std::nullopt);
}

awaitable<result<std::vector<result<void>>>> set_data_set_values_op(
    std::shared_ptr<client_state> s, error_details* d, model::object_reference ds, std::vector<mms::data> values) {
  if (values.empty()) co_return misuse;
  auto name = model::to_mms_named_variable_list(ds, s->limits);
  if (!name) co_return name.error();
  auto a = s->current(d);
  if (!a) co_return a.error();
  co_return co_await write_on(*a, mms::variable_access_specification::named(name->view()), values,
                              values.size());
}

// --- reporting

awaitable<result<rcb_values>> get_rcb_values_op(std::shared_ptr<client_state> s, error_details* d,
                                                model::object_reference rcb) {
  auto a = s->current(d);
  if (!a) co_return a.error();
  co_return co_await get_rcb_values_on(s, *a, std::move(rcb));
}

awaitable<result<void>> set_rcb_values_op(std::shared_ptr<client_state> s, error_details* d,
                                          model::object_reference rcb, rcb_settings w) {
  auto a = s->current(d);
  if (!a) co_return a.error();
  co_return co_await set_rcb_values_on(s, *a, std::move(rcb), std::move(w));
}

awaitable<result<rcb_values>> enable_reporting_op(std::shared_ptr<client_state> s, error_details* d,
                                                  model::object_reference rcb,
                                                  report_settings settings) {
  auto a = s->current(d);
  if (!a) co_return a.error();
  enable_mode mode;
  mode.entry = settings.entry_id;
  mode.purge = settings.purge_buffer;
  mode.gi = settings.general_interrogation;
  co_return co_await enable_on(s, *a, std::move(rcb), std::move(settings), mode);
}

awaitable<result<void>> disable_reporting_op(std::shared_ptr<client_state> s, error_details* d,
                                             model::object_reference rcb) {
  auto kind = rcb_kind(rcb);
  if (!kind) co_return kind.error();
  bool reserved = false;
  if (auto it = s->subscriptions.find(rcb.to_string()); it != s->subscriptions.end()) {
    reserved = it->second.reserved;
    s->subscriptions.erase(it);
  }
  auto a = s->current(d);
  if (!a) co_return a.error();
  auto r = co_await write_attribute(s, *a, rcb, "RptEna", mms::data::boolean(false));
  if (!r) co_return r;
  if (*kind == fc::RP && reserved) {
    co_return co_await write_attribute(s, *a, rcb, "Resv", mms::data::boolean(false));
  }
  co_return result<void>{};
}

awaitable<result<void>> trigger_gi_op(std::shared_ptr<client_state> s, error_details* d,
                                      model::object_reference rcb) {
  if (auto kind = rcb_kind(rcb); !kind) co_return kind.error();
  auto a = s->current(d);
  if (!a) co_return a.error();
  co_return co_await write_attribute(s, *a, std::move(rcb), "GI", mms::data::boolean(true));
}

// --- helpers for control.cpp and acsi_services.cpp

awaitable<result<association::service_response>> call_on(assoc_ptr a,
                                                         mms::confirmed_service_request svc) {
  co_return co_await call(std::move(a), std::move(svc));
}

awaitable<result<std::vector<result<mms::data>>>> read_variables_on(
    assoc_ptr a, std::vector<model::mms_variable> vars) {
  const auto specs = specs_of(vars);
  co_return co_await read_on(a, mms::variable_access_specification::list(specs), vars.size());
}

awaitable<result<void>> write_variable_on(assoc_ptr a, model::mms_variable var, mms::data value) {
  co_return co_await write_one(a, var, std::move(value));
}

awaitable<result<mms::type_description>> type_description_on(assoc_ptr a, std::string domain,
                                                             std::string item) {
  co_return co_await type_on(a, std::move(domain), std::move(item));
}

awaitable<std::vector<rcb_error>> restore_on(std::shared_ptr<client_state> s, assoc_ptr a) {
  std::vector<rcb_error> errors;
  std::vector<std::string> keys;
  for (const auto& [k, sub] : s->subscriptions) keys.push_back(k);
  for (const auto& k : keys) {
    const auto it = s->subscriptions.find(k);
    if (it == s->subscriptions.end()) continue;
    const subscription sub = it->second;
    enable_mode mode;
    mode.restore = true;
    if (sub.buffered) mode.entry = sub.last_entry_id ? sub.last_entry_id : sub.settings.entry_id;
    mode.gi = sub.settings.general_interrogation && (!sub.buffered || !mode.entry);
    auto r = co_await enable_on(s, a, sub.rcb, sub.settings, mode);
    if (!r) {
      if (a->state() == association::association_state::closed) break;
      if (s->subscriptions.contains(k)) errors.push_back({sub.rcb, r.error()});
    }
  }
  co_return errors;
}

}  // namespace openiec61850::client::detail
