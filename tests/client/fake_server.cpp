#include "fake_server.hpp"

#include "openiec61850/model/enums.hpp"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <deque>
#include <limits>
#include <utility>
#include <variant>

#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>

namespace openiec61850::testing {

namespace {

using asio::awaitable;
using association::incoming_request;
using association::server_association;
using td = mms::type_description;
using dae = mms::data_access_error;

constexpr std::string_view ld0 = "IED1LD0";

td structure(std::initializer_list<std::pair<const char*, td>> components) {
  std::vector<mms::type_component> v;
  for (const auto& [name, type] : components) v.push_back({name, type});
  return td::structure(std::move(v));
}

td quality() { return td::bit_string(13); }
td visible129() { return td::visible_string(-129); }

td status_bool() { return structure({{"stVal", td::boolean()}, {"q", quality()}, {"t", td::utc_time()}}); }
td mod() { return structure({{"stVal", td::integer(8)}, {"q", quality()}, {"t", td::utc_time()}}); }
td cmv() {
  return structure({{"cVal", structure({{"mag", structure({{"f", td::float32()}})}})},
                    {"q", quality()},
                    {"t", td::utc_time()}});
}

td brcb() {
  return structure({{"RptID", visible129()},       {"RptEna", td::boolean()},
                    {"DatSet", visible129()},      {"ConfRev", td::unsigned_integer(32)},
                    {"OptFlds", td::bit_string(10)}, {"BufTm", td::unsigned_integer(32)},
                    {"SqNum", td::unsigned_integer(16)}, {"TrgOps", td::bit_string(6)},
                    {"IntgPd", td::unsigned_integer(32)}, {"GI", td::boolean()},
                    {"PurgeBuf", td::boolean()},   {"EntryID", td::octet_string(8)},
                    {"TimeOfEntry", td::binary_time(true)}, {"ResvTms", td::integer(16)},
                    {"Owner", td::octet_string(-64)}});
}

td urcb() {
  return structure({{"RptID", visible129()},       {"RptEna", td::boolean()},
                    {"Resv", td::boolean()},       {"DatSet", visible129()},
                    {"ConfRev", td::unsigned_integer(32)}, {"OptFlds", td::bit_string(10)},
                    {"BufTm", td::unsigned_integer(32)}, {"SqNum", td::unsigned_integer(8)},
                    {"TrgOps", td::bit_string(6)}, {"IntgPd", td::unsigned_integer(32)},
                    {"GI", td::boolean()},         {"Owner", td::octet_string(-64)}});
}

mms::data default_value(const td& t) {
  switch (t.type) {
    case mms::data_type::structure: {
      std::vector<mms::data> v;
      for (const auto& c : t.components) v.push_back(default_value(c.type));
      return mms::data::structure(std::move(v));
    }
    case mms::data_type::array: {
      std::vector<mms::data> v;
      for (std::uint32_t i = 0; i < t.number_of_elements; ++i) {
        v.push_back(default_value(t.components.front().type));
      }
      return mms::data::array(std::move(v));
    }
    case mms::data_type::bit_string: {
      const auto n = static_cast<std::size_t>(std::abs(t.size));
      const byte_buffer zeros((n + 7) / 8, 0);
      return mms::data::bit_string(zeros, n);
    }
    case mms::data_type::integer: return mms::data::integer(0);
    case mms::data_type::unsigned_: return mms::data::unsigned_integer(0);
    case mms::data_type::floating_point:
      return t.format_width == 64 ? mms::data::floating_point(0.0) : mms::data::floating_point(0.0F);
    case mms::data_type::octet_string: {
      const byte_buffer zeros(t.size > 0 ? static_cast<std::size_t>(t.size) : 0, 0);
      return mms::data::octet_string(zeros);
    }
    case mms::data_type::visible_string: return mms::data::visible_string("");
    case mms::data_type::mms_string: return mms::data::mms_string("");
    case mms::data_type::utc_time: return mms::data::utc_time({});
    case mms::data_type::binary_time:
      return mms::data::binary_time({0, t.with_date ? std::optional<std::uint16_t>(0) : std::nullopt});
    default: return mms::data::boolean(false);
  }
}

mms::data bits(std::uint16_t raw, std::size_t count) {
  byte_buffer b((count + 7) / 8, 0);
  for (std::size_t i = 0; i < count; ++i) {
    if (((static_cast<unsigned>(raw) >> i) & 1U) != 0) b[i / 8] = static_cast<std::uint8_t>(b[i / 8] | (0x80U >> (i % 8)));
  }
  return mms::data::bit_string(b, count);
}

struct logical_node {
  std::string name;
  td type;
  mms::data value;
};

struct domain {
  std::string name;
  std::vector<logical_node> lns;
};

struct member {
  std::string domain;
  std::string item;
};

struct variable_list {
  std::vector<member> members;
  bool deletable = true;
};

struct entry {
  model::entry_id id;
  mms::binary_time time;
  std::vector<std::size_t> included;
  std::vector<mms::data> values;
  std::vector<model::trigger_conditions> reasons;
};

struct session;

struct rcb_runtime {
  std::string item;  // "LLN0$BR$brcb01"
  bool buffered = false;
  session* owner = nullptr;
  bool enabled = false;
  bool armed = false;  // BRCB: buffering since the first enable
  std::deque<entry> buffer;
  std::uint64_t next_id = 1;
  std::optional<model::entry_id> resume;
};

struct session {
  explicit session(server_association a, const asio::any_io_executor& ex)
      : assoc(std::move(a)), wake(ex, std::chrono::steady_clock::time_point::max()) {}
  server_association assoc;
  std::map<std::string, variable_list> aa_lists;
  std::deque<std::vector<mms::data>> outbox;
  asio::steady_timer wake;
  bool alive = true;
};

struct node {
  const td* type = nullptr;
  mms::data* value = nullptr;
};

std::vector<std::string_view> split(std::string_view item) {
  std::vector<std::string_view> parts;
  std::size_t pos = 0;
  for (;;) {
    const auto next = item.find('$', pos);
    parts.push_back(item.substr(pos, next == std::string_view::npos ? next : next - pos));
    if (next == std::string_view::npos) break;
    pos = next + 1;
  }
  return parts;
}

void item_names(const std::string& prefix, const td& t, std::vector<std::string>& out) {
  if (t.type != mms::data_type::structure) return;
  for (const auto& c : t.components) {
    auto name = prefix + "$" + c.name;
    out.push_back(name);
    item_names(name, c.type, out);
  }
}

model::entry_id entry_id_of(std::uint64_t n) {
  model::entry_id::bytes_type b{};
  for (std::size_t i = 0; i < 8; ++i) b[7 - i] = static_cast<std::uint8_t>((n >> (8 * i)) & 0xFFU);
  return model::entry_id(b);
}

mms::service_error definition_error(std::int64_t code) {
  return {mms::error_class::definition, code};
}

}  // namespace

struct fake_server::state : std::enable_shared_from_this<fake_server::state> {
  state(asio::any_io_executor e, fake_server_options o) : ex(std::move(e)), opts(std::move(o)) {
    build_model();
  }

  asio::any_io_executor ex;
  fake_server_options opts;
  std::optional<association::association_listener> listener;
  bool stopped = false;
  std::vector<domain> domains;
  std::map<std::string, variable_list> lists;  // "LD/LN$DS"
  std::vector<rcb_runtime> rcbs;
  std::vector<std::shared_ptr<session>> sessions;
  std::size_t accepted = 0;
  std::vector<std::string> write_log;
  std::map<std::uint32_t, std::size_t> counts;
  std::uint64_t clock_ms = 0;
  bool hold = false;
  std::vector<incoming_request> held;

  void build_model() {
    domain d0{std::string(ld0), {}};
    d0.lns.push_back({"LLN0", structure({{"ST", structure({{"Mod", mod()}})},
                                         {"BR", structure({{"brcb01", brcb()}})},
                                         {"RP", structure({{"urcb01", urcb()}})}}),
                      {}});
    d0.lns.push_back({"MMXU1",
                      structure({{"MX", structure({{"TotW", structure({{"mag", structure({{"f", td::float32()}})},
                                                                      {"q", quality()},
                                                                      {"t", td::utc_time()}})},
                                                   {"PhV", structure({{"phsA", cmv()}, {"phsB", cmv()}})}})},
                                 {"CF", structure({{"TotW", structure({{"db", td::unsigned_integer(32)}})}})}}),
                      {}});
    d0.lns.push_back({"XCBR1",
                      structure({{"ST", structure({{"Pos", structure({{"stVal", td::bit_string(2)},
                                                                     {"q", quality()},
                                                                     {"t", td::utc_time()}})}})},
                                 {"CF", structure({{"Pos", structure({{"ctlModel", td::integer(8)}})}})}}),
                      {}});
    domain d1{"IED1LD1", {}};
    d1.lns.push_back({"LLN0", structure({{"ST", structure({{"Mod", mod()}})}}), {}});
    d1.lns.push_back({"GGIO1", structure({{"ST", structure({{"Ind1", status_bool()}})}}), {}});
    for (auto* d : {&d0, &d1}) {
      for (auto& ln : d->lns) ln.value = default_value(ln.type);
    }
    domains.push_back(std::move(d0));
    domains.push_back(std::move(d1));

    lists["IED1LD0/LLN0$DS1"] = {{{std::string(ld0), "MMXU1$MX$TotW"},
                                  {std::string(ld0), "XCBR1$ST$Pos$stVal"},
                                  {std::string(ld0), "XCBR1$ST$Pos$q"},
                                  {std::string(ld0), "MMXU1$MX$PhV$phsA$cVal$mag$f"}},
                                 false};

    const auto trg = model::trigger_conditions::of({model::trigger::data_change,
                                                    model::trigger::quality_change,
                                                    model::trigger::general_interrogation});
    for (const auto* rcb : {"LLN0$BR$brcb01", "LLN0$RP$urcb01"}) {
      rcb_runtime rt;
      rt.item = rcb;
      rt.buffered = std::string_view(rcb).find("$BR$") != std::string_view::npos;
      set(rt.item + "$DatSet", mms::data::visible_string("IED1LD0/LLN0$DS1"));
      set(rt.item + "$ConfRev", mms::data::unsigned_integer(1));
      set(rt.item + "$TrgOps", trg.to_mms());
      if (rt.buffered) set(rt.item + "$RptID", mms::data::visible_string("brcb01-id"));
      rcbs.push_back(std::move(rt));
    }
    set("XCBR1$ST$Pos$stVal", model::to_mms(model::dbpos::off));
    set("MMXU1$MX$TotW$mag$f", mms::data::floating_point(1.5F));
  }

  // --- model

  domain* find_domain(std::string_view name) {
    for (auto& d : domains) {
      if (d.name == name) return &d;
    }
    return nullptr;
  }

  node find(std::string_view dom, std::string_view item) {
    auto* d = find_domain(dom);
    if (d == nullptr) return {};
    const auto parts = split(item);
    logical_node* ln = nullptr;
    for (auto& l : d->lns) {
      if (l.name == parts[0]) ln = &l;
    }
    if (ln == nullptr) return {};
    node n{&ln->type, &ln->value};
    for (std::size_t i = 1; i < parts.size(); ++i) {
      if (n.type->type != mms::data_type::structure) return {};
      const auto& comps = n.type->components;
      const auto it = std::find_if(comps.begin(), comps.end(),
                                   [&](const mms::type_component& c) { return c.name == parts[i]; });
      if (it == comps.end()) return {};
      const auto idx = static_cast<std::size_t>(it - comps.begin());
      auto children = n.value->mutable_elements();
      if (!children) return {};
      n = {&it->type, &(**children)[idx]};
    }
    return n;
  }

  void set(const std::string& item, mms::data v) {
    auto n = find(ld0, item);
    if (n.value != nullptr) *n.value = std::move(v);
  }

  mms::data get(const std::string& item) {
    auto n = find(ld0, item);
    return n.value != nullptr ? *n.value : mms::data{};
  }

  std::vector<std::string> domain_items(const domain& d) const {
    std::vector<std::string> out;
    for (const auto& ln : d.lns) {
      out.push_back(ln.name);
      item_names(ln.name, ln.type, out);
    }
    return out;
  }

  variable_list* find_list(session& s, const mms::object_name& name) {
    if (name.scope == mms::object_scope::aa_specific) {
      auto it = s.aa_lists.find(std::string(name.item_id));
      return it == s.aa_lists.end() ? nullptr : &it->second;
    }
    if (name.scope != mms::object_scope::domain_specific) return nullptr;
    auto it = lists.find(std::string(name.domain_id) + "/" + std::string(name.item_id));
    return it == lists.end() ? nullptr : &it->second;
  }

  // --- reports

  void enqueue(session& s, std::vector<mms::data> values) {
    if (!s.alive) return;
    s.outbox.push_back(std::move(values));
    s.wake.cancel();
  }

  std::vector<mms::data> build_report(rcb_runtime& rc, const entry& e) {
    const auto attr = [&](const char* name) { return get(rc.item + "$" + name); };
    std::vector<mms::data> v;
    auto rpt_id = std::string(*attr("RptID").as_visible_string());
    if (rpt_id.empty()) rpt_id = std::string(ld0) + "/" + rc.item;
    v.push_back(mms::data::visible_string(rpt_id));
    auto opt = *model::optional_fields::from_mms(attr("OptFlds"));
    opt = opt.configurable(rc.buffered);
    v.push_back(opt.to_mms());
    if (opt.sequence_number()) {
      const auto sq = *attr("SqNum").as_uint64();
      v.push_back(mms::data::unsigned_integer(sq));
      const auto wrap = rc.buffered ? 0x10000U : 0x100U;
      set(rc.item + "$SqNum", mms::data::unsigned_integer((sq + 1) % wrap));
    }
    if (opt.report_time_stamp()) v.push_back(mms::data::binary_time(e.time));
    if (opt.data_set_name()) v.push_back(attr("DatSet"));
    if (opt.buffer_overflow()) v.push_back(mms::data::boolean(false));
    if (opt.entry_id()) v.push_back(e.id.to_mms());
    if (opt.conf_revision()) v.push_back(attr("ConfRev"));
    const auto* ds = data_set_of(rc);
    const std::size_t n = ds != nullptr ? ds->members.size() : 0;
    std::uint16_t inc = 0;
    for (auto i : e.included) inc = static_cast<std::uint16_t>(inc | (1U << i));
    v.push_back(bits(inc, n));
    if (opt.data_reference()) {
      for (auto i : e.included) {
        v.push_back(mms::data::visible_string(ds->members[i].domain + "/" + ds->members[i].item));
      }
    }
    for (const auto& value : e.values) v.push_back(value);
    if (opt.reason_for_inclusion()) {
      for (const auto& r : e.reasons) v.push_back(*r.to_mms_reason_code());
    }
    return v;
  }

  const variable_list* data_set_of(rcb_runtime& rc) {
    const auto ds = get(rc.item + "$DatSet");
    const auto text = ds.as_visible_string();
    if (!text) return nullptr;
    auto it = lists.find(std::string(*text));
    return it == lists.end() ? nullptr : &it->second;
  }

  void emit(rcb_runtime& rc, entry e) {
    e.time = mms::binary_time{static_cast<std::uint32_t>(++clock_ms), std::uint16_t{14000}};
    if (rc.buffered) {
      if (!rc.armed) return;
      e.id = entry_id_of(rc.next_id++);
      rc.buffer.push_back(e);
      if (rc.buffer.size() > 64) rc.buffer.pop_front();
    }
    if (rc.enabled && rc.owner != nullptr) enqueue(*rc.owner, build_report(rc, e));
  }

  void general_interrogation(rcb_runtime& rc) {
    const auto* ds = data_set_of(rc);
    if (ds == nullptr) return;
    entry e;
    for (std::size_t i = 0; i < ds->members.size(); ++i) {
      e.included.push_back(i);
      e.values.push_back(*find(ds->members[i].domain, ds->members[i].item).value);
      e.reasons.push_back(model::trigger_conditions::of({model::trigger::general_interrogation}));
    }
    emit(rc, std::move(e));
  }

  void release_rcbs(const session* s) {
    for (auto& rc : rcbs) {
      if (rc.owner != s) continue;
      rc.owner = nullptr;
      rc.enabled = false;
      set(rc.item + "$RptEna", mms::data::boolean(false));
      if (!rc.buffered) set(rc.item + "$Resv", mms::data::boolean(false));
    }
  }

  // --- writes

  rcb_runtime* rcb_of(std::string_view dom, std::string_view item, std::string_view& attr) {
    if (dom != ld0) return nullptr;
    for (auto& rc : rcbs) {
      if (item.starts_with(rc.item) && item.size() > rc.item.size() && item[rc.item.size()] == '$') {
        attr = item.substr(rc.item.size() + 1);
        return &rc;
      }
      if (item == rc.item) {
        attr = {};
        return &rc;
      }
    }
    return nullptr;
  }

  std::optional<dae> write_rcb(session& s, rcb_runtime& rc, std::string_view attr, node n,
                               const mms::data& v) {
    if (attr.empty() || attr.find('$') != std::string_view::npos) return dae::object_access_denied;
    if (rc.owner != nullptr && rc.owner != &s) return dae::object_access_denied;
    if (attr == "ConfRev" || attr == "SqNum" || attr == "Owner" || attr == "TimeOfEntry") {
      return dae::object_access_denied;
    }
    if (rc.enabled && attr != "RptEna" && attr != "GI") return dae::temporarily_unavailable;
    if (!rc.buffered) {
      if (attr == "Resv") {
        const bool on = *v.as_boolean();
        rc.owner = on ? &s : nullptr;
        *n.value = v;
        return std::nullopt;
      }
      rc.owner = &s;
      set(rc.item + "$Resv", mms::data::boolean(true));
    }
    if (attr == "RptEna") {
      const bool on = *v.as_boolean();
      *n.value = v;
      rc.enabled = on;
      if (on) {
        rc.owner = &s;
        if (rc.buffered) {
          rc.armed = true;
          auto it = rc.buffer.begin();
          if (rc.resume && !rc.resume->is_zero()) {
            auto found = std::find_if(rc.buffer.begin(), rc.buffer.end(),
                                      [&](const entry& e) { return e.id == *rc.resume; });
            if (found != rc.buffer.end()) it = std::next(found);
          }
          for (; it != rc.buffer.end(); ++it) enqueue(s, build_report(rc, *it));
        }
      } else if (rc.buffered) {
        rc.owner = nullptr;
      }
      return std::nullopt;
    }
    if (attr == "GI") {
      if (*v.as_boolean() && rc.enabled) general_interrogation(rc);
      return std::nullopt;
    }
    if (attr == "PurgeBuf") {
      if (*v.as_boolean()) rc.buffer.clear();
      return std::nullopt;
    }
    if (attr == "EntryID") {
      auto id = model::entry_id::from_mms(v);
      if (!id) return dae::object_value_invalid;
      rc.resume = *id;
    }
    *n.value = v;
    return std::nullopt;
  }

  std::optional<dae> write_variable(session& s, std::string_view dom, std::string_view item,
                                    const mms::data& v) {
    auto n = find(dom, item);
    if (n.value == nullptr) return dae::object_non_existent;
    if (n.value->type() != v.type()) return dae::type_inconsistent;
    std::string_view attr;
    if (auto* rc = rcb_of(dom, item, attr)) {
      if (auto e = write_rcb(s, *rc, attr, n, v)) return e;
    } else {
      *n.value = v;
    }
    write_log.push_back(std::string(dom) + "/" + std::string(item));
    return std::nullopt;
  }

  // --- requests

  awaitable<void> handle(session& s, incoming_request& r) {
    const auto& svc = r.service();
    if (const auto* q = std::get_if<mms::get_name_list_request>(&svc)) {
      co_await get_name_list(s, r, *q);
    } else if (const auto* q2 = std::get_if<mms::get_variable_access_attributes_request>(&svc)) {
      auto n = q2->name.scope == mms::object_scope::domain_specific
                   ? find(q2->name.domain_id, q2->name.item_id)
                   : node{};
      if (n.type == nullptr) {
        (void)co_await r.respond_error(definition_error(mms::error_code::definition::object_undefined));
      } else {
        (void)co_await r.respond(mms::get_variable_access_attributes_response{false, *n.type});
      }
    } else if (const auto* q3 = std::get_if<mms::read_request>(&svc)) {
      co_await read(s, r, *q3);
    } else if (const auto* q4 = std::get_if<mms::write_request>(&svc)) {
      co_await write(s, r, *q4);
    } else if (const auto* q5 = std::get_if<mms::get_named_variable_list_attributes_request>(&svc)) {
      const auto* l = find_list(s, q5->name);
      if (l == nullptr) {
        (void)co_await r.respond_error(definition_error(mms::error_code::definition::object_undefined));
        co_return;
      }
      std::vector<mms::variable_spec> specs;
      for (const auto& m : l->members) specs.emplace_back(mms::object_name::domain(m.domain, m.item));
      (void)co_await r.respond(mms::get_named_variable_list_attributes_response{l->deletable, specs});
    } else if (const auto* q6 = std::get_if<mms::define_named_variable_list_request>(&svc)) {
      co_await define_list(s, r, *q6);
    } else if (const auto* q7 = std::get_if<mms::delete_named_variable_list_request>(&svc)) {
      std::uint32_t matched = 0;
      std::uint32_t deleted = 0;
      for (const auto name : q7->names) {
        if (find_list(s, name) == nullptr) continue;
        ++matched;
        if (name.scope == mms::object_scope::aa_specific) {
          s.aa_lists.erase(std::string(name.item_id));
          ++deleted;
        } else if (auto it = lists.find(std::string(name.domain_id) + "/" + std::string(name.item_id));
                   it->second.deletable) {
          lists.erase(it);
          ++deleted;
        }
      }
      (void)co_await r.respond(mms::delete_named_variable_list_response{matched, deleted});
    } else if (std::holds_alternative<mms::identify_request>(svc)) {
      (void)co_await r.respond(mms::identify_response{"openiec61850", "fake-ied", "1", {}});
    } else {
      (void)co_await r.reject(mms::reject_code::confirmed_request::unrecognized_service);
    }
  }

  awaitable<void> get_name_list(session& s, incoming_request& r, const mms::get_name_list_request& q) {
    std::vector<std::string> names;
    using oc = mms::object_class;
    if (q.cls == oc::domain && q.scope == mms::object_scope::vmd_specific) {
      for (const auto& d : domains) names.push_back(d.name);
    } else if (q.cls == oc::named_variable && q.scope == mms::object_scope::domain_specific) {
      const auto* d = find_domain(q.domain_id);
      if (d == nullptr) {
        (void)co_await r.respond_error(definition_error(mms::error_code::definition::object_undefined));
        co_return;
      }
      names = domain_items(*d);
    } else if (q.cls == oc::named_variable_list && q.scope == mms::object_scope::domain_specific) {
      const std::string prefix = std::string(q.domain_id) + "/";
      for (const auto& [key, l] : lists) {
        if (key.starts_with(prefix)) names.push_back(key.substr(prefix.size()));
      }
    } else if (q.cls == oc::named_variable_list && q.scope == mms::object_scope::aa_specific) {
      for (const auto& [key, l] : s.aa_lists) names.push_back(key);
    }
    std::size_t start = 0;
    if (q.continue_after) {
      const auto it = std::find(names.begin(), names.end(), *q.continue_after);
      if (it == names.end()) {
        (void)co_await r.respond_error(
            {mms::error_class::service, mms::error_code::service::continuation_invalid});
        co_return;
      }
      start = static_cast<std::size_t>(it - names.begin()) + 1;
    }
    std::size_t count = names.size() - start;
    if (opts.name_list_page != 0) count = std::min(count, opts.name_list_page);
    const std::vector<std::string_view> ids(names.begin() + static_cast<std::ptrdiff_t>(start),
                                            names.begin() + static_cast<std::ptrdiff_t>(start + count));
    (void)co_await r.respond(mms::get_name_list_response{ids, start + count < names.size()});
  }

  awaitable<void> read(session& s, incoming_request& r, const mms::read_request& q) {
    std::vector<member> targets;
    if (q.spec.type == mms::variable_access_specification::kind::variable_list_name) {
      const auto* l = find_list(s, q.spec.list_name);
      if (l == nullptr) {
        (void)co_await r.respond_error(definition_error(mms::error_code::definition::object_undefined));
        co_return;
      }
      targets = l->members;
    } else {
      for (const auto v : q.spec.variables) {
        targets.push_back({std::string(v.name.domain_id), std::string(v.name.item_id)});
      }
    }
    std::vector<std::optional<mms::data>> values;
    for (const auto& t : targets) {
      auto n = find(t.domain, t.item);
      values.push_back(n.value != nullptr ? std::optional<mms::data>(*n.value) : std::nullopt);
    }
    std::vector<mms::access_result> results;
    for (const auto& v : values) {
      results.push_back(v ? mms::access_result(mms::data_ref(*v))
                          : mms::access_result(dae::object_non_existent));
    }
    (void)co_await r.respond(mms::read_response{std::nullopt, results});
  }

  awaitable<void> write(session& s, incoming_request& r, const mms::write_request& q) {
    std::vector<member> targets;
    if (q.spec.type == mms::variable_access_specification::kind::variable_list_name) {
      const auto* l = find_list(s, q.spec.list_name);
      if (l == nullptr) {
        (void)co_await r.respond_error(definition_error(mms::error_code::definition::object_undefined));
        co_return;
      }
      targets = l->members;
    } else {
      for (const auto v : q.spec.variables) {
        targets.push_back({std::string(v.name.domain_id), std::string(v.name.item_id)});
      }
    }
    std::vector<mms::data> values;
    for (const auto v : q.values) values.push_back(*mms::data::from_view(v.view()));
    if (values.size() != targets.size()) {
      (void)co_await r.reject(mms::reject_code::confirmed_request::invalid_argument);
      co_return;
    }
    std::vector<mms::write_result> results;
    for (std::size_t i = 0; i < targets.size(); ++i) {
      const auto e = write_variable(s, targets[i].domain, targets[i].item, values[i]);
      results.push_back(e ? mms::write_result(*e) : mms::write_result());
    }
    (void)co_await r.respond(mms::write_response{results});
  }

  awaitable<void> define_list(session& s, incoming_request& r,
                              const mms::define_named_variable_list_request& q) {
    if (find_list(s, q.name) != nullptr) {
      (void)co_await r.respond_error(definition_error(mms::error_code::definition::object_exists));
      co_return;
    }
    variable_list l;
    for (const auto v : q.variables) {
      if (v.name.scope != mms::object_scope::domain_specific ||
          find(v.name.domain_id, v.name.item_id).value == nullptr) {
        (void)co_await r.respond_error(definition_error(mms::error_code::definition::object_undefined));
        co_return;
      }
      l.members.push_back({std::string(v.name.domain_id), std::string(v.name.item_id)});
    }
    if (q.name.scope == mms::object_scope::aa_specific) {
      s.aa_lists[std::string(q.name.item_id)] = std::move(l);
    } else {
      lists[std::string(q.name.domain_id) + "/" + std::string(q.name.item_id)] = std::move(l);
    }
    (void)co_await r.respond(mms::define_named_variable_list_response{});
  }

  // --- associations

  void end_session(const std::shared_ptr<session>& s) {
    if (!s->alive) return;
    s->alive = false;
    release_rcbs(s.get());
    std::erase(sessions, s);
    s->wake.cancel();
  }

  static awaitable<void> serve(std::shared_ptr<state> self, std::shared_ptr<session> s) {
    for (;;) {
      auto r = co_await s->assoc.next_request();
      if (!r) break;
      ++self->counts[mms::service_tag(r->service())];
      if (self->hold) {
        self->held.push_back(std::move(*r));
        continue;
      }
      co_await self->handle(*s, *r);
    }
    self->end_session(s);
  }

  static awaitable<void> sender(std::shared_ptr<state> self, std::shared_ptr<session> s) {
    (void)self;
    while (s->alive) {
      if (s->outbox.empty()) {
        s->wake.expires_at(std::chrono::steady_clock::time_point::max());
        (void)co_await s->wake.async_wait(asio::as_tuple(asio::use_awaitable));
        continue;
      }
      const auto values = std::move(s->outbox.front());
      s->outbox.pop_front();
      std::vector<mms::access_result> results;
      for (const auto& v : values) results.emplace_back(mms::data_ref(v));
      const mms::information_report ir{
          mms::variable_access_specification::named(mms::object_name::vmd("RPT")), results};
      auto sent = co_await s->assoc.send_unconfirmed(ir);
      if (!sent) break;
    }
  }

  static awaitable<void> accept_loop(std::shared_ptr<state> self) {
    while (!self->stopped) {
      auto a = co_await self->listener->accept();
      if (self->stopped) co_return;
      if (!a) {
        if (a.error() == asio::error::operation_aborted) co_return;
        continue;
      }
      ++self->accepted;
      auto s = std::make_shared<session>(std::move(*a), self->ex);
      self->sessions.push_back(s);
      asio::co_spawn(self->ex, serve(self, s), asio::detached);
      asio::co_spawn(self->ex, sender(self, s), asio::detached);
    }
  }
};

fake_server::fake_server(asio::any_io_executor ex, fake_server_options options) {
  if (options.association.association_timeout == std::chrono::milliseconds{10000}) {
    options.association.association_timeout = std::chrono::seconds{2};
    options.association.transport.handshake_timeout = std::chrono::seconds{2};
  }
  state_ = std::make_shared<state>(std::move(ex), std::move(options));
}

fake_server::~fake_server() { stop(); }

result<void> fake_server::start() {
  const asio::ip::tcp::endpoint ep{asio::ip::address_v4::loopback(), 0};
  auto l = association::association_listener::listen(state_->ex, ep, state_->opts.association);
  if (!l) return l.error();
  state_->listener.emplace(std::move(*l));
  asio::co_spawn(state_->ex, state::accept_loop(state_), asio::detached);
  return {};
}

std::uint16_t fake_server::port() const noexcept {
  return state_->listener ? state_->listener->local_endpoint().port() : 0;
}

void fake_server::stop() {
  if (state_->stopped) return;
  state_->stopped = true;
  if (state_->listener) state_->listener->close();
  for (auto& s : state_->sessions) s->assoc.abort();
}

void fake_server::drop_connections() {
  for (auto& s : state_->sessions) {
    state_->release_rcbs(s.get());
    s->assoc.close();
  }
  state_->held.clear();
}

void fake_server::hold_requests(bool on) { state_->hold = on; }

std::size_t fake_server::associations_accepted() const noexcept { return state_->accepted; }

std::size_t fake_server::active_associations() const noexcept { return state_->sessions.size(); }

std::size_t fake_server::requests(mms::confirmed_service s) const {
  const auto it = state_->counts.find(static_cast<std::uint32_t>(s));
  return it == state_->counts.end() ? 0 : it->second;
}

const std::vector<std::string>& fake_server::write_log() const noexcept { return state_->write_log; }

void fake_server::clear_write_log() { state_->write_log.clear(); }

std::optional<mms::data> fake_server::value(std::string_view domain, std::string_view item) const {
  auto n = state_->find(domain, item);
  if (n.value == nullptr) return std::nullopt;
  return *n.value;
}

bool fake_server::set_value(std::string_view domain, std::string_view item, mms::data v) {
  auto n = state_->find(domain, item);
  if (n.value == nullptr) return false;
  *n.value = std::move(v);
  return true;
}

bool fake_server::update(std::string_view item, mms::data v, model::trigger_conditions reason) {
  if (!set_value(ld0, item, std::move(v))) return false;
  for (auto& rc : state_->rcbs) {
    const auto* ds = state_->data_set_of(rc);
    if (ds == nullptr) continue;
    const auto trg = model::trigger_conditions::from_mms(state_->get(rc.item + "$TrgOps"));
    if (!trg || (trg->raw() & reason.raw()) == 0) continue;
    entry e;
    for (std::size_t i = 0; i < ds->members.size(); ++i) {
      const auto& m = ds->members[i];
      if (m.domain != ld0) continue;
      if (item == m.item || (item.starts_with(m.item) && item.size() > m.item.size() &&
                             item[m.item.size()] == '$')) {
        e.included.push_back(i);
        e.values.push_back(*state_->find(m.domain, m.item).value);
        e.reasons.push_back(reason);
      }
    }
    if (!e.included.empty()) state_->emit(rc, std::move(e));
  }
  return true;
}

void fake_server::send_report(std::vector<mms::data> access_results) {
  for (auto& s : state_->sessions) state_->enqueue(*s, access_results);
}

std::size_t fake_server::buffered_entries(std::string_view brcb) const {
  for (const auto& rc : state_->rcbs) {
    if (rc.item.ends_with(brcb)) return rc.buffer.size();
  }
  return 0;
}

bool fake_server::rcb_enabled(std::string_view rcb) const {
  for (const auto& rc : state_->rcbs) {
    if (rc.item.ends_with(rcb)) return rc.enabled;
  }
  return false;
}

}  // namespace openiec61850::testing
