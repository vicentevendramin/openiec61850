#include "openiec61850/scl/document.hpp"

#include <algorithm>

#include "text.hpp"

namespace openiec61850::scl {
namespace {

template <typename Range, typename Pred>
auto* find_in(const Range& r, Pred p) noexcept {
  const auto it = std::find_if(r.begin(), r.end(), p);
  return it == r.end() ? nullptr : &*it;
}

}  // namespace

std::string_view to_string(value_kind k) noexcept {
  switch (k) {
    case value_kind::spec: return "Spec";
    case value_kind::conf: return "Conf";
    case value_kind::ro: return "RO";
    case value_kind::set: return "Set";
  }
  return {};
}

std::optional<value_kind> parse_value_kind(std::string_view text) noexcept {
  if (text == "Spec") return value_kind::spec;
  if (text == "Conf") return value_kind::conf;
  if (text == "RO") return value_kind::ro;
  if (text == "Set") return value_kind::set;
  return std::nullopt;
}

const std::string* address::find(std::string_view type) const noexcept {
  const auto* e = find_in(p, [&](const p_address& x) { return x.type == type; });
  return e != nullptr ? &e->value : nullptr;
}

const connected_ap* communication::find(std::string_view ied,
                                        std::string_view ap) const noexcept {
  for (const auto& sn : sub_networks) {
    for (const auto& cap : sn.connected_aps) {
      if (cap.ied_name == ied && cap.ap_name == ap) return &cap;
    }
  }
  return nullptr;
}

const enum_value* enum_type::find_text(std::string_view text) const noexcept {
  return find_in(values, [&](const enum_value& v) { return v.text == text; });
}

const enum_value* enum_type::find_ord(std::int32_t ord) const noexcept {
  return find_in(values, [&](const enum_value& v) { return v.ord == ord; });
}

const lnode_type* data_type_templates::find_lnode_type(std::string_view id) const noexcept {
  return find_in(lnode_types, [&](const auto& t) { return t.id == id; });
}
const do_type* data_type_templates::find_do_type(std::string_view id) const noexcept {
  return find_in(do_types, [&](const auto& t) { return t.id == id; });
}
const da_type* data_type_templates::find_da_type(std::string_view id) const noexcept {
  return find_in(da_types, [&](const auto& t) { return t.id == id; });
}
const enum_type* data_type_templates::find_enum_type(std::string_view id) const noexcept {
  return find_in(enum_types, [&](const auto& t) { return t.id == id; });
}

std::string logical_node::name() const {
  std::string n;
  n.reserve(prefix.size() + ln_class.size() + inst.size());
  n += prefix;
  n += ln_class;
  n += inst;
  return n;
}

const data_set* logical_node::find_data_set(std::string_view n) const noexcept {
  return find_in(data_sets, [&](const data_set& d) { return d.name == n; });
}

std::string logical_device::name(std::string_view ied_name) const {
  if (!ld_name.empty()) return ld_name;
  std::string n{ied_name};
  n += inst;
  return n;
}

const logical_node* logical_device::find_ln(std::string_view ln_name) const {
  if (ln0.name() == ln_name) return &ln0;
  return find_in(lns, [&](const logical_node& ln) { return ln.name() == ln_name; });
}

const logical_device* server::find_ld(std::string_view inst) const noexcept {
  return find_in(ldevices, [&](const logical_device& ld) { return ld.inst == inst; });
}

const std::string* service_capability::attribute(std::string_view n) const noexcept {
  const auto* a = find_in(attributes, [&](const auto& x) { return x.first == n; });
  return a != nullptr ? &a->second : nullptr;
}

const service_capability* service_capability::find(std::string_view n) const noexcept {
  return find_in(children, [&](const service_capability& c) { return c.name == n; });
}

std::optional<std::uint32_t> service_capability::max() const noexcept {
  const auto* m = attribute("max");
  if (m == nullptr) return std::nullopt;
  return detail::parse_integer<std::uint32_t>(*m);
}

const service_capability* services::find(std::string_view n) const noexcept {
  return find_in(items, [&](const service_capability& c) { return c.name == n; });
}

const access_point* ied::find_access_point(std::string_view n) const noexcept {
  return find_in(access_points, [&](const access_point& ap) { return ap.name == n; });
}

const struct server* ied::find_server(std::string_view ap) const noexcept {
  const access_point* a = nullptr;
  if (ap.empty()) {
    a = find_in(access_points, [](const access_point& x) { return x.srv.has_value(); });
    if (a == nullptr) {
      a = find_in(access_points, [](const access_point& x) { return !x.server_at.empty(); });
    }
  } else {
    a = find_access_point(ap);
  }
  // ServerAt chains are followed a bounded number of times.
  for (std::size_t hops = 0; a != nullptr && hops <= access_points.size(); ++hops) {
    if (a->srv) return &*a->srv;
    if (a->server_at.empty()) return nullptr;
    a = find_access_point(a->server_at);
  }
  return nullptr;
}

const struct ied* document::find_ied(std::string_view name) const noexcept {
  return find_in(ieds, [&](const struct ied& i) { return i.name == name; });
}

}  // namespace openiec61850::scl
