// Resolution of MMS names and ACSI references onto the model, and value access
// (IEC 61850-8-1 §8.1.3, §9).

#include <string>
#include <utility>

#include "detail.hpp"

namespace openiec61850::server::detail {

namespace {

using model::fc;

std::error_code not_found() { return make_error_code(errc::object_not_found); }

bool visible(const node& parent, const node& child, std::optional<model::functional_constraint> f) {
  if (parent.is_attribute() || !f) return true;
  return child.has_fc(*f);
}

}  // namespace

std::optional<target> server_state::resolve_mms(const mms::object_name& name,
                                                byte_view alternate_access) const {
  if (name.scope != mms::object_scope::domain_specific) return std::nullopt;
  if (!alternate_access.empty()) {
    model::parse_options po{model::name_limits::unlimited(), false};
    auto ref = model::from_mms_variable(name, alternate_access, po);
    if (!ref || !ref->fc()) return std::nullopt;
    auto t = resolve_ref(*ref);
    if (!t) return std::nullopt;
    return std::move(*t);
  }
  const node_id ld = model.find_logical_device(name.domain_id);
  if (ld == no_node) return std::nullopt;
  const std::string_view item = name.item_id;
  std::vector<std::string_view> parts;
  for (std::size_t from = 0;;) {
    const auto p = item.find('$', from);
    parts.push_back(item.substr(from, p == std::string_view::npos ? p : p - from));
    if (p == std::string_view::npos) break;
    from = p + 1;
  }
  for (const auto part : parts) {
    if (part.empty()) return std::nullopt;
  }
  const node_id ln = model.find_child(ld, parts[0]);
  if (ln == no_node || at(ln).kind != node_kind::logical_node) return std::nullopt;
  if (parts.size() == 1) return target{ln, std::nullopt, {}};
  const auto f = model::parse_functional_constraint(parts[1]);
  if (!f || *f == fc::XX || !at(ln).has_fc(*f)) return std::nullopt;
  node_id cur = ln;
  for (std::size_t k = 2; k < parts.size(); ++k) {
    const auto& n = at(cur);
    if (n.holds_value() || n.is_object_array()) return std::nullopt;
    const node_id child = model.find_child(cur, parts[k]);
    if (child == no_node || !visible(n, at(child), f)) return std::nullopt;
    cur = child;
  }
  return target{cur, f, {}};
}

result<target> server_state::resolve_ref(const model::object_reference& ref) const {
  if (ref.empty() || ref.is_association_specific() || !ref.has_ln()) return not_found();
  const node_id ld = model.find_logical_device(ref.ld());
  if (ld == no_node) return not_found();
  const node_id ln = model.find_child(ld, ref.ln());
  if (ln == no_node || at(ln).kind != node_kind::logical_node) return not_found();
  auto f = ref.fc();
  if (f && *f == fc::XX) return not_found();
  target t{ln, f, {}};
  node_id cur = ln;
  bool in_value = false;   // below an array element
  node_id tmpl = no_node;  // the node describing the current position inside a value
  bool whole_array = false;
  for (const auto pe : ref.path()) {
    if (!in_value) {
      const auto& n = at(cur);
      if (n.holds_value()) return not_found();
      const node_id child = model.find_child(cur, pe.name);
      if (child == no_node || !visible(n, at(child), f)) return not_found();
      cur = child;
      if (pe.index) {
        if (at(cur).count == 0 || *pe.index >= at(cur).count) return not_found();
        if (at(cur).is_object_array()) {  // its elements are nodes
          cur = at(cur).children[*pe.index];
          continue;
        }
        t.path.push_back({true, *pe.index});
        in_value = true;
        tmpl = cur;
      }
      continue;
    }
    const auto& tn = at(tmpl);
    if (whole_array || tn.type) return not_found();
    std::uint32_t k = 0;
    for (; k < tn.children.size(); ++k) {
      if (at(tn.children[k]).name == pe.name) break;
    }
    if (k == tn.children.size()) return not_found();
    t.path.push_back({false, k});
    tmpl = tn.children[k];
    whole_array = false;
    if (pe.index) {
      if (at(tmpl).count == 0 || *pe.index >= at(tmpl).count) return not_found();
      t.path.push_back({true, *pe.index});
    } else if (at(tmpl).count > 0) {
      whole_array = true;
    }
  }
  if (!f) {
    if (!at(cur).fc || at(cur).kind == node_kind::logical_node) return not_found();
    f = at(cur).fc;
  }
  if (!at(cur).has_fc(*f)) return not_found();
  t.node = cur;
  t.fc = f;
  return t;
}

namespace {

mms::data build(const server_state& s, node_id id, std::optional<model::functional_constraint> f) {
  const auto& n = s.at(id);
  if (n.holds_value()) {
    if (f == fc::SE && n.fc == fc::SG) return s.edit_value(id);
    return s.values[id];
  }
  std::vector<mms::data> comps;
  if (n.kind == node_kind::logical_node && !f) {
    for (std::size_t i = 0; i < model::functional_constraint_count; ++i) {
      const auto fi = static_cast<model::functional_constraint>(i);
      if (fi == fc::XX || !n.has_fc(fi)) continue;
      comps.push_back(build(s, id, fi));
    }
    return mms::data::structure(std::move(comps));
  }
  for (const auto c : n.children) {
    if (!visible(n, s.at(c), f)) continue;
    comps.push_back(build(s, c, f));
  }
  if (n.is_object_array()) return mms::data::array(std::move(comps));
  return mms::data::structure(std::move(comps));
}

}  // namespace

result<mms::data> server_state::value_of(const target& t) const {
  if (t.path.empty()) return build(*this, t.node, t.fc);
  const mms::data* cur = t.fc == fc::SE && at(t.node).fc == fc::SG ? &edit_value(t.node)
                                                                     : &values[t.node];
  for (const auto& sel : t.path) {
    const auto elems = cur->elements();
    if (sel.value >= elems.size()) return not_found();
    cur = &elems[sel.value];
  }
  return *cur;
}

result<mms::type_description> server_state::type_of(const target& t) const {
  auto type = model.type_of(t.node, t.fc);
  if (!type) return type;
  for (const auto& sel : t.path) {
    const std::size_t i = sel.index ? 0 : sel.value;
    if (i >= type->components.size()) return not_found();
    mms::type_description inner = std::move(type->components[i].type);
    *type = std::move(inner);
  }
  return type;
}

void server_state::plan(const target& t, const mms::data& v, std::vector<assignment>& out) const {
  const auto& n = at(t.node);
  if (n.holds_value() || !t.path.empty()) {
    out.push_back({t.node, t.path, v});
    return;
  }
  const auto elems = v.elements();
  std::size_t i = 0;
  if (n.kind == node_kind::logical_node && !t.fc) {
    for (std::size_t k = 0; k < model::functional_constraint_count; ++k) {
      const auto fi = static_cast<model::functional_constraint>(k);
      if (fi == fc::XX || !n.has_fc(fi)) continue;
      if (i >= elems.size()) return;
      plan(target{t.node, fi, {}}, elems[i++], out);
    }
    return;
  }
  for (const auto c : n.children) {
    if (!visible(n, at(c), t.fc)) continue;
    if (i >= elems.size()) return;
    plan(target{c, t.fc, {}}, elems[i++], out);
  }
}

std::vector<node_id> server_state::holders_under(const target& t) const {
  std::vector<node_id> out;
  if (!t.path.empty()) {
    out.push_back(t.node);
    return out;
  }
  auto walk = [&](auto&& self, node_id id, std::optional<model::functional_constraint> f) -> void {
    const auto& n = at(id);
    if (n.holds_value()) {
      out.push_back(id);
      return;
    }
    for (const auto c : n.children) {
      if (visible(n, at(c), f)) self(self, c, f);
    }
  };
  walk(walk, t.node, t.fc);
  return out;
}

void server_state::apply(std::vector<assignment> plan_items) {
  struct change {
    node_id holder;
    model::trigger_conditions reasons;
  };
  std::vector<change> changes;
  changes.reserve(plan_items.size());
  for (const auto& a : plan_items) {
    const mms::data* cur = &values[a.holder];
    for (const auto& sel : a.path) cur = &cur->elements()[sel.value];
    const bool changed = !(*cur == a.value);
    const auto& tr = at(a.holder).triggers;
    model::trigger_conditions r;
    if (changed && tr.dchg) r.set(model::trigger::data_change);
    if (changed && tr.qchg) r.set(model::trigger::quality_change);
    if (tr.dupd) r.set(model::trigger::data_update);
    changes.push_back({a.holder, r});
  }
  for (const auto& c : changes) {
    if (!c.reasons.empty()) before_change(c.holder);
  }
  for (auto& a : plan_items) {
    mms::data* cur = &values[a.holder];
    for (const auto& sel : a.path) {
      auto elems = cur->mutable_elements();
      if (!elems || sel.value >= (*elems)->size()) {
        cur = nullptr;
        break;
      }
      cur = &(**elems)[sel.value];
    }
    if (cur != nullptr) *cur = std::move(a.value);
  }
  for (const auto& c : changes) {
    if (!c.reasons.empty()) on_change(c.holder, c.reasons);
  }
  std::vector<std::pair<node_id, model::trigger_conditions>> logged;
  for (const auto& c : changes) {
    store_active(c.holder);
    if (!c.reasons.empty()) logged.emplace_back(c.holder, c.reasons);
  }
  if (!logged.empty() && !lcbs.empty()) log_changes(logged);
}

result<model::object_reference> server_state::acsi_reference(const target& t) const {
  std::string text = model.reference_of(t.node);
  if (!t.path.empty()) {
    node_id tmpl = t.node;
    for (const auto& sel : t.path) {
      if (sel.index) {
        text.push_back('(');
        text.append(std::to_string(sel.value));
        text.push_back(')');
      } else {
        tmpl = at(tmpl).children[sel.value];
        text.push_back('.');
        text.append(at(tmpl).name);
      }
    }
  }
  auto ref = model::object_reference::parse(text, {model::name_limits::unlimited(), false});
  if (!ref) return ref.error();
  ref->set_fc(t.fc);
  return ref;
}

std::string server_state::mms_reference(const target& t) const {
  target base{t.node, t.fc, {}};
  auto ref = acsi_reference(base);
  if (!ref) return {};
  auto text = model::to_mms_data_reference(*ref, model::name_limits::unlimited());
  return text ? std::move(*text) : std::string{};
}

}  // namespace openiec61850::server::detail
