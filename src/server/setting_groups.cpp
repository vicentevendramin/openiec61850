// Setting group control (IEC 61850-7-2 §16, IEC 61850-8-1 §16): the SGCB "LLN0$SP$SGCB".
//
//   SelectActiveSG       Write ActSG: the SG values of the LD switch to the stored group at once
//                        (one apply(), so the changes trigger reports and logs together).
//   SelectEditSG         Write EditSG: loads the group into the edit buffer, reserved for the
//                        association (Ed.2 ResvTms: released after that many seconds without
//                        edit activity); EditSG = 0 releases it.
//   SetEditSGValue       Write "LN$SE$...": changes the edit buffer only.
//   ConfirmEditSGValues  Write CnfEdit = true: stores the edit buffer into its group (and into the
//                        SG values when it is the active group).
//   GetEditSGValue       Read "LN$SE$..."; GetSGCBValues: Read "LLN0$SP$SGCB".

#include <chrono>
#include <limits>
#include <utility>

#include "detail.hpp"
#include "values.hpp"

namespace openiec61850::server::detail {

namespace {

std::optional<std::uint8_t> as_group(const mms::data& v) {
  std::optional<std::uint64_t> x;
  if (v.type() == mms::data_type::unsigned_) {
    if (auto u = v.as_uint64()) x = *u;
  } else if (v.type() == mms::data_type::integer) {
    if (auto i = v.as_int64(); i && *i >= 0) x = static_cast<std::uint64_t>(*i);
  }
  if (!x || *x > std::numeric_limits<std::uint8_t>::max()) return std::nullopt;
  return static_cast<std::uint8_t>(*x);
}

void arm(server_state& st, sgcb& g) {
  ++g.resv_gen;
  g.resv_timer.cancel();
  if (g.resv_tms == 0 || g.edit == 0) return;
  const auto gen = g.resv_gen;
  g.resv_timer.expires_after(std::chrono::seconds(g.resv_tms));
  g.resv_timer.async_wait([w = st.weak_from_this(), p = &g, gen](std::error_code ec) {
    auto self = w.lock();
    if (!self || ec || gen != p->resv_gen) return;
    self->release_edit(*p);
  });
}

}  // namespace

void server_state::init_sgcb(const setting_group_definition& def) {
  auto g = std::make_unique<sgcb>(strand);
  g->node = def.node;
  g->ld = model.logical_device_of(def.ln);
  for (const auto c : at(def.node).children) g->attrs.emplace(at(c).name, c);
  g->num = def.settings.num_of_sgs;
  g->act = def.settings.act_sg;
  g->resv_tms = def.settings.resv_tms;
  g->lact_tm = model::timestamp::now();
  const auto nodes = model.nodes();
  for (std::size_t i = 0; i < nodes.size(); ++i) {
    const auto& n = nodes[i];
    if (!n.holds_value() || n.fc != model::fc::SG) continue;
    const auto id = static_cast<node_id>(i);
    if (model.logical_device_of(id) != g->ld) continue;
    g->index.emplace(id, g->holders.size());
    g->holders.push_back(id);
  }
  g->groups.resize(g->num);
  for (std::size_t k = 0; k < g->num; ++k) {
    for (const auto h : g->holders) {
      const auto& n = at(h);
      g->groups[k].push_back(k < n.group_values.size() && n.group_values[k].valid() ? n.group_values[k]
                                                                                     : n.value);
    }
  }
  for (std::size_t i = 0; i < g->holders.size(); ++i) {
    values[g->holders[i]] = g->groups[g->act - 1U][i];
    sgcb_of_holder[g->holders[i]] = g.get();
  }
  sgcb_of[def.node] = g.get();
  sync(*g);
  sgcbs.push_back(std::move(g));
}

void server_state::sync(sgcb& g) {
  auto set = [&](std::string_view name, mms::data v) {
    if (const auto it = g.attrs.find(name); it != g.attrs.end()) values[it->second] = std::move(v);
  };
  set("NumOfSG", mms::data::unsigned_integer(g.num));
  set("ActSG", mms::data::unsigned_integer(g.act));
  set("EditSG", mms::data::unsigned_integer(g.edit));
  set("CnfEdit", mms::data::boolean(false));
  set("LActTm", g.lact_tm.to_mms());
  set("ResvTms", mms::data::unsigned_integer(g.resv_tms));
}

const mms::data& server_state::edit_value(node_id holder) const {
  const auto it = sgcb_of_holder.find(holder);
  if (it != sgcb_of_holder.end() && it->second->edit != 0) {
    return it->second->edit_values[it->second->index.at(holder)];
  }
  return values[holder];
}

void server_state::store_active(node_id holder) {
  const auto it = sgcb_of_holder.find(holder);
  if (it == sgcb_of_holder.end()) return;
  auto& g = *it->second;
  g.groups[g.act - 1U][g.index.at(holder)] = values[holder];
}

void server_state::activate_group(sgcb& g, std::uint8_t sg) {
  g.act = sg;
  g.lact_tm = model::timestamp::now();
  std::vector<assignment> plan_items;
  plan_items.reserve(g.holders.size());
  for (std::size_t i = 0; i < g.holders.size(); ++i) {
    plan_items.push_back({g.holders[i], {}, g.groups[sg - 1U][i]});
  }
  apply(std::move(plan_items));
  sync(g);
}

void server_state::release_edit(sgcb& g) {
  g.edit = 0;
  g.owner = 0;
  g.edit_values.clear();
  ++g.resv_gen;
  g.resv_timer.cancel();
  sync(g);
}

void server_state::setting_groups_session_closed(session& s) {
  for (auto& g : sgcbs) {
    if (g->owner == s.id) release_edit(*g);
  }
}

std::optional<dae> server_state::write_sgcb(session& s, sgcb& g, std::string_view attr,
                                            const mms::data& v) {
  auto allowed = [&](setting_group_action a, std::uint8_t group) -> std::optional<dae> {
    if (!options.on_setting_group) return std::nullopt;
    return options.on_setting_group({s.id, at(g.ld).name, a, group});
  };
  if (attr == "ActSG") {
    const auto sg = as_group(v);
    if (!sg) return v.type() == mms::data_type::unsigned_ || v.type() == mms::data_type::integer
                        ? dae::object_value_invalid
                        : dae::type_inconsistent;
    if (*sg == 0 || *sg > g.num) return dae::object_value_invalid;
    if (auto e = allowed(setting_group_action::select_active, *sg)) return e;
    activate_group(g, *sg);
    return std::nullopt;
  }
  if (attr == "EditSG") {
    const auto sg = as_group(v);
    if (!sg) return v.type() == mms::data_type::unsigned_ || v.type() == mms::data_type::integer
                        ? dae::object_value_invalid
                        : dae::type_inconsistent;
    if (*sg > g.num) return dae::object_value_invalid;
    if (g.owner != 0 && g.owner != s.id) return dae::temporarily_unavailable;
    if (auto e = allowed(setting_group_action::select_edit, *sg)) return e;
    if (*sg == 0) {
      release_edit(g);
      return std::nullopt;
    }
    g.owner = s.id;
    g.edit = *sg;
    g.edit_values = g.groups[*sg - 1U];
    arm(*this, g);
    sync(g);
    return std::nullopt;
  }
  if (attr == "CnfEdit") {
    auto b = v.as_boolean();
    if (!b) return dae::type_inconsistent;
    if (!*b) return std::nullopt;
    if (g.edit == 0) return dae::temporarily_unavailable;
    if (g.owner != s.id) return dae::object_access_denied;
    if (auto e = allowed(setting_group_action::confirm_edit, g.edit)) return e;
    g.groups[g.edit - 1U] = g.edit_values;
    if (g.edit == g.act) {
      std::vector<assignment> plan_items;
      for (std::size_t i = 0; i < g.holders.size(); ++i) {
        plan_items.push_back({g.holders[i], {}, g.edit_values[i]});
      }
      apply(std::move(plan_items));
    }
    arm(*this, g);
    sync(g);
    return std::nullopt;
  }
  return dae::object_access_denied;
}

std::optional<dae> server_state::write_edit(session& s, const target& t, const mms::data& v) {
  const auto holders = holders_under(t);
  if (holders.empty()) return dae::object_non_existent;
  const auto it = sgcb_of_holder.find(holders.front());
  if (it == sgcb_of_holder.end()) return dae::object_access_denied;
  auto& g = *it->second;
  if (g.edit == 0) return dae::temporarily_unavailable;
  if (g.owner != s.id) return dae::object_access_denied;
  auto type = type_of(t);
  if (!type) return dae::object_non_existent;
  auto c = conform(v, *type);
  if (auto* e = std::get_if<dae>(&c)) return *e;
  auto& value = std::get<mms::data>(c);
  if (options.on_write) {
    auto ref = acsi_reference(t);
    if (!ref) return dae::object_non_existent;
    if (auto refused = options.on_write(write_event{s.id, std::move(*ref), value})) return *refused;
  }
  std::vector<assignment> p;
  plan(t, value, p);
  for (auto& a : p) {
    const auto idx = g.index.find(a.holder);
    if (idx == g.index.end()) continue;
    mms::data* cur = &g.edit_values[idx->second];
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
  arm(*this, g);
  return std::nullopt;
}

}  // namespace openiec61850::server::detail
