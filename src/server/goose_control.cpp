// GOOSE control blocks as MMS variables (IEC 61850-7-2 §18.2, IEC 61850-8-1 §18.1): "LN$GO$name".
// GoEna is writable at any time; GoID and DatSet only while GoEna is false (a new DatSet
// increments ConfRev and sets NdsCom when there is no data set). The other attributes are
// read-only. Each accepted change is reported through server_options::on_goose_control.

#include <utility>

#include "detail.hpp"

namespace openiec61850::server::detail {

void server_state::init_gocb(const goose_control_definition& def) {
  auto g = std::make_unique<gocb>();
  g->node = def.node;
  g->ln = def.ln;
  for (const auto c : at(def.node).children) g->attrs.emplace(at(c).name, c);
  g->live = def.settings;
  if (auto ref = acsi_reference(target{def.node, model::fc::GO, {}})) g->reference = std::move(*ref);
  if (!def.settings.data_set.empty()) {
    const node_id ld = model.logical_device_of(def.ln);
    const auto it = data_sets.find({at(ld).name, at(def.ln).name + "$" + def.settings.data_set});
    if (it != data_sets.end()) {
      g->ds = it->second;
      g->dat_set = it->second->mms_text;
    }
  }
  gocb_of[def.node] = g.get();
  sync(*g);
  gocbs.push_back(std::move(g));
}

void server_state::sync(gocb& g) {
  auto set = [&](std::string_view name, mms::data v) {
    if (const auto it = g.attrs.find(name); it != g.attrs.end()) values[it->second] = std::move(v);
  };
  set("GoEna", mms::data::boolean(g.live.go_ena));
  set("GoID", mms::data::visible_string(g.live.go_id));
  set("DatSet", mms::data::visible_string(g.dat_set));
  set("ConfRev", mms::data::unsigned_integer(g.live.conf_rev));
  set("NdsCom", mms::data::boolean(!g.ds));
}

goose_control_state server_state::state_of(const gocb& g) const {
  goose_control_state st;
  st.reference = g.reference;
  st.go_ena = g.live.go_ena;
  st.go_id = g.live.go_id;
  st.dat_set = g.dat_set;
  if (g.ds) {
    for (const auto& m : g.ds->members) {
      if (auto r = acsi_reference(m.t)) st.members.push_back(std::move(*r));
    }
  }
  st.conf_rev = g.live.conf_rev;
  st.nds_com = !g.ds;
  st.dst_mac = g.live.dst_mac;
  st.vlan_priority = g.live.vlan_priority;
  st.vlan_id = g.live.vlan_id;
  st.app_id = g.live.app_id;
  st.min_time = g.live.min_time;
  st.max_time = g.live.max_time;
  st.fixed_offs = g.live.fixed_offs;
  return st;
}

std::optional<dae> server_state::write_gocb(session& s, gocb& g, std::string_view attr,
                                            const mms::data& v) {
  const bool ed1 = model.edition() == model::edition::ed1;
  if (attr == "GoEna") {
    auto b = v.as_boolean();
    if (!b) return dae::type_inconsistent;
    if (*b && !g.ds) return dae::object_attribute_inconsistent;
    g.live.go_ena = *b;
  } else if (attr == "GoID") {
    if (g.live.go_ena) return dae::temporarily_unavailable;
    auto x = v.as_visible_string();
    if (!x) return dae::type_inconsistent;
    if (x->size() > (ed1 ? 65U : 129U)) return dae::object_value_invalid;
    g.live.go_id = std::string(*x);
  } else if (attr == "DatSet") {
    if (g.live.go_ena) return dae::temporarily_unavailable;
    auto x = v.as_visible_string();
    if (!x) return dae::type_inconsistent;
    std::shared_ptr<data_set> ds;
    if (!x->empty()) {
      if (x->starts_with('@')) return dae::object_value_invalid;
      ds = find_data_set(&s, *x);
      if (!ds) return dae::object_value_invalid;
    }
    if (ds != g.ds) {
      g.ds = ds;
      g.dat_set = ds ? ds->mms_text : std::string{};
      ++g.live.conf_rev;
    }
  } else {
    return dae::object_access_denied;
  }
  sync(g);
  if (options.on_goose_control) options.on_goose_control({s.id, state_of(g)});
  return std::nullopt;
}

}  // namespace openiec61850::server::detail
