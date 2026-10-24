// Control model (IEC 61850-7-2 §20, IEC 61850-8-1 §20): direct-normal and sbo-normal security.
// Enhanced security (SBOw, CommandTermination) is not implemented: Oper/SBOw on such objects is
// refused with AddCause not-supported.

#include <chrono>
#include <utility>

#include "detail.hpp"
#include "values.hpp"

namespace openiec61850::server::detail {

namespace {

using model::fc;

// LastApplError Error codes (IEC 61850-8-1 §20): 0 no error, 1 unknown.
constexpr std::int64_t error_unknown = 1;

const mms::data* component(const server_state& st, node_id tmpl, const mms::data& v,
                           std::string_view name) {
  const auto& n = st.at(tmpl);
  const auto elems = v.elements();
  for (std::size_t i = 0; i < n.children.size() && i < elems.size(); ++i) {
    if (st.at(n.children[i]).name == name) return &elems[i];
  }
  return nullptr;
}

}  // namespace

namespace {

model::ctl_model ctl_model_of(const server_state& st, node_id do_id) {
  const node_id c = st.model.find_child(do_id, "ctlModel");
  if (c == no_node || !st.at(c).holds_value()) return model::ctl_model::direct_with_normal_security;
  auto v = st.values[c].as_int64();
  if (!v || *v < 0 || *v > 4) return model::ctl_model::status_only;
  return static_cast<model::ctl_model>(*v);
}

std::chrono::milliseconds sbo_timeout_of(const server_state& st, node_id do_id) {
  const node_id c = st.model.find_child(do_id, "sboTimeout");
  if (c != no_node && st.at(c).holds_value()) {
    auto v = st.values[c].as_uint64();
    if (v && *v > 0) return std::chrono::milliseconds(*v);
  }
  return st.options.default_sbo_timeout;
}

}  // namespace

bool server_state::control_read(session& s, const target& t, mms::data& out) {
  if (t.fc != fc::CO || !t.path.empty()) return false;
  const auto& n = at(t.node);
  if (n.name != "SBO" || n.parent == no_node || at(n.parent).kind != node_kind::data_object) {
    return false;
  }
  const node_id do_id = n.parent;
  out = mms::data::visible_string("");
  const auto ctl = ctl_model_of(*this, do_id);
  if (ctl != model::ctl_model::sbo_with_normal_security) return true;
  if (const auto it = selections.find(do_id); it != selections.end() && it->second.session != s.id) {
    return true;
  }
  auto ref = acsi_reference(target{do_id, std::nullopt, {}});
  if (!ref) return true;
  control_request req;
  req.association = s.id;
  req.action = control_action::select;
  req.object = ref->with_fc(std::nullopt);
  req.ctl_model = ctl;
  const auto res = options.on_control ? options.on_control(req) : control_result::refused(add_cause::not_supported);
  if (!res.accepted) return true;
  auto& sel = selections[do_id];
  sel.session = s.id;
  const auto gen = ++sel.gen;
  if (!sel.timer) sel.timer = std::make_unique<asio::steady_timer>(strand);
  sel.timer->expires_after(sbo_timeout_of(*this, do_id));
  sel.timer->async_wait([w = weak_from_this(), do_id, gen](std::error_code ec) {
    auto self = w.lock();
    if (!self || ec) return;
    const auto it = self->selections.find(do_id);
    if (it != self->selections.end() && it->second.gen == gen) self->selections.erase(it);
  });
  out = mms::data::visible_string(ref->text());
  return true;
}

std::optional<dae> server_state::control_write(session& s, const target& t, const mms::data& v) {
  const auto& n = at(t.node);
  if (!t.path.empty() || n.parent == no_node || at(n.parent).kind != node_kind::data_object ||
      (n.name != "Oper" && n.name != "Cancel" && n.name != "SBOw")) {
    return dae::object_access_denied;
  }
  const node_id do_id = n.parent;
  auto type = type_of(t);
  if (!type) return dae::object_non_existent;
  auto c = conform(v, *type);
  if (auto* e = std::get_if<dae>(&c)) return *e;
  const auto& value = std::get<mms::data>(c);
  auto ref = acsi_reference(target{do_id, std::nullopt, {}});
  if (!ref) return dae::object_non_existent;

  control_request req;
  req.association = s.id;
  req.object = ref->with_fc(std::nullopt);
  req.ctl_model = ctl_model_of(*this, do_id);
  req.action = n.name == "Cancel" ? control_action::cancel : control_action::operate;
  if (const auto* x = component(*this, t.node, value, "ctlVal")) req.ctl_val = *x;
  if (const auto* origin = component(*this, t.node, value, "origin")) {
    const node_id origin_node = model.find_child(t.node, "origin");
    if (origin_node != no_node) {
      if (const auto* cat = component(*this, origin_node, *origin, "orCat")) {
        if (auto oc = model::orcat_from_mms(*cat)) req.or_cat = *oc;
      }
      if (const auto* ident = component(*this, origin_node, *origin, "orIdent")) {
        if (auto b = ident->as_octet_string()) req.or_ident.assign(b->begin(), b->end());
      }
    }
  }
  if (const auto* x = component(*this, t.node, value, "ctlNum")) {
    if (auto u = x->as_uint64()) req.ctl_num = *u;
  }
  if (const auto* x = component(*this, t.node, value, "T")) {
    if (auto ts = model::timestamp::from_mms(*x)) req.t = *ts;
  }
  if (const auto* x = component(*this, t.node, value, "Test")) {
    if (auto b = x->as_boolean()) req.test = *b;
  }
  if (const auto* x = component(*this, t.node, value, "Check")) {
    if (auto ch = model::check_conditions::from_mms(*x)) req.check = *ch;
  }

  // IEC 61850-8-1 §20: a negative Oper/Cancel response is preceded by a LastApplError report.
  auto refuse = [&](add_cause cause) -> std::optional<dae> {
    if (s.assoc) {
      std::vector<mms::data> origin;
      origin.push_back(mms::data::integer(req.or_cat ? static_cast<std::int64_t>(*req.or_cat) : 0));
      origin.push_back(mms::data::octet_string(req.or_ident));
      std::vector<mms::data> fields;
      const auto obj = mms_reference(t);
      fields.push_back(mms::data::visible_string(obj));
      fields.push_back(mms::data::integer(error_unknown));
      fields.push_back(mms::data::structure(std::move(origin)));
      fields.push_back(mms::data::unsigned_integer(req.ctl_num));
      fields.push_back(mms::data::integer(static_cast<std::int64_t>(cause)));
      const auto report = mms::data::structure(std::move(fields));
      const std::vector<mms::variable_spec> vars{mms::variable_spec(mms::object_name::vmd("LastApplError"))};
      const std::vector<mms::access_result> results{mms::access_result(mms::data_ref(report))};
      const mms::information_report ir{mms::variable_access_specification::list(vars), results};
      s.push(s.assoc->send_unconfirmed(ir));
    }
    return dae::object_access_denied;
  };

  if (n.name == "SBOw") return refuse(add_cause::not_supported);
  if (!options.on_control) return refuse(add_cause::not_supported);
  const auto it = selections.find(do_id);
  const bool selected_here = it != selections.end() && it->second.session == s.id;

  if (req.action == control_action::cancel) {
    if (req.ctl_model != model::ctl_model::sbo_with_normal_security) {
      return refuse(add_cause::not_supported);
    }
    if (!selected_here) return refuse(add_cause::object_not_selected);
    selections.erase(it);
    (void)options.on_control(req);
    return std::nullopt;
  }

  switch (req.ctl_model) {
    case model::ctl_model::direct_with_normal_security:
      break;
    case model::ctl_model::sbo_with_normal_security:
      if (!selected_here) return refuse(add_cause::object_not_selected);
      selections.erase(it);
      break;
    default:
      return refuse(add_cause::not_supported);
  }
  const auto res = options.on_control(req);
  if (!res.accepted) return refuse(res.cause);
  return std::nullopt;
}

void server_state::control_session_closed(session& s) {
  for (auto it = selections.begin(); it != selections.end();) {
    if (it->second.session == s.id) {
      it = selections.erase(it);
    } else {
      ++it;
    }
  }
}

}  // namespace openiec61850::server::detail
