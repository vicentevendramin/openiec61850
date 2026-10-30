// Control model (IEC 61850-7-2 §20, IEC 61850-8-1 §20): direct and sbo, with normal and enhanced
// security.
//
//   sbo-with-normal-security    Select = Read of SBO (the DO reference when selected, "" when
//                               not), Operate = Write of Oper, Cancel = Write of Cancel.
//   sbo-with-enhanced-security  SelectWithValue = Write of SBOw; Oper and Cancel must repeat its
//                               ctlVal, origin, ctlNum and Test (inconsistent-parameters).
//   direct-*                    Operate = Write of Oper (Cancel only for a time-activated
//                               operate with enhanced security).
//
// A refused request is a negative Write response (or SBO = "") preceded by a LastApplError
// InformationReport. With enhanced security an accepted Operate ends with a CommandTermination:
// an InformationReport of "LN$CO$DO$Oper" carrying the Oper value (positive), or of
// LastApplError and "LN$CO$DO$Oper" (negative). The termination is always sent after the Write
// response: it is posted to the strand, behind the response pushed by handle_request().
//
// Selections time out after CF sboTimeout (operate-once: an Operate or a Cancel deselects;
// sboClass operate-many is not supported). Operations with operTm (TimeActivatedOperate) are
// accepted at once and handed to the application when the time comes.

#include <chrono>
#include <utility>

#include <asio/post.hpp>

#include "detail.hpp"
#include "values.hpp"

namespace openiec61850::server {

bool control_completion::complete(const control_result& result) const {
  if (!state_ || state_->done.exchange(true)) return false;
  auto st = state_->state.lock();
  if (!st || st->stopped) return false;
  asio::post(st->strand, [st, object = state_->object, gen = state_->gen, result] {
    st->finish_execution(object, gen, result);
  });
  return true;
}

}  // namespace openiec61850::server

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

bool is_enhanced(model::ctl_model m) noexcept {
  return m == model::ctl_model::direct_with_enhanced_security ||
         m == model::ctl_model::sbo_with_enhanced_security;
}

std::optional<std::int64_t> status_of(const server_state& st, node_id ln, std::string_view dobj) {
  if (ln == no_node) return std::nullopt;
  const node_id d = st.model.find_child(ln, dobj);
  if (d == no_node) return std::nullopt;
  const node_id v = st.model.find_child(d, "stVal");
  if (v == no_node || !st.at(v).holds_value()) return std::nullopt;
  auto i = st.values[v].as_int64();
  if (!i) return std::nullopt;
  return *i;
}

// The behaviour governing a DO (7-4 Annex A): Beh of its LN, else Beh or Mod of LLN0.
std::optional<model::behaviour> behaviour_of(const server_state& st, node_id do_id) {
  const node_id ln = st.model.logical_node_of(do_id);
  auto b = status_of(st, ln, "Beh");
  if (!b) {
    const node_id lln0 = st.model.find_child(st.model.logical_device_of(ln), "LLN0");
    b = status_of(st, lln0, "Beh");
    if (!b) b = status_of(st, lln0, "Mod");
  }
  if (!b || *b < 1 || *b > 5) return std::nullopt;
  return static_cast<model::behaviour>(*b);
}

// Whether the Test flag of a command is acceptable in the current behaviour.
bool test_mode_allows(const server_state& st, node_id do_id, bool test) {
  if (!st.options.check_test_mode || st.at(do_id).name == "Mod") return true;
  const auto b = behaviour_of(st, do_id);
  if (!b) return true;
  switch (*b) {
    case model::behaviour::on:
    case model::behaviour::on_blocked:
      return !test;
    case model::behaviour::test:
    case model::behaviour::test_blocked:
      return test;
    case model::behaviour::off:
      return false;
  }
  return true;
}

control_params params_of(const control_request& r) {
  return {r.ctl_val, r.or_cat, r.or_ident, r.ctl_num, r.test};
}

bool same_origin(const control_params& p, const control_request& r) {
  return p.or_cat == r.or_cat && p.or_ident == r.or_ident && p.ctl_num == r.ctl_num &&
         p.test == r.test;
}

mms::data last_appl_error(std::string cntrl_obj, const control_request& req, add_cause cause) {
  std::vector<mms::data> origin;
  origin.push_back(mms::data::integer(req.or_cat ? static_cast<std::int64_t>(*req.or_cat) : 0));
  origin.push_back(mms::data::octet_string(req.or_ident));
  std::vector<mms::data> fields;
  fields.push_back(mms::data::visible_string(std::move(cntrl_obj)));
  fields.push_back(mms::data::integer(error_unknown));
  fields.push_back(mms::data::structure(std::move(origin)));
  fields.push_back(mms::data::unsigned_integer(req.ctl_num));
  fields.push_back(mms::data::integer(static_cast<std::int64_t>(cause)));
  return mms::data::structure(std::move(fields));
}

// Sends an InformationReport of LastApplError (when `error` is set) and/or of a domain variable
// "LD/item" (when `oper_ref` is not empty).
void send_control_report(session& s, const mms::data* error, std::string_view oper_ref,
                         const mms::data* oper) {
  if (!s.assoc) return;
  std::vector<mms::variable_spec> vars;
  std::vector<mms::access_result> results;
  result<model::mms_variable> var = make_error_code(errc::object_not_found);
  if (error != nullptr) {
    vars.emplace_back(mms::object_name::vmd("LastApplError"));
    results.emplace_back(mms::data_ref(*error));
  }
  if (!oper_ref.empty() && oper != nullptr) {
    // An element of an array of data objects is named with an AlternateAccess.
    const model::parse_options po{model::name_limits::unlimited(), false};
    if (auto ref = model::from_mms_data_reference(oper_ref, po)) {
      var = model::to_mms_variable(*ref, po.limits);
      if (var) {
        vars.push_back(var->spec());
        results.emplace_back(mms::data_ref(*oper));
      }
    }
  }
  if (vars.empty()) return;
  const mms::information_report ir{mms::variable_access_specification::list(vars), results};
  s.push(s.assoc->send_unconfirmed(ir));
}

void fill_request(const server_state& st, node_id tmpl, const mms::data& value,
                  control_request& req) {
  if (const auto* x = component(st, tmpl, value, "ctlVal")) req.ctl_val = *x;
  if (const auto* x = component(st, tmpl, value, "operTm")) {
    if (auto ts = model::timestamp::from_mms(*x); ts && (ts->seconds() != 0 || ts->fraction() != 0)) {
      req.oper_time = *ts;
    }
  }
  if (const auto* origin = component(st, tmpl, value, "origin")) {
    const node_id origin_node = st.model.find_child(tmpl, "origin");
    if (origin_node != no_node) {
      if (const auto* cat = component(st, origin_node, *origin, "orCat")) {
        if (auto oc = model::orcat_from_mms(*cat)) req.or_cat = *oc;
      }
      if (const auto* ident = component(st, origin_node, *origin, "orIdent")) {
        if (auto b = ident->as_octet_string()) {
          req.or_ident.assign(b->begin(), b->end());
        } else if (auto vs = ident->as_visible_string()) {
          req.or_ident.assign(vs->begin(), vs->end());
        }
      }
    }
  }
  if (const auto* x = component(st, tmpl, value, "ctlNum")) {
    if (auto u = x->as_uint64()) req.ctl_num = *u;
  }
  if (const auto* x = component(st, tmpl, value, "T")) {
    if (auto ts = model::timestamp::from_mms(*x)) req.t = *ts;
  }
  if (const auto* x = component(st, tmpl, value, "Test")) {
    if (auto b = x->as_boolean()) req.test = *b;
  }
  if (const auto* x = component(st, tmpl, value, "Check")) {
    if (auto ch = model::check_conditions::from_mms(*x)) req.check = *ch;
  }
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
  auto refuse = [&](add_cause cause) {
    const auto e = last_appl_error(mms_reference(t), req, cause);
    send_control_report(s, &e, {}, nullptr);
    return true;
  };
  if (executions.contains(do_id)) return refuse(add_cause::command_already_in_execution);
  const auto res =
      options.on_control ? options.on_control(req) : control_result::refused(add_cause::not_supported);
  if (!res.accepted()) return refuse(res.cause);
  auto& sel = selections[do_id];
  sel.session = s.id;
  sel.sbow.reset();
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
  req.action = n.name == "Cancel" ? control_action::cancel
               : n.name == "SBOw" ? control_action::select
                                  : control_action::operate;
  fill_request(*this, t.node, value, req);

  // IEC 61850-8-1 §20: a negative response is preceded by a LastApplError report.
  auto refuse = [&](add_cause cause, dae code = dae::object_access_denied) -> std::optional<dae> {
    const auto e = last_appl_error(mms_reference(t), req, cause);
    send_control_report(s, &e, {}, nullptr);
    return code;
  };

  if (!options.on_control) return refuse(add_cause::not_supported);
  const auto ctl = req.ctl_model;
  const bool sbo = ctl == model::ctl_model::sbo_with_normal_security ||
                   ctl == model::ctl_model::sbo_with_enhanced_security;
  const bool enhanced = is_enhanced(ctl);
  switch (req.action) {
    case control_action::select:
      if (ctl != model::ctl_model::sbo_with_enhanced_security) return refuse(add_cause::not_supported);
      break;
    case control_action::operate:
      if (ctl == model::ctl_model::status_only) return refuse(add_cause::not_supported);
      break;
    case control_action::cancel:
      if (!sbo && ctl != model::ctl_model::direct_with_enhanced_security) {
        return refuse(add_cause::not_supported);
      }
      break;
  }

  // An operation in progress: only the Cancel of a time-activated operate of the same client.
  if (const auto ex = executions.find(do_id); ex != executions.end()) {
    auto& e = ex->second;
    if (req.action != control_action::cancel || !e.waiting_activation || e.session != s.id) {
      return refuse(add_cause::command_already_in_execution);
    }
    if (enhanced && !same_origin(params_of(e.req), req)) {
      return refuse(add_cause::inconsistent_parameters, dae::object_value_invalid);
    }
    const auto res = options.on_control(req);
    if (!res.accepted()) return refuse(res.cause);
    e.waiting_activation = false;
    e.timer.reset();
    e.completion->done = true;
    // The negative termination of the aborted operate follows the Cancel response.
    if (e.enhanced) {
      asio::post(strand, [w = weak_from_this(), do_id, gen = e.gen] {
        if (auto self = w.lock()) {
          self->finish_execution(do_id, gen, control_result::refused(add_cause::abortion_by_cancel));
        }
      });
    } else {
      executions.erase(ex);
    }
    return std::nullopt;
  }

  if (!test_mode_allows(*this, do_id, req.test)) return refuse(add_cause::blocked_by_mode);

  const auto sel = selections.find(do_id);
  const bool selected_here = sel != selections.end() && sel->second.session == s.id;

  if (req.action == control_action::select) {
    if (sel != selections.end()) {
      return refuse(add_cause::object_already_selected,
                    selected_here ? dae::object_access_denied : dae::temporarily_unavailable);
    }
    const auto res = options.on_control(req);
    if (!res.accepted()) return refuse(res.cause);
    auto& ns = selections[do_id];
    ns.session = s.id;
    ns.sbow = params_of(req);
    const auto gen = ++ns.gen;
    if (!ns.timer) ns.timer = std::make_unique<asio::steady_timer>(strand);
    ns.timer->expires_after(sbo_timeout_of(*this, do_id));
    ns.timer->async_wait([w = weak_from_this(), do_id, gen](std::error_code ec) {
      auto self = w.lock();
      if (!self || ec) return;
      const auto it = self->selections.find(do_id);
      if (it != self->selections.end() && it->second.gen == gen) self->selections.erase(it);
    });
    return std::nullopt;
  }

  if (sbo) {
    if (!selected_here) {
      return refuse(add_cause::object_not_selected);
    }
    if (sel->second.sbow) {
      const auto& p = *sel->second.sbow;
      if (!same_origin(p, req) || !(p.ctl_val == req.ctl_val)) {
        return refuse(add_cause::inconsistent_parameters, dae::object_value_invalid);
      }
    }
  }

  if (req.action == control_action::cancel) {
    const auto res = options.on_control(req);
    if (!res.accepted()) return refuse(res.cause);
    if (sel != selections.end()) selections.erase(sel);
    return std::nullopt;
  }

  // Operate. The selection ends with it, accepted or not (operate-once).
  if (sel != selections.end() && selected_here) selections.erase(sel);

  const auto gen = ++next_control_gen;
  auto completion = std::make_shared<completion_state>();
  completion->state = weak_from_this();
  completion->object = do_id;
  completion->gen = gen;
  req.completion = completion_state::make(completion);

  execution e;
  e.session = s.id;
  e.gen = gen;
  e.enhanced = enhanced;
  e.req = req;
  e.oper = value;
  e.oper_node = t.node;
  e.completion = completion;

  if (req.oper_time && req.oper_time->to_time_point() > std::chrono::system_clock::now()) {
    // TimeActivatedOperate: accepted now, run at operTm.
    e.waiting_activation = true;
    e.timer = std::make_unique<asio::steady_timer>(strand);
    const auto delay = req.oper_time->to_time_point() - std::chrono::system_clock::now();
    e.timer->expires_after(std::chrono::duration_cast<clock::duration>(delay));
    e.timer->async_wait([w = weak_from_this(), do_id, gen](std::error_code ec) {
      auto self = w.lock();
      if (!self || ec) return;
      self->activate(do_id, gen);
    });
    executions.emplace(do_id, std::move(e));
    return std::nullopt;
  }

  auto& placed = executions.emplace(do_id, std::move(e)).first->second;
  const auto res = options.on_control(req);
  if (!res.accepted()) {
    placed.completion->done = true;
    executions.erase(do_id);
    return refuse(res.cause);
  }
  if (res.outcome == control_result::kind::accepted) {
    placed.completion->done = true;
    if (!enhanced) {
      executions.erase(do_id);
    } else {
      asio::post(strand, [w = weak_from_this(), do_id, gen] {
        if (auto self = w.lock()) self->finish_execution(do_id, gen, control_result::ok());
      });
    }
    return std::nullopt;
  }
  // Pending: completed by the application, or by operate_timeout.
  if (options.operate_timeout.count() > 0) {
    placed.timer = std::make_unique<asio::steady_timer>(strand);
    placed.timer->expires_after(options.operate_timeout);
    placed.timer->async_wait([w = weak_from_this(), do_id, gen](std::error_code ec) {
      auto self = w.lock();
      if (!self || ec) return;
      const auto it = self->executions.find(do_id);
      if (it == self->executions.end() || it->second.gen != gen) return;
      if (it->second.completion->done.exchange(true)) return;  // a completion is on its way
      self->finish_execution(do_id, gen, control_result::refused(add_cause::time_limit_over));
    });
  }
  return std::nullopt;
}

void server_state::activate(node_id object, std::uint64_t gen) {
  const auto it = executions.find(object);
  if (it == executions.end() || it->second.gen != gen || !it->second.waiting_activation) return;
  auto& e = it->second;
  e.waiting_activation = false;
  e.timer.reset();
  if (!test_mode_allows(*this, object, e.req.test)) {
    e.completion->done = true;
    finish_execution(object, gen, control_result::refused(add_cause::blocked_by_mode));
    return;
  }
  const auto res = options.on_control ? options.on_control(e.req)
                                      : control_result::refused(add_cause::not_supported);
  if (res.outcome == control_result::kind::pending) {
    if (options.operate_timeout.count() > 0) {
      e.timer = std::make_unique<asio::steady_timer>(strand);
      e.timer->expires_after(options.operate_timeout);
      e.timer->async_wait([w = weak_from_this(), object, gen](std::error_code ec) {
        auto self = w.lock();
        if (!self || ec) return;
        const auto x = self->executions.find(object);
        if (x == self->executions.end() || x->second.gen != gen) return;
        if (x->second.completion->done.exchange(true)) return;
        self->finish_execution(object, gen, control_result::refused(add_cause::time_limit_over));
      });
    }
    return;
  }
  e.completion->done = true;
  finish_execution(object, gen, res);
}

void server_state::finish_execution(node_id object, std::uint64_t gen, control_result r) {
  const auto it = executions.find(object);
  if (it == executions.end() || it->second.gen != gen) return;
  execution e = std::move(it->second);
  executions.erase(it);
  e.completion->done = true;
  session* s = find_session(e.session);
  if (s == nullptr || s->closed) return;
  const auto oper_ref = mms_reference(target{e.oper_node, fc::CO, {}});
  if (e.enhanced) {
    // CommandTermination (8-1 §20.7): positive, or LastApplError + Oper.
    if (r.accepted()) {
      send_control_report(*s, nullptr, oper_ref, &e.oper);
    } else {
      const auto err = last_appl_error(oper_ref, e.req, r.cause);
      send_control_report(*s, &err, oper_ref, &e.oper);
    }
  } else if (!r.accepted()) {
    // Normal security has no termination; a failed time-activated operate is still reported.
    const auto err = last_appl_error(oper_ref, e.req, r.cause);
    send_control_report(*s, &err, {}, nullptr);
  }
}

void server_state::control_session_closed(session& s) {
  for (auto it = selections.begin(); it != selections.end();) {
    if (it->second.session == s.id) {
      it = selections.erase(it);
    } else {
      ++it;
    }
  }
  // Executions continue (the command was accepted); their termination has nowhere to go.
}

void server_state::control_shutdown() {
  selections.clear();
  for (auto& [id, e] : executions) {
    if (e.completion) e.completion->done = true;
  }
  executions.clear();
}

}  // namespace openiec61850::server::detail
