// MMS services of the server (IEC 61850-8-1 §9 - §14).

#include <algorithm>
#include <limits>
#include <utility>
#include <variant>

#include "detail.hpp"
#include "values.hpp"

namespace openiec61850::server::detail {

namespace {

using model::fc;
namespace ec = mms::error_code;

template <typename... F>
struct overloaded : F... {
  using F::operator()...;
};
template <typename... F>
overloaded(F...) -> overloaded<F...>;

std::size_t identifier_cost(std::string_view name) noexcept {
  return name.size() + (name.size() > 127 ? 4 : 2);
}

std::optional<mms::data> owned(const mms::data_ref& r) {
  if (const auto* d = r.owned(); d != nullptr) return *d;
  auto d = mms::data::from_view(r.view());
  if (!d) return std::nullopt;
  return std::move(*d);
}

bool writable(model::functional_constraint f) noexcept {
  switch (f) {
    case fc::SP: case fc::SV: case fc::CF: case fc::DC: case fc::BL: case fc::SE:
      return true;
    default:
      return false;
  }
}

}  // namespace

std::shared_ptr<data_set> server_state::find_data_set(const session* s,
                                                      std::string_view mms_text) const {
  if (mms_text.starts_with('@')) {
    if (s == nullptr) return nullptr;
    const auto it = s->aa_sets.find(mms_text.substr(1));
    return it == s->aa_sets.end() ? nullptr : it->second;
  }
  const auto slash = mms_text.find('/');
  if (slash == std::string_view::npos) return nullptr;
  const auto it = data_sets.find({std::string(mms_text.substr(0, slash)),
                                  std::string(mms_text.substr(slash + 1))});
  return it == data_sets.end() ? nullptr : it->second;
}

result<std::shared_ptr<data_set>> server_state::make_data_set(
    std::string domain, std::string item, const mms::list_view<mms::variable_spec>& vars) {
  auto ds = std::make_shared<data_set>();
  ds->domain = std::move(domain);
  ds->item = std::move(item);
  ds->mms_text = ds->domain.empty() ? "@" + ds->item : ds->domain + "/" + ds->item;
  for (const auto vs : vars) {
    auto t = resolve_mms(vs.name, vs.alternate_access);
    if (!t || at(t->node).kind == node_kind::logical_node) {
      return make_error_code(errc::object_not_found);
    }
    member m;
    m.var.name = model::mms_name::from(vs.name);
    m.var.alternate_access.assign(vs.alternate_access.begin(), vs.alternate_access.end());
    m.mms_ref = mms_reference(*t);
    m.t = std::move(*t);
    ds->members.push_back(std::move(m));
  }
  for (std::size_t i = 0; i < ds->members.size(); ++i) {
    for (const auto h : holders_under(ds->members[i].t)) ds->by_holder[h].push_back(i);
  }
  return ds;
}

std::optional<dae> server_state::write_one(session& s, const target& t, const mms::data& value) {
  if (!t.fc) return dae::object_access_denied;
  const auto f = *t.fc;
  const auto& n = at(t.node);
  if (f == fc::BR || f == fc::RP) {
    if (!t.path.empty() || n.parent == no_node) return dae::object_access_denied;
    const auto it = rcb_of.find(n.parent);
    if (it == rcb_of.end()) return dae::object_access_denied;
    return write_rcb(s, *it->second, n.name, value);
  }
  if (f == fc::CO) return control_write(s, t, value);
  if (!writable(f) || n.kind == node_kind::logical_node) return dae::object_access_denied;
  auto type = type_of(t);
  if (!type) return dae::object_non_existent;
  auto c = conform(value, *type);
  if (auto* e = std::get_if<dae>(&c)) return *e;
  auto& v = std::get<mms::data>(c);
  if (options.on_write) {
    auto ref = acsi_reference(t);
    if (!ref) return dae::object_non_existent;
    write_event ev{s.id, std::move(*ref), v};
    if (auto refused = options.on_write(ev)) return *refused;
  }
  std::vector<assignment> p;
  plan(t, v, p);
  apply(std::move(p));
  return std::nullopt;
}

void server_state::dispatch(session& s, const mms::confirmed_service_request& req, reply& out) {
  std::visit(
      overloaded{
          [&](const mms::identify_request&) {
            out.response = mms::identify_response{options.ident.vendor, options.ident.model,
                                                  options.ident.revision, {}};
          },
          [&](const mms::get_name_list_request& r) {
            const std::vector<std::string>* list = nullptr;
            std::vector<std::string> tmp;
            const bool domain_scope = r.scope == mms::object_scope::domain_specific;
            node_id ld = no_node;
            if (domain_scope) {
              ld = model.find_logical_device(r.domain_id);
              if (ld == no_node) {
                out.fail(mms::error_class::definition, ec::definition::object_undefined);
                return;
              }
            }
            switch (r.cls) {
              case mms::object_class::domain:
                if (r.scope == mms::object_scope::vmd_specific) list = &domains;
                break;
              case mms::object_class::named_variable:
                if (domain_scope) list = &variable_names[ld];
                break;
              case mms::object_class::named_variable_list:
                if (domain_scope) {
                  for (const auto& [key, ds] : data_sets) {
                    if (key.first == r.domain_id) tmp.push_back(key.second);
                  }
                } else if (r.scope == mms::object_scope::aa_specific) {
                  for (const auto& [name, ds] : s.aa_sets) tmp.push_back(name);
                }
                break;
              default:
                break;
            }
            if (list == nullptr) list = &tmp;
            auto it = list->begin();
            if (r.continue_after) {
              it = std::upper_bound(list->begin(), list->end(), *r.continue_after,
                                    [](std::string_view a, const std::string& b) { return a < b; });
            }
            const std::size_t budget =
                s.max_pdu > 64 ? s.max_pdu - 32 : std::numeric_limits<std::size_t>::max();
            const std::size_t cap = options.max_names_per_response > 0
                                        ? options.max_names_per_response
                                        : std::numeric_limits<std::size_t>::max();
            std::size_t used = 0;
            for (; it != list->end() && out.names.size() < cap; ++it) {
              const auto cost = identifier_cost(*it);
              if (!out.names.empty() && used + cost > budget) break;
              used += cost;
              if (list == &tmp) {
                out.strings.push_back(*it);
                out.names.emplace_back(out.strings.back());
              } else {
                out.names.emplace_back(*it);
              }
            }
            out.response = mms::get_name_list_response{out.names, it != list->end()};
          },
          [&](const mms::read_request& r) {
            auto read_target = [&](const std::optional<target>& t) {
              if (!t) {
                out.results.emplace_back(dae::object_non_existent);
                return;
              }
              mms::data v;
              if (!control_read(s, *t, v)) {
                auto got = value_of(*t);
                if (!got) {
                  out.results.emplace_back(dae::object_non_existent);
                  return;
                }
                v = std::move(*got);
              }
              out.data.push_back(std::move(v));
              out.results.emplace_back(mms::data_ref(out.data.back()));
            };
            if (r.spec.type == mms::variable_access_specification::kind::list_of_variable) {
              for (const auto vs : r.spec.variables) {
                read_target(resolve_mms(vs.name, vs.alternate_access));
              }
            } else {
              std::shared_ptr<data_set> ds;
              if (r.spec.list_name.scope == mms::object_scope::domain_specific) {
                const auto it = data_sets.find(
                    {std::string(r.spec.list_name.domain_id), std::string(r.spec.list_name.item_id)});
                if (it != data_sets.end()) ds = it->second;
              } else if (r.spec.list_name.scope == mms::object_scope::aa_specific) {
                const auto it = s.aa_sets.find(r.spec.list_name.item_id);
                if (it != s.aa_sets.end()) ds = it->second;
              }
              if (!ds) {
                out.fail(mms::error_class::definition, ec::definition::object_undefined);
                return;
              }
              for (const auto& m : ds->members) read_target(m.t);
            }
            mms::read_response rr;
            if (r.specification_with_result) rr.spec = r.spec;
            rr.results = out.results;
            out.response = rr;
          },
          [&](const mms::write_request& r) {
            std::vector<std::optional<target>> targets;
            if (r.spec.type == mms::variable_access_specification::kind::list_of_variable) {
              for (const auto vs : r.spec.variables) {
                targets.push_back(resolve_mms(vs.name, vs.alternate_access));
              }
            } else {
              std::shared_ptr<data_set> ds;
              if (r.spec.list_name.scope == mms::object_scope::domain_specific) {
                const auto it = data_sets.find(
                    {std::string(r.spec.list_name.domain_id), std::string(r.spec.list_name.item_id)});
                if (it != data_sets.end()) ds = it->second;
              } else if (r.spec.list_name.scope == mms::object_scope::aa_specific) {
                const auto it = s.aa_sets.find(r.spec.list_name.item_id);
                if (it != s.aa_sets.end()) ds = it->second;
              }
              if (!ds) {
                out.fail(mms::error_class::definition, ec::definition::object_undefined);
                return;
              }
              for (const auto& m : ds->members) targets.emplace_back(m.t);
            }
            if (r.values.size() != targets.size()) {
              out.reject(mms::reject_code::confirmed_request::invalid_argument);
              return;
            }
            std::size_t i = 0;
            for (const auto value : r.values) {
              const auto& t = targets[i++];
              if (!t) {
                out.writes.emplace_back(dae::object_non_existent);
                continue;
              }
              auto v = owned(value);
              if (!v) {
                out.writes.emplace_back(dae::type_inconsistent);
                continue;
              }
              if (auto e = write_one(s, *t, *v)) {
                out.writes.emplace_back(*e);
              } else {
                out.writes.emplace_back();
              }
            }
            out.response = mms::write_response{out.writes};
          },
          [&](const mms::get_variable_access_attributes_request& r) {
            auto t = resolve_mms(r.name, {});
            if (!t) {
              out.fail(mms::error_class::definition, ec::definition::object_undefined);
              return;
            }
            auto type = type_of(*t);
            if (!type) {
              out.fail(mms::error_class::definition, ec::definition::object_undefined);
              return;
            }
            out.response = mms::get_variable_access_attributes_response{false, std::move(*type)};
          },
          [&](const mms::get_named_variable_list_attributes_request& r) {
            std::shared_ptr<data_set> ds;
            if (r.name.scope == mms::object_scope::domain_specific) {
              const auto it =
                  data_sets.find({std::string(r.name.domain_id), std::string(r.name.item_id)});
              if (it != data_sets.end()) ds = it->second;
            } else if (r.name.scope == mms::object_scope::aa_specific) {
              const auto it = s.aa_sets.find(r.name.item_id);
              if (it != s.aa_sets.end()) ds = it->second;
            }
            if (!ds) {
              out.fail(mms::error_class::definition, ec::definition::object_undefined);
              return;
            }
            for (const auto& m : ds->members) out.specs.push_back(m.var.spec());
            out.response = mms::get_named_variable_list_attributes_response{ds->deletable, out.specs};
          },
          [&](const mms::define_named_variable_list_request& r) {
            const auto count = r.variables.size();
            if (count == 0 || count > options.max_data_set_members) {
              out.fail(mms::error_class::resource, ec::resource::capability_unavailable);
              return;
            }
            std::string domain;
            std::string item(r.name.item_id);
            if (r.name.scope == mms::object_scope::domain_specific) {
              const node_id ld = model.find_logical_device(r.name.domain_id);
              const auto dollar = item.find('$');
              if (ld == no_node || dollar == std::string::npos ||
                  !model::is_identifier(item.substr(dollar + 1))) {
                out.fail(mms::error_class::definition, ec::definition::object_undefined);
                return;
              }
              const node_id ln = model.find_child(ld, item.substr(0, dollar));
              if (ln == no_node || at(ln).kind != node_kind::logical_node) {
                out.fail(mms::error_class::definition, ec::definition::object_undefined);
                return;
              }
              domain = std::string(r.name.domain_id);
              if (data_sets.contains({domain, item})) {
                out.fail(mms::error_class::definition, ec::definition::object_exists);
                return;
              }
              if (dynamic_data_sets >= options.max_persistent_data_sets) {
                out.fail(mms::error_class::resource, ec::resource::capability_unavailable);
                return;
              }
            } else if (r.name.scope == mms::object_scope::aa_specific) {
              if (!model::is_identifier(item)) {
                out.fail(mms::error_class::definition, ec::definition::type_unsupported);
                return;
              }
              if (s.aa_sets.contains(item)) {
                out.fail(mms::error_class::definition, ec::definition::object_exists);
                return;
              }
              if (s.aa_sets.size() >= options.max_association_data_sets) {
                out.fail(mms::error_class::resource, ec::resource::capability_unavailable);
                return;
              }
            } else {
              out.fail(mms::error_class::access, ec::access::object_access_unsupported);
              return;
            }
            auto ds = make_data_set(domain, item, r.variables);
            if (!ds) {
              out.fail(mms::error_class::definition, ec::definition::object_undefined);
              return;
            }
            (*ds)->deletable = true;
            if (domain.empty()) {
              (*ds)->owner = s.id;
              s.aa_sets.emplace(item, std::move(*ds));
            } else {
              data_sets.emplace(std::make_pair(domain, item), std::move(*ds));
              ++dynamic_data_sets;
            }
            out.response = mms::define_named_variable_list_response{};
          },
          [&](const mms::delete_named_variable_list_request& r) {
            std::uint32_t matched = 0;
            std::uint32_t deleted = 0;
            auto referenced = [&](const std::shared_ptr<data_set>& ds) {
              return std::any_of(rcbs.begin(), rcbs.end(),
                                 [&](const auto& rc) { return rc->ds == ds; });
            };
            auto try_domain = [&](decltype(data_sets)::iterator it) {
              ++matched;
              if (!it->second->deletable || referenced(it->second)) return std::next(it);
              ++deleted;
              --dynamic_data_sets;
              return data_sets.erase(it);
            };
            auto try_aa = [&](decltype(s.aa_sets)::iterator it) {
              ++matched;
              if (referenced(it->second)) return std::next(it);
              ++deleted;
              return s.aa_sets.erase(it);
            };
            switch (r.scope) {
              case mms::delete_scope::specific:
                for (const auto name : r.names) {
                  if (name.scope == mms::object_scope::domain_specific) {
                    auto it = data_sets.find({std::string(name.domain_id), std::string(name.item_id)});
                    if (it != data_sets.end()) try_domain(it);
                  } else if (name.scope == mms::object_scope::aa_specific) {
                    auto it = s.aa_sets.find(name.item_id);
                    if (it != s.aa_sets.end()) try_aa(it);
                  }
                }
                break;
              case mms::delete_scope::aa_specific:
                for (auto it = s.aa_sets.begin(); it != s.aa_sets.end();) it = try_aa(it);
                break;
              case mms::delete_scope::domain:
                for (auto it = data_sets.begin(); it != data_sets.end();) {
                  if (r.domain_name && it->first.first == *r.domain_name) {
                    it = try_domain(it);
                  } else {
                    ++it;
                  }
                }
                break;
              case mms::delete_scope::vmd:
                for (auto it = data_sets.begin(); it != data_sets.end();) it = try_domain(it);
                for (auto it = s.aa_sets.begin(); it != s.aa_sets.end();) it = try_aa(it);
                break;
            }
            out.response = mms::delete_named_variable_list_response{matched, deleted};
          },
          [&](const mms::other_service&) {
            out.reject(mms::reject_code::confirmed_request::unrecognized_service);
          },
      },
      req);
}

}  // namespace openiec61850::server::detail
