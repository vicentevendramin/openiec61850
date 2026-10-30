#include <algorithm>
#include <set>
#include <string>
#include <unordered_map>
#include <utility>

#include "openiec61850/scl/instance.hpp"

namespace openiec61850::scl {
namespace {

using code = diagnostic_code;
using model::functional_constraint;

using object_path = std::vector<std::optional<std::uint32_t>>;

std::string in_quotes(std::string_view s) {
  std::string out{"'"};
  out += s;
  out += '\'';
  return out;
}

data_node* find_child(data_node& n, std::string_view name) {
  const auto it = std::find_if(n.children.begin(), n.children.end(),
                               [&](const data_node& c) { return c.name == name; });
  return it == n.children.end() ? nullptr : &*it;
}

class builder {
 public:
  builder(const document& doc, const ied& i, diagnostics* diags, const instantiate_options& opts)
      : doc_(doc), ied_(i), diags_(diags), opts_(opts) {
    const auto& t = doc.templates;
    for (const auto& x : t.lnode_types) lnode_types_.emplace(x.id, &x);
    for (const auto& x : t.do_types) do_types_.emplace(x.id, &x);
    for (const auto& x : t.da_types) da_types_.emplace(x.id, &x);
    for (const auto& x : t.enum_types) enum_types_.emplace(x.id, &x);
  }

  [[nodiscard]] bool failed() const noexcept { return overflow_; }
  [[nodiscard]] bool had_errors() const noexcept { return errors_; }

  instantiated_ld build_ld(const logical_device& ld) {
    instantiated_ld out;
    out.name = ld.name(ied_.name);
    out.inst = ld.inst;
    out.desc = ld.desc;
    out.lns.reserve(ld.lns.size() + 1);
    if (auto ln0 = build_ln(ld.ln0, out.name, true)) out.lns.push_back(std::move(*ln0));
    for (const auto& ln : ld.lns) {
      if (overflow_) break;
      if (auto x = build_ln(ln, out.name, false)) out.lns.push_back(std::move(*x));
    }
    return out;
  }

  // Second pass, once every LD exists: FCDAs may reference other LDs of the server.
  // The FCDA ix selects an element of the array among its names, while make_fcda_reference puts it
  // on the last one: "DO.DA(1)" is really "DO(1).DA" when DO is the array.
  static std::optional<model::object_reference> index_on_array(const instantiated_ied& out,
                                                               const model::object_reference& ref,
                                                               const model::parse_options& opts) {
    const auto leaf = ref.leaf();
    const auto* ld = out.find(ref.ld());
    const auto* ln = ld != nullptr ? ld->find(ref.ln()) : nullptr;
    if (ln == nullptr || !leaf || !leaf->index) return std::nullopt;
    std::string text{ref.ld()};
    text += '/';
    text += ref.ln();
    const data_node* node = nullptr;
    bool placed = false;
    for (const auto e : ref.path()) {
      node = node == nullptr ? ln->find(e.name) : node->child(e.name);
      if (node == nullptr) return std::nullopt;
      text += '.';
      text += e.name;
      if (!placed && node->count > 0) {
        text += '(' + std::to_string(*leaf->index) + ')';
        placed = true;
      }
    }
    if (!placed) return std::nullopt;
    auto moved = model::object_reference::parse(text, opts);
    if (!moved) return std::nullopt;
    moved->set_fc(ref.fc());
    return std::move(*moved);
  }

  void resolve_data_sets(instantiated_ied& out, const server& srv) {
    std::unordered_map<std::string_view, std::string> ld_names;
    for (const auto& ld : srv.ldevices) ld_names.emplace(ld.inst, ld.name(ied_.name));
    const auto strict_limits = model::parse_options_for(doc_.edition);
    const model::parse_options relaxed{model::name_limits::unlimited(), true};

    for (std::size_t li = 0; li < srv.ldevices.size() && li < out.lds.size(); ++li) {
      const auto& ld = srv.ldevices[li];
      auto& ild = out.lds[li];
      auto handle_ln = [&](const logical_node& ln) {
        const auto name = ln.name();
        const auto it = std::find_if(ild.lns.begin(), ild.lns.end(),
                                     [&](const instantiated_ln& l) { return l.name == name; });
        if (it == ild.lns.end()) return;
        auto* iln = &*it;
        for (const auto& ds : ln.data_sets) {
          resolved_data_set rds{ds.name, ds.desc, {}};
          for (const auto& m : ds.members) {
            const auto ld_it = ld_names.find(m.ld_inst);
            if (ld_it == ld_names.end()) {
              error(code::unresolved_reference, m.line,
                    "FCDA of data set " + in_quotes(ds.name) + " names unknown LD inst " +
                        in_quotes(m.ld_inst));
              continue;
            }
            auto ref = make_fcda_reference(ld_it->second, m, strict_limits);
            if (!ref && ref.error() == make_error_code(errc::length_overflow)) {
              ref = make_fcda_reference(ld_it->second, m, relaxed);
              if (ref) {
                warning(code::invalid_name, m.line,
                        "FCDA " + ref->to_string() + " exceeds the name limits of the edition");
              }
            }
            if (!ref) {
              error(code::invalid_name, m.line,
                    "FCDA of data set " + in_quotes(ds.name) + " does not form a valid reference");
              continue;
            }
            if (out.find(*ref) == nullptr) {
              if (auto moved = index_on_array(out, *ref, relaxed)) ref = std::move(*moved);
            }
            if (out.find(*ref) == nullptr) {
              error(code::unresolved_reference, m.line,
                    "FCDA " + ref->to_string() + " of data set " + in_quotes(ds.name) +
                        " does not exist in the data model");
              continue;
            }
            rds.members.push_back(std::move(*ref));
          }
          iln->data_sets.push_back(std::move(rds));
        }
      };
      handle_ln(ld.ln0);
      for (const auto& ln : ld.lns) handle_ln(ln);
    }
  }

  void collect_enums(instantiated_ied& out) const {
    for (const auto& e : doc_.templates.enum_types) {
      if (used_enums_.contains(e.id) && out.find_enum_type(e.id) == nullptr) {
        out.enum_types.push_back(e);
      }
    }
  }

 private:
  void error(code c, std::uint32_t line, std::string msg) {
    errors_ = true;
    if (diags_ != nullptr) diags_->error(c, line, std::move(msg));
  }
  void warning(code c, std::uint32_t line, std::string msg) {
    if (diags_ != nullptr) diags_->warning(c, line, std::move(msg));
  }

  bool take_node(std::uint32_t line) {
    if (overflow_) return false;
    if (++nodes_ <= opts_.max_nodes) return true;
    overflow_ = true;
    error(code::limit_exceeded, line, "instantiated data model exceeds max_nodes");
    return false;
  }

  std::optional<instantiated_ln> build_ln(const logical_node& ln, const std::string& ld_name,
                                          bool ln0) {
    instantiated_ln out;
    out.name = ln.name();
    out.prefix = ln.prefix;
    out.ln_class = ln.ln_class;
    out.inst = ln.inst;
    out.ln_type = ln.ln_type;
    out.desc = ln.desc;
    out.report_controls = ln.report_controls;
    out.log_controls = ln.log_controls;
    out.gse_controls = ln.gse_controls;
    out.smv_controls = ln.smv_controls;
    out.setting = ln.setting;

    const auto where = ld_name + "/" + out.name;
    const auto it = lnode_types_.find(ln.ln_type);
    if (it == lnode_types_.end()) {
      error(code::unknown_type, ln.line,
            "LNodeType " + in_quotes(ln.ln_type) + " of " + where + " is not defined" +
                (ln0 ? "" : "; LN dropped"));
      if (ln0) return out;
      return std::nullopt;
    }
    for (const auto& d : it->second->data_objects) {
      std::vector<std::string_view> active;
      if (auto node = build_do(d.name, d.desc, d.type, d.count, d.line, 1, active)) {
        out.data_objects.push_back(std::move(*node));
      }
      if (overflow_) return std::nullopt;
    }
    for (const auto& doi : ln.data) {
      const auto node = std::find_if(out.data_objects.begin(), out.data_objects.end(),
                                     [&](const data_node& n) { return n.name == doi.name; });
      if (node == out.data_objects.end()) {
        warning(code::unresolved_reference, doi.line,
                "DOI " + in_quotes(doi.name) + " of " + where + " is not a data object of LNodeType " +
                    in_quotes(ln.ln_type));
        continue;
      }
      if (!doi.desc.empty()) node->desc = doi.desc;
      if (node->count > 0 && doi.ix && *doi.ix >= node->count) {
        warning(code::unresolved_reference, doi.line,
                "DOI " + in_quotes(doi.name) + " index " + std::to_string(*doi.ix) +
                    " is outside the array");
        continue;
      }
      object_path objects;
      if (node->count > 0) objects.push_back(doi.ix);
      apply_instance(*node, doi, where + "." + doi.name, std::nullopt, objects, 1);
    }
    return out;
  }

  std::optional<data_node> build_do(std::string_view name, std::string_view desc,
                                    std::string_view type_id, std::uint32_t count,
                                    std::uint32_t line, std::size_t depth,
                                    std::vector<std::string_view>& active) {
    const auto it = do_types_.find(type_id);
    if (it == do_types_.end()) {
      error(code::unknown_type, line,
            "DOType " + in_quotes(type_id) + " of " + in_quotes(name) + " is not defined; dropped");
      return std::nullopt;
    }
    if (std::find(active.begin(), active.end(), type_id) != active.end()) {
      error(code::circular_type, line, "DOType " + in_quotes(type_id) + " contains itself; dropped");
      return std::nullopt;
    }
    if (depth > opts_.max_depth) {
      error(code::limit_exceeded, line, "data object nesting exceeds max_depth at " + in_quotes(name));
      return std::nullopt;
    }
    if (!take_node(line)) return std::nullopt;
    const do_type& t = *it->second;
    data_node n;
    n.kind = node_kind::data_object;
    n.name = std::string{name};
    n.desc = std::string{desc};
    n.type_id = t.id;
    n.cdc = t.cdc;
    n.count = count;

    // SDOs and DAs in declaration order.
    active.push_back(type_id);
    std::size_t si = 0;
    std::size_t ai = 0;
    while (si < t.sub_data_objects.size() || ai < t.attributes.size()) {
      const bool take_sdo =
          ai == t.attributes.size() ||
          (si < t.sub_data_objects.size() &&
           t.sub_data_objects[si].position < t.attributes[ai].position);
      if (take_sdo) {
        const auto& s = t.sub_data_objects[si++];
        if (auto c = build_do(s.name, s.desc, s.type, s.count, s.line, depth + 1, active)) {
          n.children.push_back(std::move(*c));
        }
      } else {
        const auto& a = t.attributes[ai++];
        std::vector<std::string_view> active_da;
        if (auto c = build_attribute(a, a.fc, {}, depth + 1, active_da)) {
          n.children.push_back(std::move(*c));
        }
      }
      if (overflow_) break;
    }
    active.pop_back();
    return n;
  }

  std::optional<data_node> build_attribute(const attribute_def& a,
                                           std::optional<functional_constraint> fc,
                                           model::trigger_conditions inherited,
                                           std::size_t depth,
                                           std::vector<std::string_view>& active) {
    const auto info = parse_btype(a.btype);
    if (!info) {
      error(code::unknown_btype, a.line,
            "unknown bType " + in_quotes(a.btype) + " of " + in_quotes(a.name) + "; dropped");
      return std::nullopt;
    }
    if (depth > opts_.max_depth) {
      error(code::limit_exceeded, a.line, "attribute nesting exceeds max_depth at " + in_quotes(a.name));
      return std::nullopt;
    }
    if (!fc) {
      error(code::missing_attribute, a.line, "attribute " + in_quotes(a.name) + " without fc; dropped");
      return std::nullopt;
    }
    data_node n;
    n.kind = node_kind::data_attribute;
    n.name = a.name;
    n.desc = a.desc;
    n.count = a.count;
    n.fc = fc;
    n.btype = a.btype;
    n.type = info->type;
    n.size = info->size;
    n.kind_of_value = a.kind;
    n.s_addr = a.s_addr;
    n.triggers = inherited;
    using model::trigger;
    if (a.dchg) n.triggers.set(trigger::data_change);
    if (a.qchg) n.triggers.set(trigger::quality_change);
    if (a.dupd) n.triggers.set(trigger::data_update);

    const enum_type* enumeration = nullptr;
    if (info->is_struct) {
      const auto it = da_types_.find(a.type);
      if (it == da_types_.end()) {
        error(code::unknown_type, a.line,
              "DAType " + in_quotes(a.type) + " of " + in_quotes(a.name) + " is not defined; dropped");
        return std::nullopt;
      }
      if (std::find(active.begin(), active.end(), std::string_view{a.type}) != active.end()) {
        error(code::circular_type, a.line,
              "DAType " + in_quotes(a.type) + " contains itself; dropped");
        return std::nullopt;
      }
      if (!take_node(a.line)) return std::nullopt;
      n.type_id = a.type;
      active.push_back(a.type);
      for (const auto& b : it->second->attributes) {
        if (auto c = build_attribute(b, fc, n.triggers, depth + 1, active)) {
          n.children.push_back(std::move(*c));
        }
        if (overflow_) break;
      }
      active.pop_back();
      return n;
    }
    if (info->type == model::basic_type::enumerated) {
      const auto it = enum_types_.find(a.type);
      if (it == enum_types_.end()) {
        error(code::unknown_type, a.line,
              "EnumType " + in_quotes(a.type) + " of " + in_quotes(a.name) + " is not defined; dropped");
        return std::nullopt;
      }
      enumeration = it->second;
      n.type_id = a.type;
      used_enums_.insert(enumeration->id);
    }
    if (!take_node(a.line)) return std::nullopt;
    for (const auto& v : a.values) {
      initial_value iv{v.text, {}, v.sgroup, std::nullopt, {}};
      if (n.type) {
        if (auto p = parse_value(*n.type, v.text, enumeration)) iv.parsed = std::move(*p);
      }
      n.values.push_back(std::move(iv));
    }
    return n;
  }

  // `index`: the element of the enclosing array attribute; `objects`: those of the enclosing arrays
  // of data objects (see initial_value).
  void apply_instance(data_node& node, const data_instance& inst, const std::string& path,
                      std::optional<std::uint32_t> index, const object_path& objects,
                      std::size_t depth) {
    if (depth > opts_.max_depth) return;
    for (const auto& sdi : inst.sub_instances) {
      auto* child = find_child(node, sdi.name);
      const auto child_path = path + "." + sdi.name;
      if (child == nullptr || (child->kind == node_kind::data_attribute && child->children.empty())) {
        warning(code::unresolved_reference, sdi.line,
                "SDI " + in_quotes(child_path) + " does not name a sub-data object or structure");
        continue;
      }
      if (!sdi.s_addr.empty()) child->s_addr = sdi.s_addr;
      if (!sdi.desc.empty()) child->desc = sdi.desc;
      if (sdi.ix && *sdi.ix >= child->count) {
        warning(code::unresolved_reference, sdi.line,
                "SDI " + in_quotes(child_path) + " index " + std::to_string(*sdi.ix) +
                    " is outside the array");
        continue;
      }
      if (child->kind == node_kind::data_object) {
        auto inner = objects;
        if (child->count > 0) inner.push_back(sdi.ix);
        apply_instance(*child, sdi, child_path, index, inner, depth + 1);
      } else {
        apply_instance(*child, sdi, child_path, sdi.ix ? sdi.ix : index, objects, depth + 1);
      }
    }
    for (const auto& dai : inst.attributes) {
      auto* child = find_child(node, dai.name);
      const auto child_path = path + "." + dai.name;
      if (child == nullptr || child->kind != node_kind::data_attribute) {
        warning(code::unresolved_reference, dai.line,
                "DAI " + in_quotes(child_path) + " does not name a data attribute");
        continue;
      }
      if (!dai.s_addr.empty()) child->s_addr = dai.s_addr;
      if (!dai.desc.empty()) child->desc = dai.desc;
      if (dai.kind) child->kind_of_value = *dai.kind;
      if (dai.values.empty()) continue;
      if (child->is_struct()) {
        warning(code::invalid_value, dai.line,
                "DAI " + in_quotes(child_path) + " sets a value on a structure; ignored");
        continue;
      }
      if (dai.ix && *dai.ix >= child->count) {
        warning(code::unresolved_reference, dai.line,
                "DAI " + in_quotes(child_path) + " index " + std::to_string(*dai.ix) +
                    " is outside the array");
        continue;
      }
      const auto idx = dai.ix ? dai.ix : index;
      const enum_type* enumeration = nullptr;
      if (child->type == model::basic_type::enumerated) {
        const auto it = enum_types_.find(child->type_id);
        if (it != enum_types_.end()) enumeration = it->second;
      }
      auto selected = objects;  // without trailing "every element"
      while (!selected.empty() && !selected.back()) selected.pop_back();
      std::erase_if(child->values, [&](const initial_value& v) {
        return v.index == idx && v.objects == selected;
      });
      for (const auto& v : dai.values) {
        initial_value iv{v.text, {}, v.sgroup, idx, selected};
        if (child->type) {
          if (auto p = parse_value(*child->type, v.text, enumeration)) {
            iv.parsed = std::move(*p);
          } else {
            warning(code::invalid_value, dai.line,
                    "Val " + in_quotes(v.text) + " of DAI " + in_quotes(child_path) +
                        " is not a valid " + child->btype);
          }
        }
        child->values.push_back(std::move(iv));
      }
    }
  }

  const document& doc_;
  const ied& ied_;
  diagnostics* diags_;
  const instantiate_options& opts_;
  std::unordered_map<std::string_view, const lnode_type*> lnode_types_;
  std::unordered_map<std::string_view, const do_type*> do_types_;
  std::unordered_map<std::string_view, const da_type*> da_types_;
  std::unordered_map<std::string_view, const enum_type*> enum_types_;
  std::set<std::string_view> used_enums_;
  std::size_t nodes_ = 0;
  bool overflow_ = false;
  bool errors_ = false;
};

const data_node* find_in(const std::vector<data_node>& nodes, std::string_view name) noexcept {
  const auto it = std::find_if(nodes.begin(), nodes.end(),
                               [&](const data_node& n) { return n.name == name; });
  return it == nodes.end() ? nullptr : &*it;
}

std::size_t count_nodes(const std::vector<data_node>& nodes) noexcept {
  std::size_t n = nodes.size();
  for (const auto& c : nodes) n += count_nodes(c.children);
  return n;
}

}  // namespace

const data_node* data_node::child(std::string_view n) const noexcept {
  return find_in(children, n);
}

bool data_node::has_fc(model::functional_constraint f) const noexcept {
  if (kind == node_kind::data_attribute) return fc == f;
  return std::any_of(children.begin(), children.end(),
                     [&](const data_node& c) { return c.has_fc(f); });
}

const data_node* instantiated_ln::find(std::string_view do_name) const noexcept {
  return find_in(data_objects, do_name);
}

const resolved_data_set* instantiated_ln::find_data_set(std::string_view n) const noexcept {
  const auto it = std::find_if(data_sets.begin(), data_sets.end(),
                               [&](const resolved_data_set& d) { return d.name == n; });
  return it == data_sets.end() ? nullptr : &*it;
}

const instantiated_ln* instantiated_ld::find(std::string_view ln_name) const noexcept {
  const auto it = std::find_if(lns.begin(), lns.end(),
                               [&](const instantiated_ln& l) { return l.name == ln_name; });
  return it == lns.end() ? nullptr : &*it;
}

const instantiated_ld* instantiated_ied::find(std::string_view ld_name) const noexcept {
  const auto it = std::find_if(lds.begin(), lds.end(),
                               [&](const instantiated_ld& l) { return l.name == ld_name; });
  return it == lds.end() ? nullptr : &*it;
}

const enum_type* instantiated_ied::find_enum_type(std::string_view id) const noexcept {
  const auto it = std::find_if(enum_types.begin(), enum_types.end(),
                               [&](const enum_type& e) { return e.id == id; });
  return it == enum_types.end() ? nullptr : &*it;
}

const data_node* instantiated_ied::find(const model::object_reference& ref) const noexcept {
  const auto* ld = find(ref.ld());
  if (ld == nullptr || !ref.has_ln()) return nullptr;
  const auto* ln = ld->find(ref.ln());
  if (ln == nullptr) return nullptr;
  const data_node* node = nullptr;
  for (const auto e : ref.path()) {
    node = node == nullptr ? ln->find(e.name) : node->child(e.name);
    if (node == nullptr) return nullptr;
    if (e.index && *e.index >= node->count) return nullptr;
  }
  if (node == nullptr) return nullptr;
  if (const auto f = ref.fc(); f && !node->has_fc(*f)) return nullptr;
  return node;
}

std::size_t instantiated_ied::node_count() const noexcept {
  std::size_t n = 0;
  for (const auto& ld : lds) {
    for (const auto& ln : ld.lns) n += count_nodes(ln.data_objects);
  }
  return n;
}

result<model::object_reference> make_fcda_reference(std::string_view ld_name, const fcda& member,
                                                    const model::parse_options& opts) {
  if (!member.fc || member.do_name.empty()) return errc::malformed_encoding;
  std::string text{ld_name};
  text += '/';
  text += member.prefix;
  text += member.ln_class;
  text += member.ln_inst;
  text += '.';
  text += member.do_name;
  if (!member.da_name.empty()) {
    text += '.';
    text += member.da_name;
  }
  if (member.ix) {
    text += '(';
    text += std::to_string(*member.ix);
    text += ')';
  }
  text += '[';
  text += model::to_string(*member.fc);
  text += ']';
  auto ref = model::object_reference::parse(text, opts);
  if (!ref) return ref.error();
  if (!ref->fc()) return errc::malformed_encoding;
  return ref;
}

result<model::object_reference> resolve_fcda(const document& doc, std::string_view ied_name,
                                             const fcda& member) {
  const auto* i = doc.find_ied(ied_name);
  if (i == nullptr) return errc::invalid_state;
  for (const auto& ap : i->access_points) {
    if (!ap.srv) continue;
    if (const auto* ld = ap.srv->find_ld(member.ld_inst)) {
      return make_fcda_reference(ld->name(i->name), member, model::parse_options_for(doc.edition));
    }
  }
  return errc::invalid_state;
}

result<instantiated_ied> instantiate(const document& doc, std::string_view ied_name,
                                     std::string_view access_point, diagnostics* diags,
                                     const instantiate_options& opts) {
  const auto* i = doc.find_ied(ied_name);
  if (i == nullptr) {
    if (diags != nullptr) diags->error(code::not_found, 0, "IED " + in_quotes(ied_name) + " not found");
    return errc::invalid_state;
  }
  const struct access_point* ap = nullptr;
  if (access_point.empty()) {
    for (const auto& a : i->access_points) {
      if (a.srv || !a.server_at.empty()) {
        ap = &a;
        break;
      }
    }
  } else {
    ap = i->find_access_point(access_point);
  }
  const server* srv = ap != nullptr ? i->find_server(ap->name) : nullptr;
  if (srv == nullptr) {
    if (diags != nullptr) {
      diags->error(code::not_found, i->line,
                   "IED " + in_quotes(ied_name) + " has no server at access point " +
                       in_quotes(access_point.empty() ? std::string_view{"(any)"} : access_point));
    }
    return errc::invalid_state;
  }

  builder b{doc, *i, diags, opts};
  instantiated_ied out;
  out.name = i->name;
  out.access_point = ap->name;
  out.edition = doc.edition;
  out.lds.reserve(srv->ldevices.size());
  for (const auto& ld : srv->ldevices) {
    out.lds.push_back(b.build_ld(ld));
    if (b.failed()) return errc::length_overflow;
  }
  b.resolve_data_sets(out, *srv);
  b.collect_enums(out);
  if (opts.strict && b.had_errors()) return errc::malformed_encoding;
  return out;
}

}  // namespace openiec61850::scl
