// Server data model from SCL (see openiec61850/server/scl_model.hpp).

#include "openiec61850/server/scl_model.hpp"

#include <algorithm>
#include <cstdio>
#include <map>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include "openiec61850/scl/address.hpp"
#include "values.hpp"

namespace openiec61850::server {

namespace {

using model::basic_type;
using model::fc;
using scl::diagnostic_code;

bool is_unsigned(basic_type t) noexcept {
  switch (t) {
    case basic_type::int8u:
    case basic_type::int16u:
    case basic_type::int24u:
    case basic_type::int32u:
      return true;
    default:
      return false;
  }
}

// A data attribute the builder can represent: a basic type, or a structure with at least one
// such component.
bool mappable(const scl::data_node& n) {
  if (n.is_data_object()) return false;
  if (n.type) return true;
  return std::any_of(n.children.begin(), n.children.end(),
                     [](const scl::data_node& c) { return mappable(c); });
}

class loader {
 public:
  loader(const scl::instantiated_ied& ied, const scl_load_options& opts, scl::diagnostics* diags,
         const scl::connected_ap* ap = nullptr)
      : ied_(ied), opts_(opts), diags_(diags), ap_(ap), b_(ied.edition) {}

  result<data_model> run() {
    sg_ = opts_.setting_group;
    if (sg_ == 0) {
      sg_ = 1;
      for (const auto& ld : ied_.lds) {
        for (const auto& ln : ld.lns) {
          if (ln.setting && ln.setting->act_sg > 0) {
            sg_ = ln.setting->act_sg;
            break;
          }
        }
      }
    }
    for (const auto& ld : ied_.lds) {
      auto ldh = b_.logical_device(ld.name);
      for (const auto& ln : ld.lns) {
        auto lnh = ldh.logical_node(ln.name);
        const std::string ln_ref = ld.name + "/" + ln.name;
        ln_ids_[ln_ref] = lnh.id();
        for (const auto& d : ln.data_objects) {
          const auto ref = ln_ref + "." + d.name;
          // Decided per top-level DO: every element of an array must keep the same type.
          nodes_ += expanded_size(d);
          if (nodes_ > opts_.instantiate.max_nodes) {
            nodes_ -= expanded_size(d);
            skipped_.push_back(ref);
            note(diagnostic_code::limit_exceeded, ref + " skipped: its arrays exceed max_nodes");
            continue;
          }
          add_data(lnh.data_object(d.name, d.count), d, ref, 0);
        }
      }
    }
    // Data sets and control blocks once every object exists (members may be in other LDs).
    for (const auto& ld : ied_.lds) {
      for (const auto& ln : ld.lns) {
        const std::string ln_ref = ld.name + "/" + ln.name;
        auto lnh = b_.logical_node_handle(find_ln(ln_ref));
        std::vector<std::string> data_sets;
        for (const auto& ds : ln.data_sets) {
          std::vector<model::object_reference> members;
          for (const auto& m : ds.members) {
            if (refers_to_skipped(m) || !addressable(m)) {
              note(diagnostic_code::unresolved_reference,
                   "member " + std::string(m.text()) + " of data set " + ln_ref + "." + ds.name +
                       " refers to an attribute that was not mapped; dropped");
              continue;
            }
            members.push_back(m);
          }
          if (members.empty()) {
            note(diagnostic_code::unresolved_reference,
                 "data set " + ln_ref + "." + ds.name + " has no members; dropped");
            continue;
          }
          lnh.data_set(ds.name, std::move(members));
          data_sets.push_back(ds.name);
        }
        for (const auto& rc : ln.report_controls) add_report_control(lnh, ln_ref, rc, data_sets);
        if (ln.setting) {
          setting_group_settings sg;
          sg.num_of_sgs = static_cast<std::uint8_t>(std::clamp<std::uint32_t>(ln.setting->num_of_sgs, 1, 255));
          sg.act_sg = static_cast<std::uint8_t>(std::clamp<std::uint32_t>(ln.setting->act_sg, 1, sg.num_of_sgs));
          lnh.setting_group_control(sg);
        }
        for (const auto& lc : ln.log_controls) add_log_control(ld, lnh, ln_ref, lc, data_sets);
        for (const auto& gc : ln.gse_controls) add_goose_control(ld, lnh, ln_ref, gc, data_sets);
      }
    }
    for (const auto& [key, name] : logs_) b_.logical_node_handle(key).log(name);
    if (failed_) return make_error_code(errc::invalid_model);
    return b_.build();
  }

 private:
  node_id find_ln(const std::string& ln_ref) const {
    const auto it = ln_ids_.find(ln_ref);
    return it == ln_ids_.end() ? no_node : it->second;
  }

  void note(diagnostic_code code, std::string message) {
    if (opts_.strict) failed_ = true;
    if (diags_ == nullptr) return;
    message.insert(0, "server model: ");
    if (opts_.strict) {
      diags_->error(code, 0, std::move(message));
    } else {
      diags_->warning(code, 0, std::move(message));
    }
  }

  void skip(const std::string& ref, std::string_view why) {
    skipped_.push_back(ref);
    note(diagnostic_code::type_mismatch, ref + " skipped: " + std::string(why));
  }

  bool refers_to_skipped(const model::object_reference& m) const {
    const std::string text(m.with_fc(std::nullopt).text());
    return std::any_of(skipped_.begin(), skipped_.end(), [&](const std::string& s) {
      return text.starts_with(s) &&
             (text.size() == s.size() || text[s.size()] == '.' || text[s.size()] == '(');
    });
  }

  // Whether a data set member reaches past an array of data objects only through an element.
  bool addressable(const model::object_reference& m) const {
    const auto* ld = ied_.find(m.ld());
    const auto* ln = ld != nullptr ? ld->find(m.ln()) : nullptr;
    if (ln == nullptr) return false;
    const scl::data_node* node = nullptr;
    bool indexed = false;
    for (const auto e : m.path()) {
      if (node != nullptr && node->is_data_object() && node->count > 0 && !indexed) return false;
      node = node == nullptr ? ln->find(e.name) : node->child(e.name);
      if (node == nullptr) return false;
      indexed = e.index.has_value();
    }
    return true;
  }

  // The nodes a data object takes in the model: an array of objects has one subtree per element.
  static std::uint64_t expanded_size(const scl::data_node& n) {
    constexpr std::uint64_t cap = std::uint64_t{1} << 31;
    std::uint64_t size = 1;
    for (const auto& c : n.children) size = std::min(size + expanded_size(c), cap);
    if (n.is_data_object() && n.count > 0) size = std::min(size * n.count + 1, cap);
    return size;
  }

  // Keeps the values of `n` and below that apply to element `e` of the array of objects at
  // nesting `level`.
  static void narrow(scl::data_node& n, std::size_t level, std::uint32_t e) {
    std::erase_if(n.values, [&](const scl::initial_value& v) {
      return level < v.objects.size() && v.objects[level] && *v.objects[level] != e;
    });
    for (auto& c : n.children) narrow(c, level, e);
  }

  // A DO or SDO; `level`: the arrays of objects it is nested in.
  void add_data(do_handle h, const scl::data_node& d, const std::string& ref, std::size_t level) {
    if (d.count == 0) {
      add_object(h, d, ref, level);
      return;
    }
    for (std::uint32_t e = 0; e < d.count; ++e) {
      auto element = d;
      narrow(element, level, e);
      add_object(h.element(e), element, ref + "(" + std::to_string(e) + ")", level + 1);
    }
  }

  void add_object(do_handle h, const scl::data_node& d, const std::string& ref, std::size_t level) {
    for (const auto& c : d.children) {
      const auto child_ref = ref + "." + c.name;
      if (c.is_data_object()) {
        add_data(h.sub_object(c.name, c.count), c, child_ref, level);
        continue;
      }
      if (!mappable(c)) {
        skip(child_ref, "bType " + c.btype + " has no basic type");
        continue;
      }
      auto options = options_for(c, child_ref);
      if (c.type) {
        auto da = h.attribute(c.name, *c.fc, *c.type, std::move(options));
        add_groups(da, c, child_ref);
      } else {
        add_components(h.structure(c.name, *c.fc, std::move(options)), c, child_ref, c.count > 0);
      }
    }
  }

  void add_components(da_handle h, const scl::data_node& d, const std::string& ref, bool in_array) {
    for (const auto& c : d.children) {
      const auto child_ref = ref + "." + c.name;
      if (!mappable(c)) {
        skip(child_ref, "bType " + c.btype + " has no basic type");
        continue;
      }
      attribute_options options;
      if (in_array) {
        // Template of an array element: the value lives in the array attribute.
        options.size = static_cast<std::int32_t>(c.size);
        options.count = c.count;
        options.triggers = triggers_of(c);
      } else {
        options = options_for(c, child_ref);
      }
      if (c.type) {
        auto da = h.attribute(c.name, *c.type, std::move(options));
        if (!in_array) add_groups(da, c, child_ref);
      } else {
        add_components(h.structure(c.name, std::move(options)), c, child_ref, in_array || c.count > 0);
      }
    }
  }

  static trigger_options triggers_of(const scl::data_node& n) {
    return {n.triggers.data_change(), n.triggers.quality_change(),
            n.triggers.has(model::trigger::data_update)};
  }

  attribute_options options_for(const scl::data_node& n, const std::string& ref) {
    attribute_options o;
    o.triggers = triggers_of(n);
    o.size = static_cast<std::int32_t>(n.size);
    o.count = n.count;
    if (n.type || n.count > 0) {
      if (auto v = value_of(n, ref)) o.value = std::move(*v);
    }
    return o;
  }

  // ---- values

  result<mms::type_description> type_of(const scl::data_node& n, bool with_count) const {
    mms::type_description element;
    if (n.type) {
      auto t = model::to_mms_type(*n.type, static_cast<std::int32_t>(n.size), ied_.edition);
      if (!t) return t.error();
      element = std::move(*t);
    } else {
      std::vector<mms::type_component> comps;
      for (const auto& c : n.children) {
        if (!mappable(c)) continue;
        auto t = type_of(c, true);
        if (!t) return t.error();
        comps.push_back({c.name, std::move(*t)});
      }
      element = mms::type_description::structure(std::move(comps));
    }
    if (with_count && n.count > 0) return mms::type_description::array(n.count, std::move(element));
    return element;
  }

  result<mms::data> default_of(const scl::data_node& n, bool with_count) const {
    mms::data element;
    if (n.type) {
      auto d = default_value(*n.type, static_cast<std::int32_t>(n.size), 0, ied_.edition);
      if (!d) return d.error();
      element = std::move(*d);
    } else {
      std::vector<mms::data> comps;
      for (const auto& c : n.children) {
        if (!mappable(c)) continue;
        auto d = default_of(c, true);
        if (!d) return d.error();
        comps.push_back(std::move(*d));
      }
      element = mms::data::structure(std::move(comps));
    }
    if (with_count && n.count > 0) {
      std::vector<mms::data> elems(n.count, element);
      return mms::data::array(std::move(elems));
    }
    return element;
  }

  // The Val of a leaf attribute converted to its type (nullopt with a diagnostic when it cannot
  // be).
  std::optional<mms::data> convert(const scl::data_node& n, const scl::initial_value& iv,
                                   const std::string& ref) {
    const auto type = *n.type;
    std::optional<mms::data> out;
    if (type == basic_type::timestamp || type == basic_type::entry_time) {
      if (auto p = parse_value(type, iv.text)) return std::move(*p);
      note(diagnostic_code::invalid_value,
           "initial value \"" + iv.text + "\" of " + ref + " (" + n.btype + ") ignored");
      return std::nullopt;
    }
    std::visit(
        [&](const auto& v) {
          using T = std::decay_t<decltype(v)>;
          if constexpr (std::is_same_v<T, bool>) {
            if (type == basic_type::boolean) out = mms::data::boolean(v);
          } else if constexpr (std::is_same_v<T, std::int64_t>) {
            if (is_unsigned(type)) {
              if (v >= 0) out = mms::data::unsigned_integer(static_cast<std::uint64_t>(v));
            } else {
              out = mms::data::integer(v);
            }
          } else if constexpr (std::is_same_v<T, std::uint64_t>) {
            out = mms::data::unsigned_integer(v);
          } else if constexpr (std::is_same_v<T, double>) {
            out = type == basic_type::float32 ? mms::data::floating_point(static_cast<float>(v))
                                              : mms::data::floating_point(v);
          }
        },
        iv.parsed);
    if (!out && !std::holds_alternative<std::monostate>(iv.parsed)) {
      auto p = parse_value(type, iv.text, static_cast<std::int32_t>(n.size));
      if (p) out = std::move(*p);
    }
    if (out) {
      auto t = type_of(n, false);
      if (t) {
        auto c = detail::conform(*out, *t);
        if (auto* d = std::get_if<mms::data>(&c)) return std::move(*d);
      }
    }
    note(diagnostic_code::invalid_value,
         "initial value \"" + iv.text + "\" of " + ref + " (" + n.btype + ") ignored");
    return std::nullopt;
  }

  // Elements of arrays of objects a Val selects: one for a single element beats one for all.
  static std::size_t selectivity(const scl::initial_value& v) {
    return static_cast<std::size_t>(std::count_if(v.objects.begin(), v.objects.end(),
                                                  [](const auto& o) { return o.has_value(); }));
  }

  // The Val among `values` for array element `index` (nullopt: not indexed), preferring the
  // active setting group for FC SG / SE.
  const scl::initial_value* pick(const std::vector<scl::initial_value>& values,
                                 std::optional<std::uint32_t> index, bool grouped) const {
    const scl::initial_value* first = nullptr;
    const scl::initial_value* plain = nullptr;
    std::size_t best = 0;
    for (const auto& v : values) {
      if (v.index == index) best = std::max(best, selectivity(v));
    }
    for (const auto& v : values) {
      if (v.index != index || selectivity(v) != best) continue;
      if (first == nullptr) first = &v;
      if (grouped && v.sgroup == sg_) return &v;
      if (!v.sgroup && plain == nullptr) plain = &v;
    }
    return plain != nullptr ? plain : first;
  }

  static std::vector<std::optional<std::uint32_t>> indexes(const std::vector<scl::initial_value>& vs) {
    std::vector<std::optional<std::uint32_t>> out;
    for (const auto& v : vs) {
      if (std::find(out.begin(), out.end(), v.index) == out.end()) out.push_back(v.index);
    }
    // Values for the whole array first, so that element values override them.
    std::stable_sort(out.begin(), out.end(), [](const auto& a, const auto& b) {
      return !a.has_value() && b.has_value();
    });
    return out;
  }

  static mms::data* at_path(mms::data& v, const std::vector<std::size_t>& path) {
    mms::data* cur = &v;
    for (const auto i : path) {
      auto elems = cur->mutable_elements();
      if (!elems || i >= (*elems)->size()) return nullptr;
      cur = &(**elems)[i];
    }
    return cur;
  }

  // Applies the Vals of the leaves below a structured array element template.
  void apply_leaves(const scl::data_node& n, std::vector<std::size_t>& path, mms::data& array,
                    const std::string& ref, bool grouped) {
    std::size_t pos = 0;
    for (const auto& c : n.children) {
      if (!mappable(c)) continue;
      path.push_back(pos++);
      const auto child_ref = ref + "." + c.name;
      if (c.type && c.count == 0 && !c.values.empty()) {
        for (const auto& idx : indexes(c.values)) {
          const auto* iv = pick(c.values, idx, grouped);
          auto v = convert(c, *iv, child_ref);
          if (!v) continue;
          auto elems = array.mutable_elements();
          if (!elems) continue;
          for (std::size_t e = 0; e < (*elems)->size(); ++e) {
            if (idx && *idx != e) continue;
            if (auto* slot = at_path((**elems)[e], path)) *slot = *v;
          }
        }
      } else if (!c.type && c.count == 0) {
        apply_leaves(c, path, array, child_ref, grouped);
      } else if (!c.values.empty() || !c.children.empty()) {
        // Arrays inside array elements keep their defaults.
        bool any = !c.values.empty();
        if (any) {
          note(diagnostic_code::invalid_value,
               "initial values of " + child_ref + " (an array inside an array) ignored");
        }
      }
      path.pop_back();
    }
  }

  std::optional<mms::data> value_of(const scl::data_node& n, const std::string& ref) {
    const bool grouped = n.fc == fc::SG || n.fc == fc::SE;
    if (n.count == 0) {
      if (n.values.empty()) return std::nullopt;
      const auto* iv = pick(n.values, std::nullopt, grouped);
      if (iv == nullptr) iv = &n.values.front();
      return convert(n, *iv, ref);
    }
    auto value = default_of(n, true);
    if (!value) {
      note(diagnostic_code::invalid_value, "no default value for " + ref);
      return std::nullopt;
    }
    if (n.type) {
      for (const auto& idx : indexes(n.values)) {
        const auto* iv = pick(n.values, idx, grouped);
        auto v = convert(n, *iv, ref);
        if (!v) continue;
        auto elems = value->mutable_elements();
        if (!elems) continue;
        for (std::size_t e = 0; e < (*elems)->size(); ++e) {
          if (!idx || *idx == e) (**elems)[e] = *v;
        }
      }
    } else {
      std::vector<std::size_t> path;
      apply_leaves(n, path, *value, ref, grouped);
    }
    return std::move(*value);
  }

  // FC SG leaves: the Val of every setting group.
  void add_groups(da_handle& h, const scl::data_node& n, const std::string& ref) {
    if (n.fc != fc::SG || !n.type || n.count > 0) return;
    for (const auto& v : n.values) {
      if (!v.sgroup || *v.sgroup == 0 || *v.sgroup > 255 || v.index) continue;
      if (auto d = convert(n, v, ref)) h.group_value(*v.sgroup, std::move(*d));
    }
  }

  // ---- log and GOOSE control blocks

  void add_log_control(const scl::instantiated_ld& ld, ln_handle& lnh, const std::string& ln_ref,
                       const scl::log_control& lc, const std::vector<std::string>& data_sets) {
    log_control_settings s;
    s.name = lc.name;
    s.data_set = lc.dat_set;
    if (!s.data_set.empty() &&
        std::find(data_sets.begin(), data_sets.end(), s.data_set) == data_sets.end()) {
      note(diagnostic_code::unresolved_reference, "log control " + ln_ref + "." + lc.name +
                                                      ": data set " + lc.dat_set +
                                                      " is not available; none configured");
      s.data_set.clear();
    }
    s.log_ena = lc.log_ena;
    s.trg_ops = lc.trg_ops;
    s.intg_pd = lc.intg_pd;
    if (!lc.log_name.empty()) {
      const auto log_ld = std::find_if(ied_.lds.begin(), ied_.lds.end(), [&](const auto& l) {
        return l.inst == (lc.ld_inst.empty() ? ld.inst : lc.ld_inst);
      });
      if (log_ld == ied_.lds.end()) {
        note(diagnostic_code::unresolved_reference,
             "log control " + ln_ref + "." + lc.name + ": no LD " + lc.ld_inst);
      } else {
        const std::string log_ln = lc.prefix + lc.ln_class + lc.ln_inst;
        const node_id id = find_ln(log_ld->name + "/" + log_ln);
        if (id == no_node) {
          note(diagnostic_code::unresolved_reference,
               "log control " + ln_ref + "." + lc.name + ": no LN " + log_ln);
        } else {
          s.log_name = lc.log_name;
          s.log_ln = log_ln;
          if (log_ld->name != ld.name) s.log_ld = log_ld->name;
          if (std::find(logs_.begin(), logs_.end(), std::make_pair(id, lc.log_name)) == logs_.end()) {
            logs_.emplace_back(id, lc.log_name);
          }
        }
      }
    }
    lnh.log_control(std::move(s));
  }

  void add_goose_control(const scl::instantiated_ld& ld, ln_handle& lnh, const std::string& ln_ref,
                         const scl::gse_control& gc, const std::vector<std::string>& data_sets) {
    if (gc.type != "GOOSE") {
      note(diagnostic_code::type_mismatch, "GSSE control " + ln_ref + "." + gc.name + " skipped");
      return;
    }
    goose_control_settings s;
    s.name = gc.name;
    s.go_id = gc.app_id;
    s.conf_rev = gc.conf_rev;
    s.fixed_offs = gc.fixed_offs;
    s.data_set = gc.dat_set;
    if (!s.data_set.empty() &&
        std::find(data_sets.begin(), data_sets.end(), s.data_set) == data_sets.end()) {
      note(diagnostic_code::unresolved_reference, "GOOSE control " + ln_ref + "." + gc.name +
                                                      ": data set " + gc.dat_set +
                                                      " is not available; none configured");
      s.data_set.clear();
    }
    if (ap_ != nullptr) {
      for (const auto& g : ap_->gse) {
        if (g.ld_inst != ld.inst || g.cb_name != gc.name) continue;
        if (auto a = scl::parse_l2_address(g.addr)) {
          s.dst_mac = a->mac;
          s.app_id = a->app_id;
          s.vlan_id = a->vlan_id;
          s.vlan_priority = a->vlan_priority;
        } else {
          note(diagnostic_code::invalid_value,
               "GSE address of " + ln_ref + "." + gc.name + " is invalid; defaults used");
        }
        s.min_time = g.min_time.value_or(0);
        s.max_time = g.max_time.value_or(0);
        break;
      }
    }
    lnh.goose_control(std::move(s));
  }

  // ---- report control blocks

  void add_report_control(ln_handle& lnh, const std::string& ln_ref, const scl::report_control& rc,
                          const std::vector<std::string>& data_sets) {
    report_control_settings s;
    s.buffered = rc.buffered;
    s.rpt_id = rc.rpt_id;
    s.data_set = rc.dat_set;
    if (!s.data_set.empty() &&
        std::find(data_sets.begin(), data_sets.end(), s.data_set) == data_sets.end()) {
      note(diagnostic_code::unresolved_reference, "report control " + ln_ref + "." + rc.name +
                                                      ": data set " + rc.dat_set +
                                                      " is not available; none configured");
      s.data_set.clear();
    }
    s.conf_rev = rc.conf_rev;
    s.opt_flds = rc.opt_fields;
    s.buf_tm = rc.buf_time;
    s.trg_ops = rc.trg_ops;
    s.intg_pd = rc.intg_pd;
    if (!rc.indexed) {
      s.name = rc.name;
      lnh.report_control(std::move(s));
      return;
    }
    auto count = std::max<std::uint32_t>(rc.rpt_enabled_max, 1);
    const auto limit = std::min<std::uint32_t>(std::max<std::uint32_t>(opts_.max_report_instances, 1), 99);
    if (count > limit) {
      note(diagnostic_code::limit_exceeded, "report control " + ln_ref + "." + rc.name + ": " +
                                                std::to_string(count) + " instances limited to " +
                                                std::to_string(limit));
      count = limit;
    }
    for (std::uint32_t i = 1; i <= count; ++i) {
      char suffix[4];
      std::snprintf(suffix, sizeof suffix, "%02u", static_cast<unsigned>(i));
      auto inst = s;
      inst.name = rc.name + suffix;
      lnh.report_control(std::move(inst));
    }
  }

  const scl::instantiated_ied& ied_;
  const scl_load_options& opts_;
  scl::diagnostics* diags_;
  const scl::connected_ap* ap_;
  model_builder b_;
  std::vector<std::pair<node_id, std::string>> logs_;
  std::uint32_t sg_ = 1;
  std::vector<std::string> skipped_;
  std::uint64_t nodes_ = 0;
  std::map<std::string, node_id, std::less<>> ln_ids_;
  bool failed_ = false;
};

}  // namespace

result<data_model> load_model(const scl::document& doc, std::string_view ied,
                              std::string_view access_point, const scl_load_options& options,
                              scl::diagnostics* diags) {
  std::string name(ied);
  if (name.empty()) {
    if (doc.ieds.empty()) return openiec61850::errc::invalid_state;
    name = doc.ieds.front().name;
  }
  auto inst = scl::instantiate(doc, name, access_point, diags, options.instantiate);
  if (!inst) return inst.error();
  loader l(*inst, options, diags, doc.comm.find(inst->name, inst->access_point));
  return l.run();
}

result<data_model> load_model_file(const std::filesystem::path& path, std::string_view ied,
                                   std::string_view access_point, const scl_load_options& options,
                                   scl::diagnostics* diags) {
  auto r = scl::load_file(path, options.load);
  if (diags != nullptr) diags->merge(r.diags);
  if (!r.doc) return r.doc.error();
  return load_model(*r.doc, ied, access_point, options, diags);
}

}  // namespace openiec61850::server
