#include "validate.hpp"

#include <set>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "openiec61850/model/object_reference.hpp"
#include "openiec61850/scl/btype.hpp"

namespace openiec61850::scl::detail {
namespace {

using code = diagnostic_code;

template <typename T>
using index = std::unordered_map<std::string_view, const T*>;

std::string in_quotes(std::string_view s) {
  std::string out{"'"};
  out += s;
  out += '\'';
  return out;
}

class checker {
 public:
  checker(const document& doc, diagnostics& d) : doc_(doc), d_(d) {}

  void run() {
    index_templates();
    check_templates();
    check_cycles();
    check_ieds();
    check_communication();
  }

 private:
  template <typename T>
  void index_types(const std::vector<T>& types, index<T>& out, std::string_view what) {
    for (const auto& t : types) {
      if (!out.emplace(t.id, &t).second) {
        d_.error(code::duplicate_name, t.line,
                 std::string{what} + " id " + in_quotes(t.id) + " is defined more than once");
      }
    }
  }

  void index_templates() {
    const auto& t = doc_.templates;
    index_types(t.lnode_types, lnode_types_, "LNodeType");
    index_types(t.do_types, do_types_, "DOType");
    index_types(t.da_types, da_types_, "DAType");
    index_types(t.enum_types, enum_types_, "EnumType");
  }

  // Names of the children of one type must be unique.
  class unique_names {
   public:
    unique_names(diagnostics& d, std::string owner) : d_(d), owner_(std::move(owner)) {}
    void add(std::string_view name, std::uint32_t line) {
      if (!seen_.emplace(name).second) {
        d_.error(code::duplicate_name, line,
                 in_quotes(name) + " is defined more than once in " + owner_);
      }
    }

   private:
    diagnostics& d_;
    std::string owner_;
    std::set<std::string, std::less<>> seen_;
  };

  void check_name(std::string_view name, std::uint32_t line, std::string_view owner) {
    if (!model::is_identifier(name)) {
      d_.warning(code::invalid_name, line,
                 in_quotes(name) + " in " + std::string{owner} + " is not a valid name");
    }
  }

  void check_attribute(const attribute_def& a, const std::string& owner) {
    check_name(a.name, a.line, owner);
    const auto info = parse_btype(a.btype);
    if (!info) {
      d_.error(code::unknown_btype, a.line,
               "unknown bType " + in_quotes(a.btype) + " of " + in_quotes(a.name) + " in " + owner);
      return;
    }
    const enum_type* enumeration = nullptr;
    if (info->is_struct) {
      if (a.type.empty()) {
        d_.error(code::type_mismatch, a.line,
                 "Struct attribute " + in_quotes(a.name) + " in " + owner + " without type");
      } else if (!da_types_.contains(a.type)) {
        d_.error(code::unknown_type, a.line,
                 "DAType " + in_quotes(a.type) + " of " + in_quotes(a.name) + " in " + owner +
                     " is not defined");
      }
    } else if (info->type == model::basic_type::enumerated) {
      if (a.type.empty()) {
        d_.error(code::type_mismatch, a.line,
                 "Enum attribute " + in_quotes(a.name) + " in " + owner + " without type");
      } else if (const auto it = enum_types_.find(a.type); it == enum_types_.end()) {
        d_.error(code::unknown_type, a.line,
                 "EnumType " + in_quotes(a.type) + " of " + in_quotes(a.name) + " in " + owner +
                     " is not defined");
      } else {
        enumeration = it->second;
      }
    }
    if (info->is_struct && !a.values.empty()) {
      d_.warning(code::invalid_value, a.line,
                 "Val of Struct attribute " + in_quotes(a.name) + " in " + owner + " ignored");
    }
    if (!info->type) return;
    for (const auto& v : a.values) {
      if (!parse_value(*info->type, v.text, enumeration)) {
        d_.warning(code::invalid_value, a.line,
                   "Val " + in_quotes(v.text) + " of " + in_quotes(a.name) + " in " + owner +
                       " is not a valid " + a.btype);
      }
    }
  }

  void check_templates() {
    const auto& t = doc_.templates;
    for (const auto& lt : t.lnode_types) {
      const auto owner = "LNodeType " + in_quotes(lt.id);
      unique_names names{d_, owner};
      for (const auto& d : lt.data_objects) {
        names.add(d.name, d.line);
        check_name(d.name, d.line, owner);
        if (!do_types_.contains(d.type)) {
          d_.error(code::unknown_type, d.line,
                   "DOType " + in_quotes(d.type) + " of DO " + in_quotes(d.name) + " in " + owner +
                       " is not defined");
        }
      }
    }
    for (const auto& dt : t.do_types) {
      const auto owner = "DOType " + in_quotes(dt.id);
      unique_names names{d_, owner};
      for (const auto& s : dt.sub_data_objects) {
        names.add(s.name, s.line);
        check_name(s.name, s.line, owner);
        if (!do_types_.contains(s.type)) {
          d_.error(code::unknown_type, s.line,
                   "DOType " + in_quotes(s.type) + " of SDO " + in_quotes(s.name) + " in " + owner +
                       " is not defined");
        }
      }
      for (const auto& a : dt.attributes) {
        names.add(a.name, a.line);
        check_attribute(a, owner);
      }
    }
    for (const auto& dt : t.da_types) {
      const auto owner = "DAType " + in_quotes(dt.id);
      unique_names names{d_, owner};
      for (const auto& a : dt.attributes) {
        names.add(a.name, a.line);
        check_attribute(a, owner);
      }
    }
    for (const auto& et : t.enum_types) {
      std::set<std::int32_t> ords;
      std::set<std::string_view> texts;
      for (const auto& v : et.values) {
        if (!ords.insert(v.ord).second) {
          d_.error(code::duplicate_name, et.line,
                   "EnumType " + in_quotes(et.id) + " defines ord " + std::to_string(v.ord) + " twice");
        }
        if (!v.text.empty() && !texts.insert(v.text).second) {
          d_.warning(code::duplicate_name, et.line,
                     "EnumType " + in_quotes(et.id) + " defines " + in_quotes(v.text) + " twice");
        }
      }
    }
  }

  // Iterative DFS over a type graph; reports each back edge once.
  template <typename T, typename Edges>
  void find_cycles(const std::vector<T>& types, const index<T>& by_id, std::string_view what,
                   Edges edges) {
    enum class state : std::uint8_t { fresh, active, done };
    std::unordered_map<const T*, state> st;
    struct frame {
      const T* type;
      std::vector<std::string_view> next;
      std::size_t pos = 0;
    };
    for (const auto& root : types) {
      if (st[&root] != state::fresh) continue;
      std::vector<frame> stack;
      stack.push_back({&root, edges(root)});
      st[&root] = state::active;
      while (!stack.empty()) {
        auto& f = stack.back();
        if (f.pos == f.next.size()) {
          st[f.type] = state::done;
          stack.pop_back();
          continue;
        }
        const auto id = f.next[f.pos++];
        const auto it = by_id.find(id);
        if (it == by_id.end()) continue;
        const T* child = it->second;
        auto& cs = st[child];
        if (cs == state::active) {
          d_.error(code::circular_type, f.type->line,
                   std::string{what} + " " + in_quotes(f.type->id) + " contains " + in_quotes(child->id) +
                       ", which contains it (circular type)");
        } else if (cs == state::fresh) {
          cs = state::active;
          auto next = edges(*child);
          stack.push_back({child, std::move(next)});
        }
      }
    }
  }

  void check_cycles() {
    const auto& t = doc_.templates;
    find_cycles(t.do_types, do_types_, "DOType", [](const do_type& dt) {
      std::vector<std::string_view> out;
      for (const auto& s : dt.sub_data_objects) out.push_back(s.type);
      return out;
    });
    find_cycles(t.da_types, da_types_, "DAType", [](const da_type& dt) {
      std::vector<std::string_view> out;
      for (const auto& a : dt.attributes) {
        if (a.btype == "Struct") out.push_back(a.type);
      }
      return out;
    });
  }

  template <typename Range>
  void unique_control_names(const Range& r, const std::string& owner) {
    unique_names names{d_, owner};
    for (const auto& x : r) names.add(x.name, x.line);
  }

  template <typename Range>
  void check_dat_set(const logical_node& ln, const Range& blocks, const std::string& owner) {
    for (const auto& cb : blocks) {
      if (!cb.dat_set.empty() && ln.find_data_set(cb.dat_set) == nullptr) {
        d_.error(code::unresolved_reference, cb.line,
                 "control block " + in_quotes(cb.name) + " in " + owner + " references data set " +
                     in_quotes(cb.dat_set) + ", which is not defined in that LN");
      }
    }
  }

  void check_ln(const logical_node& ln, const std::string& ld_owner) {
    const auto owner = "LN " + in_quotes(ln.name()) + " of " + ld_owner;
    if (!ln.ln_type.empty()) {
      const auto it = lnode_types_.find(ln.ln_type);
      if (it == lnode_types_.end()) {
        d_.error(code::unknown_type, ln.line,
                 "LNodeType " + in_quotes(ln.ln_type) + " of " + owner + " is not defined");
      } else if (it->second->ln_class != ln.ln_class) {
        d_.warning(code::type_mismatch, ln.line,
                   owner + " has lnClass " + in_quotes(ln.ln_class) + " but LNodeType " +
                       in_quotes(ln.ln_type) + " is for " + in_quotes(it->second->ln_class));
      }
    }
    unique_control_names(ln.data_sets, owner);
    unique_control_names(ln.report_controls, owner);
    unique_control_names(ln.log_controls, owner);
    unique_control_names(ln.gse_controls, owner);
    unique_control_names(ln.smv_controls, owner);
    check_dat_set(ln, ln.report_controls, owner);
    check_dat_set(ln, ln.log_controls, owner);
    check_dat_set(ln, ln.gse_controls, owner);
    check_dat_set(ln, ln.smv_controls, owner);
  }

  void check_ieds() {
    unique_names ied_names{d_, "the SCL file"};
    const auto limits = model::name_limits::for_edition(doc_.edition);
    for (const auto& i : doc_.ieds) {
      ied_names.add(i.name, i.line);
      const auto ied_owner = "IED " + in_quotes(i.name);
      unique_names ap_names{d_, ied_owner};
      for (const auto& ap : i.access_points) {
        ap_names.add(ap.name, ap.line);
        if (!ap.server_at.empty()) {
          const auto* target = i.find_access_point(ap.server_at);
          if (target == nullptr) {
            d_.error(code::unresolved_reference, ap.line,
                     "ServerAt of access point " + in_quotes(ap.name) + " names unknown access point " +
                         in_quotes(ap.server_at));
          } else if (!target->srv) {
            d_.warning(code::unresolved_reference, ap.line,
                       "ServerAt of access point " + in_quotes(ap.name) + " names access point " +
                           in_quotes(ap.server_at) + ", which has no Server");
          }
        }
        if (!ap.srv) continue;
        const auto ap_owner = "access point " + in_quotes(ap.name) + " of " + ied_owner;
        unique_names ld_names{d_, ap_owner};
        for (const auto& ld : ap.srv->ldevices) {
          ld_names.add(ld.inst, ld.line);
          const auto ld_name = ld.name(i.name);
          if (!model::is_identifier(ld_name)) {
            d_.warning(code::invalid_name, ld.line, "LD name " + in_quotes(ld_name) + " is not valid");
          } else if (ld_name.size() > limits.max_ld_name) {
            d_.warning(code::invalid_name, ld.line,
                       "LD name " + in_quotes(ld_name) + " is longer than the edition allows");
          }
          const auto ld_owner = "LD " + in_quotes(ld_name);
          unique_names ln_names{d_, ld_owner};
          ln_names.add(ld.ln0.name(), ld.ln0.line);
          check_ln(ld.ln0, ld_owner);
          for (const auto& ln : ld.lns) {
            ln_names.add(ln.name(), ln.line);
            check_ln(ln, ld_owner);
          }
        }
      }
    }
  }

  void check_communication() {
    std::set<std::pair<std::string_view, std::string_view>> seen;
    for (const auto& sn : doc_.comm.sub_networks) {
      for (const auto& cap : sn.connected_aps) {
        if (!seen.emplace(cap.ied_name, cap.ap_name).second) {
          d_.warning(code::duplicate_name, cap.line,
                     "ConnectedAP " + in_quotes(cap.ied_name) + "/" + in_quotes(cap.ap_name) +
                         " appears more than once");
        }
        const auto* i = doc_.find_ied(cap.ied_name);
        if (i == nullptr) {
          d_.warning(code::unresolved_reference, cap.line,
                     "ConnectedAP names unknown IED " + in_quotes(cap.ied_name));
        } else if (i->find_access_point(cap.ap_name) == nullptr) {
          d_.warning(code::unresolved_reference, cap.line,
                     "ConnectedAP names unknown access point " + in_quotes(cap.ap_name) + " of IED " +
                         in_quotes(cap.ied_name));
        }
      }
    }
  }

  const document& doc_;
  diagnostics& d_;
  index<lnode_type> lnode_types_;
  index<do_type> do_types_;
  index<da_type> da_types_;
  index<enum_type> enum_types_;
};

}  // namespace

void validate(const document& doc, diagnostics& diags) { checker{doc, diags}.run(); }

}  // namespace openiec61850::scl::detail
