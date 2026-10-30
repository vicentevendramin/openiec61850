#include "openiec61850/scl/load.hpp"

#include <fstream>
#include <string>
#include <system_error>

#include <pugixml.hpp>

#include "openiec61850/model/object_reference.hpp"
#include "text.hpp"
#include "validate.hpp"
#include "xml.hpp"

// IEC 61850-6 (Ed.1 §9, Ed.2 §8/§9): element and attribute names of the SCL schema.

namespace openiec61850::scl {
namespace {

using detail::ns_scope;
using pugi::xml_node;

class parser {
 public:
  parser(std::string_view text, const load_options& opts, diagnostics& diags)
      : lines_(text), opts_(opts), diags_(diags) {}

  void parse(xml_node root, const ns_scope& scope, document& doc);

 private:
  [[nodiscard]] std::uint32_t line(xml_node n) const noexcept {
    return lines_.line_of(n.offset_debug());
  }
  void error(xml_node n, diagnostic_code c, std::string msg) {
    diags_.error(c, line(n), std::move(msg));
  }
  void warning(xml_node n, diagnostic_code c, std::string msg) {
    diags_.warning(c, line(n), std::move(msg));
  }

  // Attribute value (trimmed); empty when absent.
  [[nodiscard]] static std::string attr(xml_node n, const char* name) {
    return std::string{detail::trim(n.attribute(name).value())};
  }
  [[nodiscard]] static bool has_attr(xml_node n, const char* name) {
    return static_cast<bool>(n.attribute(name));
  }
  // Required attribute; reports missing_attribute when absent or empty.
  std::string required(xml_node n, const char* name) {
    auto v = attr(n, name);
    if (v.empty()) {
      error(n, diagnostic_code::missing_attribute,
            std::string{detail::local_name(n)} + " without attribute '" + name + "'");
    }
    return v;
  }
  template <typename T>
  T number(xml_node n, const char* name, T fallback) {
    const auto a = n.attribute(name);
    if (!a) return fallback;
    if (const auto v = detail::parse_integer<T>(a.value())) return *v;
    error(n, diagnostic_code::invalid_attribute,
          std::string{detail::local_name(n)} + " attribute '" + name + "' is not a valid number: '" +
              a.value() + "'");
    return fallback;
  }
  template <typename T>
  std::optional<T> optional_number(xml_node n, const char* name) {
    if (!has_attr(n, name)) return std::nullopt;
    return number<T>(n, name, T{});
  }
  bool boolean(xml_node n, const char* name, bool fallback) {
    const auto a = n.attribute(name);
    if (!a) return fallback;
    if (const auto v = detail::parse_bool(a.value())) return *v;
    error(n, diagnostic_code::invalid_attribute,
          std::string{detail::local_name(n)} + " attribute '" + name +
              "' is not a boolean: '" + a.value() + "'");
    return fallback;
  }
  std::optional<model::functional_constraint> fc_attr(xml_node n, bool required_fc) {
    const auto text = attr(n, "fc");
    if (text.empty()) {
      if (required_fc) {
        error(n, diagnostic_code::missing_attribute,
              std::string{detail::local_name(n)} + " without attribute 'fc'");
      }
      return std::nullopt;
    }
    auto f = model::parse_functional_constraint(text);
    if (!f || *f == model::fc::XX) {
      error(n, diagnostic_code::unknown_fc, "unknown functional constraint '" + text + "'");
      return std::nullopt;
    }
    return f;
  }
  bool too_deep(xml_node n, std::size_t depth) {
    if (depth <= opts_.max_depth) return false;
    error(n, diagnostic_code::limit_exceeded, "element nesting deeper than the configured limit");
    return true;
  }

  void parse_header(xml_node n, header& h);
  void parse_communication(xml_node n, const ns_scope& s, communication& c);
  void parse_address(xml_node n, const ns_scope& s, address& a);
  void parse_ied(xml_node n, const ns_scope& s, ied& out);
  void parse_service(xml_node n, const ns_scope& s, service_capability& out, std::size_t depth);
  void parse_access_point(xml_node n, const ns_scope& s, access_point& out);
  void parse_server(xml_node n, const ns_scope& s, server& out);
  void parse_ldevice(xml_node n, const ns_scope& s, logical_device& out);
  void parse_ln(xml_node n, const ns_scope& s, logical_node& out, bool ln0);
  void parse_data_set(xml_node n, const ns_scope& s, data_set& out);
  void parse_report_control(xml_node n, const ns_scope& s, report_control& out);
  model::trigger_conditions parse_trg_ops(xml_node n);
  void parse_data_instance(xml_node n, const ns_scope& s, data_instance& out, std::size_t depth);
  void parse_values(xml_node n, const ns_scope& s, std::vector<value>& out);
  void parse_templates(xml_node n, const ns_scope& s, data_type_templates& out);
  void parse_attribute_def(xml_node n, const ns_scope& s, attribute_def& out, bool is_da);

  detail::line_map lines_;
  const load_options& opts_;
  diagnostics& diags_;
};

void parser::parse(xml_node root, const ns_scope& scope, document& doc) {
  doc.version = attr(root, "version");
  doc.revision = attr(root, "revision");
  doc.release = optional_number<std::uint32_t>(root, "release");
  if (doc.version.empty()) {
    doc.edition = model::edition::ed1;
  } else if (doc.revision == "A" || doc.revision.empty()) {
    doc.edition = model::edition::ed2;
  } else {
    doc.edition = model::edition::ed2_1;
  }

  bool header_seen = false;
  detail::for_each_scl_child(scope, root, [&](std::string_view name, xml_node c, const ns_scope& s) {
    if (name == "Header") {
      if (header_seen) warning(c, diagnostic_code::duplicate_name, "more than one Header");
      header_seen = true;
      parse_header(c, doc.hdr);
    } else if (name == "Communication") {
      parse_communication(c, s, doc.comm);
    } else if (name == "IED") {
      parse_ied(c, s, doc.ieds.emplace_back());
    } else if (name == "DataTypeTemplates") {
      parse_templates(c, s, doc.templates);
    }
  });
  if (!header_seen) warning(root, diagnostic_code::missing_attribute, "SCL without Header");
}

void parser::parse_header(xml_node n, header& h) {
  h.id = attr(n, "id");
  h.version = attr(n, "version");
  h.revision = attr(n, "revision");
  h.tool_id = attr(n, "toolID");
  if (has_attr(n, "nameStructure")) h.name_structure = attr(n, "nameStructure");
  h.line = line(n);
}

void parser::parse_address(xml_node n, const ns_scope& s, address& a) {
  detail::for_each_scl_child(s, n, [&](std::string_view name, xml_node p, const ns_scope&) {
    if (name != "P") return;
    auto type = required(p, "type");
    if (type.empty()) return;
    a.p.push_back({std::move(type), std::string{detail::trim(p.child_value())}});
  });
}

void parser::parse_communication(xml_node n, const ns_scope& s, communication& c) {
  detail::for_each_scl_child(s, n, [&](std::string_view name, xml_node sn, const ns_scope& sns) {
    if (name != "SubNetwork") return;
    auto& net = c.sub_networks.emplace_back();
    net.name = required(sn, "name");
    net.desc = attr(sn, "desc");
    net.type = attr(sn, "type");
    net.line = line(sn);
    detail::for_each_scl_child(sns, sn, [&](std::string_view cn, xml_node ap, const ns_scope& aps) {
      if (cn != "ConnectedAP") return;
      connected_ap cap;
      cap.ied_name = required(ap, "iedName");
      cap.ap_name = required(ap, "apName");
      cap.desc = attr(ap, "desc");
      cap.line = line(ap);
      if (cap.ied_name.empty() || cap.ap_name.empty()) return;
      detail::for_each_scl_child(aps, ap, [&](std::string_view en, xml_node e, const ns_scope& es) {
        if (en == "Address") {
          parse_address(e, es, cap.addr);
        } else if (en == "GSE" || en == "SMV") {
          address a;
          std::optional<std::uint32_t> min_time;
          std::optional<std::uint32_t> max_time;
          auto ld_inst = required(e, "ldInst");
          auto cb_name = required(e, "cbName");
          detail::for_each_scl_child(es, e, [&](std::string_view gn, xml_node g, const ns_scope& gs) {
            if (gn == "Address") {
              parse_address(g, gs, a);
            } else if (gn == "MinTime" || gn == "MaxTime") {
              const auto v = detail::parse_integer<std::uint32_t>(g.child_value());
              if (!v) {
                error(g, diagnostic_code::invalid_attribute,
                      std::string{gn} + " is not a valid number");
              }
              (gn == "MinTime" ? min_time : max_time) = v;
            }
          });
          if (en == "GSE") {
            cap.gse.push_back({std::move(ld_inst), std::move(cb_name), std::move(a), min_time,
                               max_time, line(e)});
          } else {
            cap.smv.push_back({std::move(ld_inst), std::move(cb_name), std::move(a), line(e)});
          }
        }
      });
      net.connected_aps.push_back(std::move(cap));
    });
  });
}

void parser::parse_service(xml_node n, const ns_scope& s, service_capability& out,
                           std::size_t depth) {
  out.name = std::string{detail::local_name(n)};
  out.line = line(n);
  for (auto a = n.first_attribute(); a; a = a.next_attribute()) {
    out.attributes.emplace_back(a.name(), a.value());
  }
  if (too_deep(n, depth)) return;
  detail::for_each_scl_child(s, n, [&](std::string_view, xml_node c, const ns_scope& cs) {
    parse_service(c, cs, out.children.emplace_back(), depth + 1);
  });
}

void parser::parse_ied(xml_node n, const ns_scope& s, ied& out) {
  out.name = required(n, "name");
  out.desc = attr(n, "desc");
  out.type = attr(n, "type");
  out.manufacturer = attr(n, "manufacturer");
  out.config_version = attr(n, "configVersion");
  out.original_scl_version = attr(n, "originalSclVersion");
  out.original_scl_revision = attr(n, "originalSclRevision");
  out.eng_right = attr(n, "engRight");
  out.owner = attr(n, "owner");
  out.line = line(n);
  detail::for_each_scl_child(s, n, [&](std::string_view name, xml_node c, const ns_scope& cs) {
    if (name == "Services") {
      out.svc.present = true;
      detail::for_each_scl_child(cs, c, [&](std::string_view, xml_node e, const ns_scope& es) {
        parse_service(e, es, out.svc.items.emplace_back(), 1);
      });
    } else if (name == "AccessPoint") {
      access_point ap;
      parse_access_point(c, cs, ap);
      if (!ap.name.empty()) out.access_points.push_back(std::move(ap));
    }
  });
}

void parser::parse_access_point(xml_node n, const ns_scope& s, access_point& out) {
  out.name = required(n, "name");
  out.desc = attr(n, "desc");
  out.router = boolean(n, "router", false);
  out.clock = boolean(n, "clock", false);
  out.line = line(n);
  detail::for_each_scl_child(s, n, [&](std::string_view name, xml_node c, const ns_scope& cs) {
    if (name == "Server") {
      if (out.srv) {
        error(c, diagnostic_code::duplicate_name, "AccessPoint '" + out.name + "' with two Servers");
        return;
      }
      parse_server(c, cs, out.srv.emplace());
    } else if (name == "ServerAt") {
      out.server_at = required(c, "apName");
    }
  });
}

void parser::parse_server(xml_node n, const ns_scope& s, server& out) {
  out.timeout = number<std::uint32_t>(n, "timeout", 30);
  out.line = line(n);
  detail::for_each_scl_child(s, n, [&](std::string_view name, xml_node c, const ns_scope& cs) {
    if (name == "Authentication") {
      out.auth.none = boolean(c, "none", true);
      out.auth.password = boolean(c, "password", false);
      out.auth.weak = boolean(c, "weak", false);
      out.auth.strong = boolean(c, "strong", false);
      out.auth.certificate = boolean(c, "certificate", false);
    } else if (name == "LDevice") {
      logical_device ld;
      parse_ldevice(c, cs, ld);
      if (!ld.inst.empty()) out.ldevices.push_back(std::move(ld));
    }
  });
}

void parser::parse_ldevice(xml_node n, const ns_scope& s, logical_device& out) {
  out.inst = required(n, "inst");
  out.ld_name = attr(n, "ldName");
  out.desc = attr(n, "desc");
  out.line = line(n);
  if (out.inst.empty()) return;
  bool ln0_seen = false;
  detail::for_each_scl_child(s, n, [&](std::string_view name, xml_node c, const ns_scope& cs) {
    if (name == "LN0") {
      if (ln0_seen) {
        error(c, diagnostic_code::duplicate_name, "LDevice '" + out.inst + "' with two LN0");
        return;
      }
      ln0_seen = true;
      parse_ln(c, cs, out.ln0, true);
    } else if (name == "LN") {
      logical_node ln;
      parse_ln(c, cs, ln, false);
      if (!ln.ln_class.empty()) out.lns.push_back(std::move(ln));
    }
  });
  if (!ln0_seen) {
    error(n, diagnostic_code::missing_attribute, "LDevice '" + out.inst + "' without LN0");
    out.ln0.ln_class = "LLN0";
    out.ln0.line = out.line;
  }
}

void parser::parse_ln(xml_node n, const ns_scope& s, logical_node& out, bool ln0) {
  out.prefix = attr(n, "prefix");
  out.ln_class = ln0 ? attr(n, "lnClass") : required(n, "lnClass");
  if (ln0 && out.ln_class.empty()) out.ln_class = "LLN0";
  out.inst = attr(n, "inst");
  out.ln_type = required(n, "lnType");
  out.desc = attr(n, "desc");
  out.line = line(n);
  if (!ln0 && out.inst.empty() && !out.ln_class.empty()) {
    error(n, diagnostic_code::missing_attribute, "LN '" + out.ln_class + "' without attribute 'inst'");
  }
  if (!out.ln_class.empty() && !model::split_ln_name(out.name())) {
    warning(n, diagnostic_code::invalid_name, "LN name '" + out.name() + "' is not [prefix]LNClass[inst]");
  }

  detail::for_each_scl_child(s, n, [&](std::string_view name, xml_node c, const ns_scope& cs) {
    if (name == "DataSet") {
      data_set ds;
      parse_data_set(c, cs, ds);
      if (!ds.name.empty()) out.data_sets.push_back(std::move(ds));
    } else if (name == "ReportControl") {
      report_control rc;
      parse_report_control(c, cs, rc);
      if (!rc.name.empty()) out.report_controls.push_back(std::move(rc));
    } else if (name == "LogControl") {
      log_control lc;
      lc.name = required(c, "name");
      lc.desc = attr(c, "desc");
      lc.dat_set = attr(c, "datSet");
      lc.log_name = required(c, "logName");
      lc.log_ena = boolean(c, "logEna", true);
      lc.reason_code = boolean(c, "reasonCode", true);
      lc.buf_time = number<std::uint32_t>(c, "bufTime", 0);
      lc.intg_pd = number<std::uint32_t>(c, "intgPd", 0);
      lc.ld_inst = attr(c, "ldInst");
      lc.prefix = attr(c, "prefix");
      if (has_attr(c, "lnClass")) lc.ln_class = attr(c, "lnClass");
      lc.ln_inst = attr(c, "lnInst");
      lc.line = line(c);
      detail::for_each_scl_child(cs, c, [&](std::string_view tn, xml_node t, const ns_scope&) {
        if (tn == "TrgOps") lc.trg_ops = parse_trg_ops(t);
      });
      if (!lc.name.empty()) out.log_controls.push_back(std::move(lc));
    } else if (name == "GSEControl") {
      if (!ln0) warning(c, diagnostic_code::type_mismatch, "GSEControl outside LN0");
      gse_control g;
      g.name = required(c, "name");
      g.desc = attr(c, "desc");
      g.dat_set = attr(c, "datSet");
      g.app_id = required(c, "appID");
      g.conf_rev = number<std::uint32_t>(c, "confRev", 0);
      if (has_attr(c, "type")) g.type = attr(c, "type");
      g.fixed_offs = boolean(c, "fixedOffs", false);
      g.line = line(c);
      if (!g.name.empty()) out.gse_controls.push_back(std::move(g));
    } else if (name == "SampledValueControl") {
      if (!ln0) warning(c, diagnostic_code::type_mismatch, "SampledValueControl outside LN0");
      sampled_value_control sv;
      sv.name = required(c, "name");
      sv.desc = attr(c, "desc");
      sv.dat_set = attr(c, "datSet");
      sv.smv_id = required(c, "smvID");
      sv.conf_rev = number<std::uint32_t>(c, "confRev", 0);
      sv.smp_rate = number<std::uint32_t>(c, "smpRate", 0);
      sv.nof_asdu = number<std::uint32_t>(c, "nofASDU", 0);
      if (has_attr(c, "smpMod")) sv.smp_mod = attr(c, "smpMod");
      sv.multicast = boolean(c, "multicast", true);
      sv.line = line(c);
      detail::for_each_scl_child(cs, c, [&](std::string_view on, xml_node o, const ns_scope&) {
        if (on != "SmvOpts") return;
        sv.opts.refresh_time = boolean(o, "refreshTime", false);
        sv.opts.sample_synchronized = boolean(o, "sampleSynchronized", true);
        sv.opts.sample_rate = boolean(o, "sampleRate", false);
        sv.opts.data_set = boolean(o, "dataSet", boolean(o, "dataRef", false));
        sv.opts.security = boolean(o, "security", false);
        sv.opts.timestamp = boolean(o, "timestamp", false);
        sv.opts.synch_source_id = boolean(o, "synchSourceId", false);
      });
      if (!sv.name.empty()) out.smv_controls.push_back(std::move(sv));
    } else if (name == "SettingControl") {
      if (!ln0) warning(c, diagnostic_code::type_mismatch, "SettingControl outside LN0");
      setting_control sc;
      sc.desc = attr(c, "desc");
      sc.num_of_sgs = number<std::uint32_t>(c, "numOfSGs", 0);
      sc.act_sg = number<std::uint32_t>(c, "actSG", 1);
      sc.line = line(c);
      if (sc.num_of_sgs == 0) {
        error(c, diagnostic_code::invalid_attribute, "SettingControl numOfSGs must be at least 1");
      } else if (sc.act_sg == 0 || sc.act_sg > sc.num_of_sgs) {
        error(c, diagnostic_code::invalid_attribute, "SettingControl actSG outside 1..numOfSGs");
      }
      out.setting = sc;
    } else if (name == "DOI") {
      data_instance d;
      parse_data_instance(c, cs, d, 1);
      if (!d.name.empty()) out.data.push_back(std::move(d));
    }
  });
}

void parser::parse_data_set(xml_node n, const ns_scope& s, data_set& out) {
  out.name = required(n, "name");
  out.desc = attr(n, "desc");
  out.line = line(n);
  detail::for_each_scl_child(s, n, [&](std::string_view name, xml_node c, const ns_scope&) {
    if (name == "FCCB") {
      warning(c, diagnostic_code::unresolved_reference, "FCCB data set members are not supported");
      return;
    }
    if (name != "FCDA") return;
    fcda f;
    f.ld_inst = attr(c, "ldInst");
    f.prefix = attr(c, "prefix");
    f.ln_class = attr(c, "lnClass");
    f.ln_inst = attr(c, "lnInst");
    f.do_name = attr(c, "doName");
    f.da_name = attr(c, "daName");
    f.fc = fc_attr(c, true);
    f.ix = optional_number<std::uint32_t>(c, "ix");
    f.line = line(c);
    if (f.ln_class.empty()) {
      error(c, diagnostic_code::missing_attribute, "FCDA without attribute 'lnClass'");
    } else if (f.ld_inst.empty()) {
      error(c, diagnostic_code::missing_attribute, "FCDA without attribute 'ldInst'");
    }
    out.members.push_back(std::move(f));
  });
}

model::trigger_conditions parser::parse_trg_ops(xml_node n) {
  using model::trigger;
  model::trigger_conditions t;
  t.set(trigger::data_change, boolean(n, "dchg", false));
  t.set(trigger::quality_change, boolean(n, "qchg", false));
  t.set(trigger::data_update, boolean(n, "dupd", false));
  t.set(trigger::integrity, boolean(n, "period", false));
  t.set(trigger::general_interrogation, boolean(n, "gi", true));
  return t;
}

void parser::parse_report_control(xml_node n, const ns_scope& s, report_control& out) {
  out.name = required(n, "name");
  out.desc = attr(n, "desc");
  out.dat_set = attr(n, "datSet");
  out.rpt_id = attr(n, "rptID");
  out.conf_rev = number<std::uint32_t>(n, "confRev", 0);
  out.buffered = boolean(n, "buffered", false);
  out.buf_time = number<std::uint32_t>(n, "bufTime", 0);
  out.intg_pd = number<std::uint32_t>(n, "intgPd", 0);
  out.indexed = boolean(n, "indexed", true);
  out.line = line(n);
  detail::for_each_scl_child(s, n, [&](std::string_view name, xml_node c, const ns_scope& cs) {
    if (name == "TrgOps") {
      out.trg_ops = parse_trg_ops(c);
    } else if (name == "OptFields") {
      using model::optional_field;
      model::optional_fields o;
      o.set(optional_field::sequence_number, boolean(c, "seqNum", false));
      o.set(optional_field::report_time_stamp, boolean(c, "timeStamp", false));
      o.set(optional_field::reason_for_inclusion, boolean(c, "reasonCode", false));
      o.set(optional_field::data_set_name, boolean(c, "dataSet", false));
      o.set(optional_field::data_reference, boolean(c, "dataRef", false));
      o.set(optional_field::buffer_overflow, boolean(c, "bufOvfl", true));
      o.set(optional_field::entry_id, boolean(c, "entryID", false));
      o.set(optional_field::conf_revision, boolean(c, "configRef", false));
      o.set(optional_field::segmentation, boolean(c, "segmentation", false));
      out.opt_fields = o;
    } else if (name == "RptEnabled") {
      out.has_rpt_enabled = true;
      out.rpt_enabled_max = number<std::uint32_t>(c, "max", 1);
      if (out.rpt_enabled_max == 0) {
        error(c, diagnostic_code::invalid_attribute, "RptEnabled max must be at least 1");
        out.rpt_enabled_max = 1;
      }
      detail::for_each_scl_child(cs, c, [&](std::string_view ln, xml_node e, const ns_scope&) {
        if (ln != "ClientLN") return;
        out.clients.push_back({attr(e, "iedName"), attr(e, "ldInst"), attr(e, "prefix"),
                               attr(e, "lnClass"), attr(e, "lnInst"), attr(e, "apRef"), line(e)});
      });
    }
  });
}

void parser::parse_values(xml_node n, const ns_scope& s, std::vector<value>& out) {
  detail::for_each_scl_child(s, n, [&](std::string_view name, xml_node v, const ns_scope&) {
    if (name != "Val") return;
    out.push_back({std::string{detail::trim(v.child_value())},
                   optional_number<std::uint32_t>(v, "sGroup")});
  });
}

void parser::parse_data_instance(xml_node n, const ns_scope& s, data_instance& out,
                                 std::size_t depth) {
  out.name = required(n, "name");
  out.desc = attr(n, "desc");
  out.s_addr = attr(n, "sAddr");
  out.ix = optional_number<std::uint32_t>(n, "ix");
  out.line = line(n);
  if (too_deep(n, depth)) return;
  detail::for_each_scl_child(s, n, [&](std::string_view name, xml_node c, const ns_scope& cs) {
    if (name == "SDI") {
      data_instance d;
      parse_data_instance(c, cs, d, depth + 1);
      if (!d.name.empty()) out.sub_instances.push_back(std::move(d));
    } else if (name == "DAI") {
      attribute_instance a;
      a.name = required(c, "name");
      a.desc = attr(c, "desc");
      a.s_addr = attr(c, "sAddr");
      a.ix = optional_number<std::uint32_t>(c, "ix");
      a.line = line(c);
      if (has_attr(c, "valKind")) {
        a.kind = parse_value_kind(attr(c, "valKind"));
        if (!a.kind) error(c, diagnostic_code::invalid_attribute, "invalid valKind '" + attr(c, "valKind") + "'");
      }
      parse_values(c, cs, a.values);
      if (!a.name.empty()) out.attributes.push_back(std::move(a));
    }
  });
}

void parser::parse_attribute_def(xml_node n, const ns_scope& s, attribute_def& out, bool is_da) {
  out.name = required(n, "name");
  out.desc = attr(n, "desc");
  out.line = line(n);
  if (is_da) {
    out.fc = fc_attr(n, true);
    out.dchg = boolean(n, "dchg", false);
    out.qchg = boolean(n, "qchg", false);
    out.dupd = boolean(n, "dupd", false);
  }
  out.btype = required(n, "bType");
  out.type = attr(n, "type");
  if (const auto c = n.attribute("count"); c) {
    if (const auto v = detail::parse_integer<std::uint32_t>(c.value())) {
      out.count = *v;
    } else {
      // Ed.2 allows a count naming another attribute; the array size is then dynamic.
      warning(n, diagnostic_code::invalid_attribute,
              "count '" + std::string{c.value()} + "' of '" + out.name +
                  "' is not a number; treated as not an array");
    }
  }
  if (has_attr(n, "valKind")) {
    const auto k = parse_value_kind(attr(n, "valKind"));
    if (k) {
      out.kind = *k;
    } else {
      error(n, diagnostic_code::invalid_attribute, "invalid valKind '" + attr(n, "valKind") + "'");
    }
  }
  out.val_import = boolean(n, "valImport", false);
  out.s_addr = attr(n, "sAddr");
  parse_values(n, s, out.values);
}

void parser::parse_templates(xml_node n, const ns_scope& s, data_type_templates& out) {
  detail::for_each_scl_child(s, n, [&](std::string_view name, xml_node t, const ns_scope& ts) {
    if (name == "LNodeType") {
      lnode_type lt;
      lt.id = required(t, "id");
      lt.ln_class = required(t, "lnClass");
      lt.desc = attr(t, "desc");
      lt.ied_type = attr(t, "iedType");
      lt.line = line(t);
      detail::for_each_scl_child(ts, t, [&](std::string_view cn, xml_node c, const ns_scope&) {
        if (cn != "DO") return;
        data_object_def d;
        d.name = required(c, "name");
        d.type = required(c, "type");
        d.desc = attr(c, "desc");
        d.count = number<std::uint32_t>(c, "count", 0);
        d.transient = boolean(c, "transient", false);
        d.line = line(c);
        if (!d.name.empty() && !d.type.empty()) lt.data_objects.push_back(std::move(d));
      });
      if (!lt.id.empty()) out.lnode_types.push_back(std::move(lt));
    } else if (name == "DOType") {
      do_type dt;
      dt.id = required(t, "id");
      dt.cdc = required(t, "cdc");
      dt.desc = attr(t, "desc");
      dt.ied_type = attr(t, "iedType");
      dt.line = line(t);
      std::uint32_t position = 0;
      detail::for_each_scl_child(ts, t, [&](std::string_view cn, xml_node c, const ns_scope& cs) {
        if (cn == "SDO") {
          sub_data_object_def d;
          d.name = required(c, "name");
          d.type = required(c, "type");
          d.desc = attr(c, "desc");
          d.count = number<std::uint32_t>(c, "count", 0);
          d.position = position++;
          d.line = line(c);
          if (!d.name.empty() && !d.type.empty()) dt.sub_data_objects.push_back(std::move(d));
        } else if (cn == "DA") {
          attribute_def a;
          parse_attribute_def(c, cs, a, true);
          a.position = position++;
          if (!a.name.empty() && !a.btype.empty() && a.fc) dt.attributes.push_back(std::move(a));
        }
      });
      if (!dt.id.empty()) out.do_types.push_back(std::move(dt));
    } else if (name == "DAType") {
      da_type dt;
      dt.id = required(t, "id");
      dt.desc = attr(t, "desc");
      dt.ied_type = attr(t, "iedType");
      dt.line = line(t);
      std::uint32_t position = 0;
      detail::for_each_scl_child(ts, t, [&](std::string_view cn, xml_node c, const ns_scope& cs) {
        if (cn != "BDA") return;
        attribute_def a;
        parse_attribute_def(c, cs, a, false);
        a.position = position++;
        if (!a.name.empty() && !a.btype.empty()) dt.attributes.push_back(std::move(a));
      });
      if (!dt.id.empty()) out.da_types.push_back(std::move(dt));
    } else if (name == "EnumType") {
      enum_type et;
      et.id = required(t, "id");
      et.desc = attr(t, "desc");
      et.line = line(t);
      detail::for_each_scl_child(ts, t, [&](std::string_view cn, xml_node c, const ns_scope&) {
        if (cn != "EnumVal") return;
        if (!has_attr(c, "ord")) {
          error(c, diagnostic_code::missing_attribute, "EnumVal without attribute 'ord'");
          return;
        }
        const auto ord = detail::parse_integer<std::int32_t>(c.attribute("ord").value());
        if (!ord) {
          error(c, diagnostic_code::invalid_attribute,
                "EnumVal ord '" + std::string{c.attribute("ord").value()} + "' is not a number");
          return;
        }
        et.values.push_back({*ord, std::string{detail::trim(c.child_value())}, attr(c, "desc")});
      });
      if (!et.id.empty()) out.enum_types.push_back(std::move(et));
    }
  });
}

}  // namespace

load_result load_string(std::string_view xml, const load_options& opts) {
  load_result out{errc::malformed_encoding, {}};
  out.diags.set_limit(opts.max_diagnostics);
  if (xml.size() > opts.max_input_size) {
    out.diags.error(diagnostic_code::limit_exceeded, 0, "input larger than max_input_size");
    out.doc = errc::length_overflow;
    return out;
  }

  pugi::xml_document xdoc;
  // No DOCTYPE processing: pugixml never resolves external entities.
  const auto parsed = xdoc.load_buffer(xml.data(), xml.size(),
                                       pugi::parse_default & ~pugi::parse_doctype,
                                       pugi::encoding_auto);
  const detail::line_map lines{xml};
  if (!parsed) {
    out.diags.error(diagnostic_code::xml_syntax, lines.line_of(parsed.offset),
                    std::string{"XML: "} + parsed.description());
    return out;
  }
  const auto root = xdoc.document_element();
  const ns_scope root_scope{nullptr, root};
  if (!root || detail::local_name(root) != "SCL" || !root_scope.is_scl(root)) {
    out.diags.error(diagnostic_code::not_scl, root ? lines.line_of(root.offset_debug()) : 0,
                    "root element is not SCL");
    return out;
  }

  document doc;
  parser p{xml, opts, out.diags};
  p.parse(root, root_scope, doc);
  detail::validate(doc, out.diags);
  if (opts.strict && out.diags.has_errors()) return out;
  out.doc = std::move(doc);
  return out;
}

load_result load_file(const std::filesystem::path& path, const load_options& opts) {
  load_result out{errc::malformed_encoding, {}};
  std::error_code ec;
  const auto size = std::filesystem::file_size(path, ec);
  if (ec) {
    out.diags.error(diagnostic_code::not_found, 0, "cannot read '" + path.string() + "': " + ec.message());
    out.doc = ec;
    return out;
  }
  if (size > opts.max_input_size) {
    out.diags.error(diagnostic_code::limit_exceeded, 0, "file larger than max_input_size");
    out.doc = errc::length_overflow;
    return out;
  }
  std::ifstream in{path, std::ios::binary};
  std::string text(static_cast<std::size_t>(size), '\0');
  if (!in || !in.read(text.data(), static_cast<std::streamsize>(text.size()))) {
    const auto err = std::make_error_code(std::errc::io_error);
    out.diags.error(diagnostic_code::not_found, 0, "cannot read '" + path.string() + "'");
    out.doc = err;
    return out;
  }
  return load_string(text, opts);
}

}  // namespace openiec61850::scl
