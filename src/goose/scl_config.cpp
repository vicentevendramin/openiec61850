#include "openiec61850/goose/scl_config.hpp"

#include <string>

#include "openiec61850/scl/address.hpp"

namespace openiec61850::goose {

namespace detail {

struct scl_lookup {
  const scl::ied* ied = nullptr;
  const scl::logical_device* ld = nullptr;
  std::string ld_name;
  const scl::address* addr = nullptr;
};

// The LD `ld_inst` of the IED's server (access point `ap_name`, or any) and the ConnectedAP
// element `want` (GSE or SMV) for cbName in the matching access point.
template <typename Element, typename Member>
result<scl_lookup> lookup(const scl::document& doc, std::string_view ied_name,
                          std::string_view ld_inst, std::string_view cb_name,
                          std::string_view ap_name, Member member, const Element** found) {
  scl_lookup r;
  r.ied = doc.find_ied(ied_name);
  if (r.ied == nullptr) return errc::invalid_state;
  for (const auto& ap : r.ied->access_points) {
    if (!ap_name.empty() && ap.name != ap_name) continue;
    const auto* srv = r.ied->find_server(ap.name);
    if (srv == nullptr) continue;
    if (const auto* ld = srv->find_ld(ld_inst)) {
      r.ld = ld;
      break;
    }
  }
  if (r.ld == nullptr) return errc::invalid_state;
  r.ld_name = r.ld->name(ied_name);

  for (const auto& sn : doc.comm.sub_networks) {
    for (const auto& cap : sn.connected_aps) {
      if (cap.ied_name != ied_name || (!ap_name.empty() && cap.ap_name != ap_name)) continue;
      for (const auto& e : cap.*member) {
        if (e.ld_inst == ld_inst && e.cb_name == cb_name) {
          *found = &e;
          r.addr = &e.addr;
          return r;
        }
      }
    }
  }
  return errc::invalid_state;
}

}  // namespace detail

namespace {

struct gse_info {
  detail::scl_lookup where;
  const scl::gse_control* cb = nullptr;
  const scl::gse_address* gse = nullptr;
  scl::l2_address l2;
};

result<gse_info> find_gse(const scl::document& doc, std::string_view ied_name,
                          std::string_view ld_inst, std::string_view cb_name,
                          std::string_view ap_name) {
  gse_info g;
  auto w = detail::lookup(doc, ied_name, ld_inst, cb_name, ap_name, &scl::connected_ap::gse,
                          &g.gse);
  if (!w) return w.error();
  g.where = std::move(*w);
  for (const auto& c : g.where.ld->ln0.gse_controls) {
    if (c.name == cb_name) g.cb = &c;
  }
  if (g.cb == nullptr) return errc::invalid_state;
  if (g.cb->type == "GSSE") return errc::unsupported;
  auto l2 = scl::parse_l2_address(g.gse->addr);
  if (!l2) return l2.error();
  g.l2 = *l2;
  return g;
}

std::string gocb_ref(const gse_info& g) {
  return g.where.ld_name + "/LLN0$GO$" + g.cb->name;
}

std::string dat_set_ref(const detail::scl_lookup& w, const std::string& dat_set) {
  return w.ld_name + "/LLN0$" + dat_set;
}

}  // namespace

result<publisher_config> publisher_config_from_scl(const scl::document& doc,
                                                   std::string_view ied_name,
                                                   std::string_view ld_inst,
                                                   std::string_view cb_name,
                                                   std::string_view ap_name) {
  auto g = find_gse(doc, ied_name, ld_inst, cb_name, ap_name);
  if (!g) return g.error();
  publisher_config c;
  c.destination = g->l2.mac;
  c.app_id = g->l2.app_id;
  c.vlan = vlan_tag{g->l2.vlan_priority, false, g->l2.vlan_id};
  c.gocb_ref = gocb_ref(*g);
  c.dat_set = dat_set_ref(g->where, g->cb->dat_set);
  c.go_id = g->cb->app_id.empty() ? c.gocb_ref : g->cb->app_id;
  c.conf_rev = g->cb->conf_rev;
  if (g->gse->min_time) c.min_time = std::chrono::milliseconds{*g->gse->min_time};
  if (g->gse->max_time) c.max_time = std::chrono::milliseconds{*g->gse->max_time};
  if (c.max_time < c.min_time) c.max_time = c.min_time;
  return c;
}

result<subscriber_config> subscriber_config_from_scl(const scl::document& doc,
                                                     std::string_view ied_name,
                                                     std::string_view ld_inst,
                                                     std::string_view cb_name,
                                                     std::string_view ap_name) {
  auto g = find_gse(doc, ied_name, ld_inst, cb_name, ap_name);
  if (!g) return g.error();
  subscriber_config c;
  c.app_id = g->l2.app_id;
  c.destination = g->l2.mac;
  c.gocb_ref = gocb_ref(*g);
  c.dat_set = dat_set_ref(g->where, g->cb->dat_set);
  c.go_id = g->cb->app_id.empty() ? c.gocb_ref : g->cb->app_id;
  c.conf_rev = g->cb->conf_rev;
  if (const auto* ds = g->where.ld->ln0.find_data_set(g->cb->dat_set)) {
    c.num_entries = static_cast<std::uint32_t>(ds->members.size());
  }
  return c;
}

}  // namespace openiec61850::goose

namespace openiec61850::sv {

namespace {

struct smv_info {
  goose::detail::scl_lookup where;
  const scl::sampled_value_control* cb = nullptr;
  const scl::smv_address* smv = nullptr;
  scl::l2_address l2;
};

result<smv_info> find_smv(const scl::document& doc, std::string_view ied_name,
                          std::string_view ld_inst, std::string_view cb_name,
                          std::string_view ap_name) {
  smv_info s;
  auto w = goose::detail::lookup(doc, ied_name, ld_inst, cb_name, ap_name,
                                 &scl::connected_ap::smv, &s.smv);
  if (!w) return w.error();
  s.where = std::move(*w);
  for (const auto& c : s.where.ld->ln0.smv_controls) {
    if (c.name == cb_name) s.cb = &c;
  }
  if (s.cb == nullptr) return errc::invalid_state;
  auto l2 = scl::parse_l2_address(s.smv->addr);
  if (!l2) return l2.error();
  s.l2 = *l2;
  return s;
}

std::uint32_t wrap_for(const scl::sampled_value_control& cb, std::uint16_t frequency_hz) {
  if (cb.smp_mod == "SmpPerPeriod") return cb.smp_rate * frequency_hz;
  if (cb.smp_mod == "SmpPerSec") return cb.smp_rate;
  return 0;
}

}  // namespace

result<publisher_config> publisher_config_from_scl(const scl::document& doc,
                                                   std::string_view ied_name,
                                                   std::string_view ld_inst,
                                                   std::string_view cb_name,
                                                   std::string_view ap_name,
                                                   std::uint16_t frequency_hz) {
  auto s = find_smv(doc, ied_name, ld_inst, cb_name, ap_name);
  if (!s) return s.error();
  publisher_config c;
  c.destination = s->l2.mac;
  c.app_id = s->l2.app_id;
  c.vlan = vlan_tag{s->l2.vlan_priority, false, s->l2.vlan_id};
  c.sv_id = s->cb->smv_id;
  if (s->cb->opts.data_set) c.dat_set = s->where.ld_name + "/LLN0$" + s->cb->dat_set;
  c.conf_rev = s->cb->conf_rev;
  if (s->cb->opts.sample_rate) c.smp_rate = static_cast<std::uint16_t>(s->cb->smp_rate);
  if (s->cb->smp_mod == "SmpPerSec") {
    c.smp_mod = static_cast<std::uint16_t>(sample_mode::samples_per_second);
  } else if (s->cb->smp_mod == "SecPerSmp") {
    c.smp_mod = static_cast<std::uint16_t>(sample_mode::seconds_per_sample);
  }
  c.refresh_time = s->cb->opts.refresh_time;
  c.asdus_per_frame = static_cast<std::uint16_t>(s->cb->nof_asdu == 0 ? 1 : s->cb->nof_asdu);
  c.smp_cnt_wrap = wrap_for(*s->cb, frequency_hz);
  return c;
}

result<subscriber_config> subscriber_config_from_scl(const scl::document& doc,
                                                     std::string_view ied_name,
                                                     std::string_view ld_inst,
                                                     std::string_view cb_name,
                                                     std::string_view ap_name,
                                                     std::uint16_t frequency_hz) {
  auto s = find_smv(doc, ied_name, ld_inst, cb_name, ap_name);
  if (!s) return s.error();
  subscriber_config c;
  c.app_id = s->l2.app_id;
  c.destination = s->l2.mac;
  c.sv_id = s->cb->smv_id;
  c.conf_rev = s->cb->conf_rev;
  c.smp_cnt_wrap = wrap_for(*s->cb, frequency_hz);
  return c;
}

}  // namespace openiec61850::sv
