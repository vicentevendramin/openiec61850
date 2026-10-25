#include "openiec61850/server/model.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstdlib>
#include <string>
#include <utility>
#include <variant>

#include "openiec61850/model/entry_id.hpp"
#include "openiec61850/model/enums.hpp"
#include "openiec61850/model/quality.hpp"
#include "values.hpp"

namespace openiec61850::server {

namespace {

using model::basic_type;
using model::fc;

std::error_code err(errc e) noexcept { return make_error_code(e); }

constexpr std::uint32_t fc_bit(model::functional_constraint f) noexcept {
  return 1U << static_cast<unsigned>(f);
}

// Default sizes when attribute_options::size is zero.
std::int32_t effective_size(basic_type t, std::int32_t size) noexcept {
  if (size != 0) return size;
  switch (t) {
    case basic_type::visible_string:
    case basic_type::unicode_string:
      return 255;
    case basic_type::octet_string:
      return 64;
    default:
      return 0;
  }
}

}  // namespace

// --- data_model

node_id data_model::find_logical_device(std::string_view name) const noexcept {
  for (const auto id : lds_) {
    if (nodes_[id].name == name) return id;
  }
  return no_node;
}

node_id data_model::find_child(node_id parent, std::string_view name) const noexcept {
  if (parent >= nodes_.size()) return no_node;
  for (const auto c : nodes_[parent].children) {
    if (nodes_[c].name == name) return c;
  }
  return no_node;
}

result<node_id> data_model::find(const model::object_reference& ref) const {
  if (ref.empty() || ref.is_association_specific()) return err(errc::object_not_found);
  const node_id ld = find_logical_device(ref.ld());
  if (ld == no_node) return err(errc::object_not_found);
  if (!ref.has_ln()) return ld;
  node_id cur = find_child(ld, ref.ln());
  if (cur == no_node) return err(errc::object_not_found);
  const auto f = ref.fc();
  if (f && *f == fc::XX) return err(errc::object_not_found);
  for (const auto pe : ref.path()) {
    if (pe.index) return err(errc::object_not_found);
    const bool filtered = !nodes_[cur].is_attribute();
    cur = find_child(cur, pe.name);
    if (cur == no_node) return err(errc::object_not_found);
    if (f && filtered && !nodes_[cur].has_fc(*f)) return err(errc::object_not_found);
  }
  if (f && !nodes_[cur].has_fc(*f)) return err(errc::object_not_found);
  return cur;
}

std::string data_model::reference_of(node_id id) const {
  std::vector<node_id> chain;
  for (node_id n = id; n != no_node; n = nodes_[n].parent) chain.push_back(n);
  std::string out;
  for (auto it = chain.rbegin(); it != chain.rend(); ++it) {
    const auto& nd = nodes_[*it];
    if (nd.kind == node_kind::logical_node) {
      out.push_back('/');
    } else if (nd.kind != node_kind::logical_device) {
      out.push_back('.');
    }
    out.append(nd.name);
  }
  return out;
}

node_id data_model::logical_node_of(node_id id) const noexcept {
  for (node_id n = id; n != no_node; n = nodes_[n].parent) {
    if (nodes_[n].kind == node_kind::logical_node) return n;
  }
  return no_node;
}

node_id data_model::logical_device_of(node_id id) const noexcept {
  for (node_id n = id; n != no_node; n = nodes_[n].parent) {
    if (nodes_[n].kind == node_kind::logical_device) return n;
  }
  return no_node;
}

result<mms::type_description> data_model::type_of(node_id id,
                                                  std::optional<model::functional_constraint> f) const {
  if (id >= nodes_.size()) return err(errc::object_not_found);
  const auto& nd = nodes_[id];
  switch (nd.kind) {
    case node_kind::logical_device:
      return err(errc::object_not_found);
    case node_kind::logical_node:
      if (!f) {
        std::vector<mms::type_component> comps;
        for (std::size_t i = 0; i < model::functional_constraint_count; ++i) {
          const auto fi = static_cast<model::functional_constraint>(i);
          if (fi == fc::XX || !nd.has_fc(fi)) continue;
          auto t = type_of(id, fi);
          if (!t) return t.error();
          comps.push_back({std::string(model::to_string(fi)), std::move(*t)});
        }
        return mms::type_description::structure(std::move(comps));
      }
      [[fallthrough]];
    case node_kind::data_object:
    case node_kind::control_block: {
      if (!f || !nd.has_fc(*f)) return err(errc::object_not_found);
      std::vector<mms::type_component> comps;
      for (const auto c : nd.children) {
        if (!nodes_[c].has_fc(*f)) continue;
        auto t = type_of(c, f);
        if (!t) return t.error();
        comps.push_back({nodes_[c].name, std::move(*t)});
      }
      return mms::type_description::structure(std::move(comps));
    }
    case node_kind::data_attribute: {
      mms::type_description element;
      if (nd.type) {
        auto t = model::to_mms_type(*nd.type, nd.size, edition_);
        if (!t) return t.error();
        element = std::move(*t);
      } else {
        std::vector<mms::type_component> comps;
        for (const auto c : nd.children) {
          auto t = type_of(c, std::nullopt);
          if (!t) return t.error();
          comps.push_back({nodes_[c].name, std::move(*t)});
        }
        element = mms::type_description::structure(std::move(comps));
      }
      if (nd.count > 0) return mms::type_description::array(nd.count, std::move(element));
      return element;
    }
  }
  return err(errc::object_not_found);
}

// --- builder

model_builder::model_builder(model::edition edition) { m_.edition_ = edition; }

bool model_builder::usable(node_id id, node_kind kind) const noexcept {
  return !error_ && id < m_.nodes_.size() && m_.nodes_[id].kind == kind;
}

node_id model_builder::add(node_id parent, std::string_view name, node_kind kind) {
  if (error_) return no_node;
  if (!model::is_identifier(name)) {
    fail(openiec61850::errc::malformed_encoding);
    return no_node;
  }
  const auto limits = model::name_limits::for_edition(m_.edition_);
  if (name.size() > limits.max_mms_identifier) {
    fail(openiec61850::errc::length_overflow);
    return no_node;
  }
  if (parent == no_node) {
    if (name.size() > limits.max_ld_name) {
      fail(openiec61850::errc::length_overflow);
      return no_node;
    }
    if (m_.find_logical_device(name) != no_node) {
      fail(err(errc::object_exists));
      return no_node;
    }
  } else if (m_.find_child(parent, name) != no_node) {
    fail(err(errc::object_exists));
    return no_node;
  }
  const auto id = static_cast<node_id>(m_.nodes_.size());
  node n;
  n.name = std::string(name);
  n.kind = kind;
  n.parent = parent;
  m_.nodes_.push_back(std::move(n));
  if (parent == no_node) {
    m_.lds_.push_back(id);
  } else {
    m_.nodes_[parent].children.push_back(id);
  }
  return id;
}

ld_handle model_builder::logical_device(std::string_view name) {
  return {this, add(no_node, name, node_kind::logical_device)};
}

ln_handle ld_handle::logical_node(std::string_view name) {
  if (!b_->usable(id_, node_kind::logical_device)) {
    b_->fail(openiec61850::errc::invalid_state);
    return {b_, no_node};
  }
  return {b_, b_->add(id_, name, node_kind::logical_node)};
}

do_handle ln_handle::data_object(std::string_view name) {
  if (!b_->usable(id_, node_kind::logical_node)) {
    b_->fail(openiec61850::errc::invalid_state);
    return {b_, no_node};
  }
  return {b_, b_->add(id_, name, node_kind::data_object)};
}

ln_handle& ln_handle::data_set(std::string_view name, std::vector<model::object_reference> members) {
  if (!b_->usable(id_, node_kind::logical_node)) {
    b_->fail(openiec61850::errc::invalid_state);
    return *this;
  }
  if (!model::is_identifier(name)) {
    b_->fail(openiec61850::errc::malformed_encoding);
    return *this;
  }
  for (const auto& ds : b_->m_.data_sets_) {
    if (ds.ln == id_ && ds.name == name) {
      b_->fail(err(errc::object_exists));
      return *this;
    }
  }
  b_->m_.data_sets_.push_back({id_, std::string(name), std::move(members)});
  return *this;
}

ln_handle& ln_handle::report_control(report_control_settings settings) {
  if (!b_->usable(id_, node_kind::logical_node)) {
    b_->fail(openiec61850::errc::invalid_state);
    return *this;
  }
  b_->add_report_control(id_, std::move(settings));
  return *this;
}

ln_handle& ln_handle::setting_group_control(setting_group_settings settings) {
  if (!b_->usable(id_, node_kind::logical_node)) {
    b_->fail(openiec61850::errc::invalid_state);
    return *this;
  }
  const auto cb = b_->add_control_block(id_, "SGCB", fc::SP);
  if (cb == no_node) return *this;
  const bool ed1 = b_->m_.edition_ == model::edition::ed1;
  auto attr = [&](std::string_view name, basic_type t, mms::data v) {
    attribute_options o;
    o.value = std::move(v);
    (void)b_->add_attribute(cb, name, fc::SP, t, std::move(o));
  };
  attr("NumOfSG", basic_type::int8u, mms::data::unsigned_integer(settings.num_of_sgs));
  attr("ActSG", basic_type::int8u, mms::data::unsigned_integer(settings.act_sg));
  attr("EditSG", basic_type::int8u, mms::data::unsigned_integer(0));
  attr("CnfEdit", basic_type::boolean, mms::data::boolean(false));
  attr("LActTm", basic_type::timestamp, mms::data::utc_time({}));
  if (!ed1) attr("ResvTms", basic_type::int16u, mms::data::unsigned_integer(settings.resv_tms));
  if (b_->error_) return *this;
  b_->m_.sgcbs_.push_back({id_, cb, settings});
  return *this;
}

ln_handle& ln_handle::log(std::string_view name) {
  if (!b_->usable(id_, node_kind::logical_node)) {
    b_->fail(openiec61850::errc::invalid_state);
    return *this;
  }
  if (!model::is_identifier(name)) {
    b_->fail(openiec61850::errc::malformed_encoding);
    return *this;
  }
  for (const auto& l : b_->m_.logs_) {
    if (l.ln == id_ && l.name == name) {
      b_->fail(err(errc::object_exists));
      return *this;
    }
  }
  b_->m_.logs_.push_back({id_, std::string(name)});
  return *this;
}

ln_handle& ln_handle::log_control(log_control_settings settings) {
  if (!b_->usable(id_, node_kind::logical_node)) {
    b_->fail(openiec61850::errc::invalid_state);
    return *this;
  }
  const auto cb = b_->add_control_block(id_, settings.name, fc::LG);
  if (cb == no_node) return *this;
  const bool ed1 = b_->m_.edition_ == model::edition::ed1;
  const std::int32_t ref_size = ed1 ? 65 : 129;
  auto attr = [&](std::string_view name, basic_type t, mms::data v, std::int32_t size = 0) {
    attribute_options o;
    o.size = size;
    o.value = std::move(v);
    (void)b_->add_attribute(cb, name, fc::LG, t, std::move(o));
  };
  attr("LogEna", basic_type::boolean, mms::data::boolean(settings.log_ena));
  attr("LogRef", basic_type::object_reference, mms::data::visible_string(""), ref_size);
  attr("DatSet", basic_type::object_reference, mms::data::visible_string(""), ref_size);
  attr("OldEntrTm", basic_type::entry_time, mms::data::binary_time({0, std::uint16_t{0}}));
  attr("NewEntrTm", basic_type::entry_time, mms::data::binary_time({0, std::uint16_t{0}}));
  attr("OldEnt", basic_type::entry_id, model::entry_id{}.to_mms());
  attr("NewEnt", basic_type::entry_id, model::entry_id{}.to_mms());
  attr("TrgOps", basic_type::trigger_conditions, settings.trg_ops.to_mms());
  attr("IntgPd", basic_type::int32u, mms::data::unsigned_integer(settings.intg_pd));
  if (b_->error_) return *this;
  b_->m_.lcbs_.push_back({id_, cb, std::move(settings)});
  return *this;
}

ln_handle& ln_handle::goose_control(goose_control_settings settings) {
  if (!b_->usable(id_, node_kind::logical_node)) {
    b_->fail(openiec61850::errc::invalid_state);
    return *this;
  }
  const auto cb = b_->add_control_block(id_, settings.name, fc::GO);
  if (cb == no_node) return *this;
  const bool ed1 = b_->m_.edition_ == model::edition::ed1;
  const std::int32_t ref_size = ed1 ? 65 : 129;
  auto attr = [&](node_id parent, std::string_view name, basic_type t, mms::data v,
                  std::int32_t size = 0) {
    attribute_options o;
    o.size = size;
    o.value = std::move(v);
    (void)b_->add_attribute(parent, name, parent == cb ? std::optional(fc::GO) : std::nullopt, t,
                            std::move(o));
  };
  attr(cb, "GoEna", basic_type::boolean, mms::data::boolean(settings.go_ena));
  attr(cb, "GoID", basic_type::visible_string, mms::data::visible_string(settings.go_id), ref_size);
  attr(cb, "DatSet", basic_type::object_reference, mms::data::visible_string(""), ref_size);
  attr(cb, "ConfRev", basic_type::int32u, mms::data::unsigned_integer(settings.conf_rev));
  attr(cb, "NdsCom", basic_type::boolean, mms::data::boolean(settings.data_set.empty()));
  const auto dst = b_->add_attribute(cb, "DstAddress", fc::GO, std::nullopt, {});
  if (dst != no_node) {
    attr(dst, "Addr", basic_type::octet_string, mms::data::octet_string(settings.dst_mac), 6);
    attr(dst, "PRIORITY", basic_type::int8u, mms::data::unsigned_integer(settings.vlan_priority));
    attr(dst, "VID", basic_type::int16u, mms::data::unsigned_integer(settings.vlan_id));
    attr(dst, "APPID", basic_type::int16u, mms::data::unsigned_integer(settings.app_id));
  }
  if (!ed1) {
    attr(cb, "MinTime", basic_type::int32u, mms::data::unsigned_integer(settings.min_time));
    attr(cb, "MaxTime", basic_type::int32u, mms::data::unsigned_integer(settings.max_time));
    attr(cb, "FixedOffs", basic_type::boolean, mms::data::boolean(settings.fixed_offs));
  }
  if (b_->error_) return *this;
  b_->m_.gocbs_.push_back({id_, cb, std::move(settings)});
  return *this;
}

do_handle do_handle::sub_object(std::string_view name) {
  if (!b_->usable(id_, node_kind::data_object)) {
    b_->fail(openiec61850::errc::invalid_state);
    return {b_, no_node};
  }
  return {b_, b_->add(id_, name, node_kind::data_object)};
}

da_handle do_handle::attribute(std::string_view name, model::functional_constraint f,
                               model::basic_type type, attribute_options options) {
  if (!b_->usable(id_, node_kind::data_object)) {
    b_->fail(openiec61850::errc::invalid_state);
    return {b_, no_node};
  }
  return {b_, b_->add_attribute(id_, name, f, type, std::move(options))};
}

da_handle do_handle::structure(std::string_view name, model::functional_constraint f,
                               attribute_options options) {
  if (!b_->usable(id_, node_kind::data_object)) {
    b_->fail(openiec61850::errc::invalid_state);
    return {b_, no_node};
  }
  return {b_, b_->add_attribute(id_, name, f, std::nullopt, std::move(options))};
}

da_handle da_handle::attribute(std::string_view name, model::basic_type type,
                               attribute_options options) {
  if (!b_->usable(id_, node_kind::data_attribute) || b_->m_.nodes_[id_].type) {
    b_->fail(openiec61850::errc::invalid_state);
    return {b_, no_node};
  }
  return {b_, b_->add_attribute(id_, name, std::nullopt, type, std::move(options))};
}

da_handle da_handle::structure(std::string_view name, attribute_options options) {
  if (!b_->usable(id_, node_kind::data_attribute) || b_->m_.nodes_[id_].type) {
    b_->fail(openiec61850::errc::invalid_state);
    return {b_, no_node};
  }
  return {b_, b_->add_attribute(id_, name, std::nullopt, std::nullopt, std::move(options))};
}

da_handle& da_handle::value(mms::data v) {
  if (!b_->usable(id_, node_kind::data_attribute)) {
    b_->fail(openiec61850::errc::invalid_state);
    return *this;
  }
  b_->m_.nodes_[id_].value = std::move(v);
  return *this;
}

da_handle& da_handle::group_value(std::uint32_t sg, mms::data v) {
  if (!b_->usable(id_, node_kind::data_attribute) || sg == 0 || sg > 255) {
    b_->fail(openiec61850::errc::invalid_state);
    return *this;
  }
  auto& g = b_->m_.nodes_[id_].group_values;
  if (g.size() < sg) g.resize(sg);
  g[sg - 1] = std::move(v);
  return *this;
}

node_id model_builder::add_control_block(node_id ln, std::string_view name,
                                         model::functional_constraint f) {
  const auto cb = add(ln, name, node_kind::control_block);
  if (cb != no_node) m_.nodes_[cb].fc = f;
  return cb;
}

node_id model_builder::add_attribute(node_id parent, std::string_view name,
                                     std::optional<model::functional_constraint> f,
                                     std::optional<model::basic_type> type,
                                     attribute_options options) {
  if (f && *f == fc::XX) {
    fail(openiec61850::errc::invalid_state);
    return no_node;
  }
  const auto id = add(parent, name, node_kind::data_attribute);
  if (id == no_node) return no_node;
  auto& n = m_.nodes_[id];
  n.fc = f ? f : m_.nodes_[parent].fc;
  n.type = type;
  n.size = type ? effective_size(*type, options.size) : 0;
  n.count = options.count;
  n.triggers = options.triggers;
  if (options.value) n.value = std::move(*options.value);
  return id;
}

void model_builder::add_report_control(node_id ln, report_control_settings s) {
  const auto f = s.buffered ? fc::BR : fc::RP;
  const auto cb = add_control_block(ln, s.name, f);
  if (cb == no_node) return;
  const bool ed1 = m_.edition_ == model::edition::ed1;
  const std::int32_t ref_size = ed1 ? 65 : 129;
  auto attr = [&](std::string_view name, basic_type t, mms::data v, std::int32_t size = 0) {
    attribute_options o;
    o.size = size;
    o.value = std::move(v);
    (void)add_attribute(cb, name, f, t, std::move(o));
  };
  attr("RptID", basic_type::visible_string, mms::data::visible_string(s.rpt_id), ref_size);
  attr("RptEna", basic_type::boolean, mms::data::boolean(false));
  if (!s.buffered) attr("Resv", basic_type::boolean, mms::data::boolean(false));
  attr("DatSet", basic_type::object_reference, mms::data::visible_string(""));
  attr("ConfRev", basic_type::int32u, mms::data::unsigned_integer(s.conf_rev));
  attr("OptFlds", basic_type::optional_fields, s.opt_flds.to_mms());
  attr("BufTm", basic_type::int32u, mms::data::unsigned_integer(s.buf_tm));
  attr("SqNum", s.buffered ? basic_type::int16u : basic_type::int8u, mms::data::unsigned_integer(0));
  attr("TrgOps", basic_type::trigger_conditions, s.trg_ops.to_mms());
  attr("IntgPd", basic_type::int32u, mms::data::unsigned_integer(s.intg_pd));
  attr("GI", basic_type::boolean, mms::data::boolean(false));
  if (s.buffered) {
    attr("PurgeBuf", basic_type::boolean, mms::data::boolean(false));
    attr("EntryID", basic_type::entry_id, model::entry_id{}.to_mms());
    attr("TimeOfEntry", basic_type::entry_time, mms::data::binary_time({0, std::uint16_t{0}}));
    if (!ed1) attr("ResvTms", basic_type::int16, mms::data::integer(0));
  }
  if (!ed1) attr("Owner", basic_type::octet_string, mms::data::octet_string({}), 64);
  if (error_) return;
  m_.rcbs_.push_back({ln, cb, std::move(s)});
}

result<data_model> model_builder::build() {
  if (error_) return error_;
  auto& nodes = m_.nodes_;
  if (m_.lds_.empty()) return err(errc::invalid_model);

  // Values and leaf types; then the FC masks, children before parents (children have larger ids).
  for (auto& n : nodes) {
    if (n.kind != node_kind::data_attribute) continue;
    if (!n.type && n.children.empty()) return err(errc::invalid_model);
    if (!n.fc) return err(errc::invalid_model);
  }
  // Setting groups: one SGCB per LD, in LLN0.
  std::vector<std::uint8_t> sg_count(nodes.size(), 0);  // by LD
  for (const auto& sg : m_.sgcbs_) {
    const node_id ld = m_.logical_device_of(sg.ln);
    if (nodes[sg.ln].name != "LLN0" || sg_count[ld] != 0) return err(errc::invalid_model);
    if (sg.settings.num_of_sgs == 0 || sg.settings.act_sg == 0 ||
        sg.settings.act_sg > sg.settings.num_of_sgs) {
      return err(errc::invalid_model);
    }
    sg_count[ld] = sg.settings.num_of_sgs;
  }
  for (std::size_t i = nodes.size(); i-- > 0;) {
    auto& n = nodes[i];
    if (n.kind == node_kind::data_attribute) {
      n.fc_mask |= fc_bit(*n.fc);
      if (*n.fc == fc::SG && sg_count[m_.logical_device_of(static_cast<node_id>(i))] > 0) {
        n.fc_mask |= fc_bit(fc::SE);
      }
    }
    if (n.parent != no_node) nodes[n.parent].fc_mask |= n.fc_mask;
  }
  for (std::size_t i = 0; i < nodes.size(); ++i) {
    auto& n = nodes[i];
    if (!n.holds_value()) continue;
    auto t = m_.type_of(static_cast<node_id>(i));
    if (!t) return t.error();
    if (!n.value.valid()) {
      if (n.type && n.count == 0) {
        auto d = default_value(*n.type, n.size, 0, m_.edition_);
        if (!d) return d.error();
        n.value = std::move(*d);
      } else {
        // Arrays: build the default from the element type.
        std::vector<mms::data> elems;
        auto def = [&](auto&& self, node_id id) -> result<mms::data> {
          const auto& e = nodes[id];
          if (e.type) return default_value(*e.type, e.size, 0, m_.edition_);
          std::vector<mms::data> comps;
          for (const auto c : e.children) {
            const auto& cn = nodes[c];
            if (cn.count > 0) {
              auto inner = cn.type ? default_value(*cn.type, cn.size, cn.count, m_.edition_)
                                   : result<mms::data>(err(errc::invalid_model));
              if (!inner) return inner.error();
              comps.push_back(std::move(*inner));
              continue;
            }
            auto v = self(self, c);
            if (!v) return v.error();
            comps.push_back(std::move(*v));
          }
          return mms::data::structure(std::move(comps));
        };
        auto one = def(def, static_cast<node_id>(i));
        if (!one) return one.error();
        for (std::uint32_t k = 0; k < n.count; ++k) elems.push_back(*one);
        n.value = mms::data::array(std::move(elems));
      }
    }
    auto c = detail::conform(n.value, *t);
    if (std::holds_alternative<mms::data_access_error>(c)) return err(errc::type_mismatch);
    n.value = std::move(std::get<mms::data>(c));
    if (!n.group_values.empty()) {
      const auto groups = sg_count[m_.logical_device_of(static_cast<node_id>(i))];
      if (*n.fc != fc::SG || n.group_values.size() > groups) return err(errc::invalid_model);
      for (auto& g : n.group_values) {
        if (!g.valid()) {
          g = n.value;
          continue;
        }
        auto gc = detail::conform(g, *t);
        if (std::holds_alternative<mms::data_access_error>(gc)) return err(errc::type_mismatch);
        g = std::move(std::get<mms::data>(gc));
      }
    }
  }

  for (const auto& ds : m_.data_sets_) {
    if (ds.members.empty()) return err(errc::invalid_model);
    for (const auto& m : ds.members) {
      if (!m.fc() || !m.has_ln() || m.path().empty()) return err(errc::invalid_model);
      if (m.has_index()) continue;  // array elements are checked when the server starts
      if (!m_.find(m)) return err(errc::invalid_model);
    }
  }
  for (const auto& r : m_.rcbs_) {
    if (r.settings.data_set.empty()) continue;
    const bool found = std::any_of(m_.data_sets_.begin(), m_.data_sets_.end(), [&](const auto& ds) {
      return ds.ln == r.ln && ds.name == r.settings.data_set;
    });
    if (!found) return err(errc::invalid_model);
  }

  auto has_data_set = [&](node_id ln, const std::string& name) {
    return name.empty() ||
           std::any_of(m_.data_sets_.begin(), m_.data_sets_.end(),
                       [&](const auto& ds) { return ds.ln == ln && ds.name == name; });
  };
  for (const auto& l : m_.lcbs_) {
    if (!has_data_set(l.ln, l.settings.data_set)) return err(errc::invalid_model);
    if (l.settings.log_name.empty()) continue;
    node_id log_ln = l.ln;
    if (!l.settings.log_ln.empty()) {
      log_ln = m_.find_child(m_.logical_device_of(l.ln), l.settings.log_ln);
      if (log_ln == no_node) return err(errc::invalid_model);
    }
    const bool found = std::any_of(m_.logs_.begin(), m_.logs_.end(), [&](const auto& lg) {
      return lg.ln == log_ln && lg.name == l.settings.log_name;
    });
    if (!found) return err(errc::invalid_model);
  }
  for (const auto& g : m_.gocbs_) {
    if (!has_data_set(g.ln, g.settings.data_set)) return err(errc::invalid_model);
  }

  data_model out = std::move(m_);
  m_ = data_model{};
  m_.edition_ = out.edition_;
  return out;
}

// --- values

result<mms::data> default_value(model::basic_type type, std::int32_t size, std::uint32_t count,
                                model::edition e) {
  (void)e;
  if (count > 0) {
    auto one = default_value(type, size, 0, e);
    if (!one) return one;
    std::vector<mms::data> elems(count, *one);
    return mms::data::array(std::move(elems));
  }
  auto zero_bits = [](std::size_t n) {
    const byte_buffer bytes((n + 7) / 8, 0);
    return mms::data::bit_string(bytes, n);
  };
  switch (type) {
    case basic_type::boolean: return mms::data::boolean(false);
    case basic_type::int8:
    case basic_type::int16:
    case basic_type::int24:
    case basic_type::int32:
    case basic_type::int64:
    case basic_type::int128:
    case basic_type::enumerated:
      return mms::data::integer(0);
    case basic_type::int8u:
    case basic_type::int16u:
    case basic_type::int24u:
    case basic_type::int32u:
      return mms::data::unsigned_integer(0);
    case basic_type::float32: return mms::data::floating_point(0.0F);
    case basic_type::float64: return mms::data::floating_point(0.0);
    case basic_type::coded_enum:
    case basic_type::packed_list:
      if (size <= 0) return openiec61850::errc::invalid_state;
      return zero_bits(static_cast<std::size_t>(size));
    case basic_type::octet_string: return mms::data::octet_string({});
    case basic_type::visible_string:
    case basic_type::object_reference:
      return mms::data::visible_string("");
    case basic_type::unicode_string: return mms::data::mms_string("");
    case basic_type::timestamp: return mms::data::utc_time({});
    case basic_type::entry_time: return mms::data::binary_time({0, std::uint16_t{0}});
    case basic_type::quality: return model::quality{}.to_mms();
    case basic_type::entry_id: return model::entry_id{}.to_mms();
    case basic_type::dbpos:
    case basic_type::tcmd:
    case basic_type::check:
      return zero_bits(2);
    case basic_type::trigger_conditions: return zero_bits(model::trigger_conditions::trg_ops_bit_count);
    case basic_type::optional_fields: return zero_bits(model::optional_fields::bit_count);
  }
  return openiec61850::errc::invalid_state;
}

namespace {

template <typename T>
std::optional<T> parse_number(std::string_view s) {
  while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front())) != 0) s.remove_prefix(1);
  while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back())) != 0) s.remove_suffix(1);
  if (!s.empty() && s.front() == '+') s.remove_prefix(1);
  T v{};
  const auto* end = s.data() + s.size();
  auto [p, ec] = std::from_chars(s.data(), end, v);
  if (ec != std::errc{} || p != end || s.empty()) return std::nullopt;
  return v;
}

std::optional<byte_buffer> parse_hex(std::string_view s) {
  if (s.size() % 2 != 0) return std::nullopt;
  byte_buffer out;
  for (std::size_t i = 0; i < s.size(); i += 2) {
    unsigned v = 0;
    auto [p, ec] = std::from_chars(s.data() + i, s.data() + i + 2, v, 16);
    if (ec != std::errc{} || p != s.data() + i + 2) return std::nullopt;
    out.push_back(static_cast<std::uint8_t>(v));
  }
  return out;
}

result<mms::data> parse_bits(std::string_view s, std::size_t count) {
  std::vector<bool> bits(count, false);
  if (s.size() > count) return err(errc::type_mismatch);
  for (std::size_t i = 0; i < s.size(); ++i) {
    if (s[i] != '0' && s[i] != '1') return err(errc::type_mismatch);
    bits[i] = s[i] == '1';
  }
  byte_buffer bytes((count + 7) / 8, 0);
  for (std::size_t i = 0; i < count; ++i) {
    if (bits[i]) bytes[i / 8] = static_cast<std::uint8_t>(bytes[i / 8] | (0x80U >> (i % 8)));
  }
  return mms::data::bit_string(bytes, count);
}

}  // namespace

result<mms::data> parse_value(model::basic_type type, std::string_view text, std::int32_t size) {
  const auto mismatch = err(errc::type_mismatch);
  switch (type) {
    case basic_type::boolean:
      if (text == "true" || text == "1") return mms::data::boolean(true);
      if (text == "false" || text == "0") return mms::data::boolean(false);
      return mismatch;
    case basic_type::int8:
    case basic_type::int16:
    case basic_type::int24:
    case basic_type::int32:
    case basic_type::int64:
    case basic_type::int128:
    case basic_type::enumerated: {
      auto v = parse_number<std::int64_t>(text);
      if (!v) return mismatch;
      return mms::data::integer(*v);
    }
    case basic_type::int8u:
    case basic_type::int16u:
    case basic_type::int24u:
    case basic_type::int32u: {
      auto v = parse_number<std::uint64_t>(text);
      if (!v) return mismatch;
      return mms::data::unsigned_integer(*v);
    }
    case basic_type::float32:
    case basic_type::float64: {
      const std::string tmp(text);
      char* end = nullptr;
      const double v = std::strtod(tmp.c_str(), &end);
      if (tmp.empty() || end != tmp.c_str() + tmp.size()) return mismatch;
      if (type == basic_type::float32) return mms::data::floating_point(static_cast<float>(v));
      return mms::data::floating_point(v);
    }
    case basic_type::visible_string:
    case basic_type::object_reference:
      return mms::data::visible_string(text);
    case basic_type::unicode_string: return mms::data::mms_string(text);
    case basic_type::octet_string:
    case basic_type::entry_id: {
      auto b = parse_hex(text);
      if (!b) return mismatch;
      return mms::data::octet_string(*b);
    }
    case basic_type::dbpos:
      if (text == "intermediate-state") return model::to_mms(model::dbpos::intermediate);
      if (text == "off") return model::to_mms(model::dbpos::off);
      if (text == "on") return model::to_mms(model::dbpos::on);
      if (text == "bad-state") return model::to_mms(model::dbpos::bad);
      return parse_bits(text, 2);
    case basic_type::tcmd:
      if (text == "stop") return model::to_mms(model::step_command::stop);
      if (text == "lower") return model::to_mms(model::step_command::lower);
      if (text == "higher") return model::to_mms(model::step_command::higher);
      if (text == "reserved") return model::to_mms(model::step_command::reserved);
      return parse_bits(text, 2);
    case basic_type::check: return parse_bits(text, 2);
    case basic_type::quality: return parse_bits(text, model::quality::bit_count);
    case basic_type::trigger_conditions:
      return parse_bits(text, model::trigger_conditions::trg_ops_bit_count);
    case basic_type::optional_fields: return parse_bits(text, model::optional_fields::bit_count);
    case basic_type::coded_enum:
    case basic_type::packed_list:
      if (size <= 0) return openiec61850::errc::invalid_state;
      return parse_bits(text, static_cast<std::size_t>(size));
    case basic_type::timestamp:
    case basic_type::entry_time:
      return openiec61850::errc::unsupported;
  }
  return mismatch;
}

}  // namespace openiec61850::server
