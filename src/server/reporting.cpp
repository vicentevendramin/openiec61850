// Reporting (IEC 61850-7-2 §17.2, IEC 61850-8-1 §17.2): BRCB and URCB.

#include <algorithm>
#include <array>
#include <chrono>
#include <limits>
#include <utility>

#include <asio/post.hpp>

#include "detail.hpp"
#include "values.hpp"

namespace openiec61850::server::detail {

namespace {

using model::optional_field;
using model::trigger;

constexpr std::uint8_t event_triggers =
    static_cast<std::uint8_t>(trigger::data_change) | static_cast<std::uint8_t>(trigger::quality_change) |
    static_cast<std::uint8_t>(trigger::data_update);

model::entry_time now_entry_time() {
  auto t = mms::binary_time::from_time_point(std::chrono::system_clock::now());
  return t ? *t : model::entry_time{0, std::uint16_t{0}};
}

bool active(const rcb& r) noexcept { return r.rpt_ena || (r.buffered && r.ever_enabled); }

// Another association holds the RCB (reserved or enabled), or keeps a BRCB reservation.
bool foreign(const rcb& r, const session& s) noexcept {
  if (r.owner != 0) return r.owner != s.id;
  return !r.held_for.empty() && r.held_for != s.address;
}

std::optional<std::uint32_t> as_u32(const mms::data& v) {
  if (v.type() == mms::data_type::unsigned_) {
    auto x = v.as_uint64();
    if (x && *x <= std::numeric_limits<std::uint32_t>::max()) return static_cast<std::uint32_t>(*x);
  } else if (v.type() == mms::data_type::integer) {
    auto x = v.as_int64();
    if (x && *x >= 0 && *x <= std::numeric_limits<std::uint32_t>::max()) {
      return static_cast<std::uint32_t>(*x);
    }
  }
  return std::nullopt;
}

// The report as an Unconfirmed-PDU; empty if it cannot be encoded.
byte_buffer encode_report(const std::vector<mms::data>& items) {
  std::vector<mms::access_result> results(items.begin(), items.end());
  const mms::information_report ir{
      mms::variable_access_specification::named(mms::object_name::vmd("RPT")), results};
  byte_buffer out;
  if (!mms::encode_pdu(mms::unconfirmed_pdu{ir}, out)) out.clear();
  return out;
}

std::size_t pdu_size(const std::vector<mms::data>& items) {
  const auto out = encode_report(items);
  return out.empty() ? std::numeric_limits<std::size_t>::max() : out.size();
}

}  // namespace

void server_state::init_rcb(const report_control_definition& def) {
  auto r = std::make_unique<rcb>(strand);
  r->node = def.node;
  r->ln = def.ln;
  r->buffered = def.settings.buffered;
  for (const auto c : at(def.node).children) r->attrs.emplace(at(c).name, c);
  target self{def.node, r->buffered ? model::fc::BR : model::fc::RP, {}};
  r->mms_ref = mms_reference(self);
  const auto& s = def.settings;
  r->rpt_id = s.rpt_id;
  r->conf_rev = s.conf_rev;
  r->opt = s.opt_flds;
  r->opt.set(optional_field::segmentation, false);
  r->buf_tm = s.buf_tm;
  r->trg = s.trg_ops;
  r->intg_pd = s.intg_pd;
  if (!s.data_set.empty()) {
    const node_id ld = model.logical_device_of(def.ln);
    const auto it = data_sets.find({at(ld).name, at(def.ln).name + "$" + s.data_set});
    if (it != data_sets.end()) {
      r->ds = it->second;
      r->dat_set = it->second->mms_text;
      r->pending.resize(r->ds->members.size());
    }
  }
  rcb_of[def.node] = r.get();
  sync(*r);
  rcbs.push_back(std::move(r));
}

void server_state::sync(rcb& r) {
  auto set = [&](std::string_view name, mms::data v) {
    if (const auto it = r.attrs.find(name); it != r.attrs.end()) values[it->second] = std::move(v);
  };
  set("RptID", mms::data::visible_string(r.rpt_id));
  set("RptEna", mms::data::boolean(r.rpt_ena));
  set("Resv", mms::data::boolean(r.resv));
  set("DatSet", mms::data::visible_string(r.dat_set));
  set("ConfRev", mms::data::unsigned_integer(r.conf_rev));
  set("OptFlds", r.opt.to_mms());
  set("BufTm", mms::data::unsigned_integer(r.buf_tm));
  set("SqNum", mms::data::unsigned_integer(r.sq_num));
  set("TrgOps", r.trg.to_mms());
  set("IntgPd", mms::data::unsigned_integer(r.intg_pd));
  set("GI", mms::data::boolean(false));
  set("PurgeBuf", mms::data::boolean(false));
  set("EntryID", r.entry.to_mms());
  set("TimeOfEntry", mms::data::binary_time(r.time_of_entry));
  set("ResvTms", mms::data::integer(r.resv_tms));
  byte_buffer owner;
  if (const auto* s = find_session(r.owner); s != nullptr) {
    owner = s->address_bytes;
  } else if (!r.held_for.empty()) {
    owner = r.held_bytes;
  }
  set("Owner", mms::data::octet_string(owner));
}

std::optional<dae> server_state::write_rcb(session& s, rcb& r, std::string_view attr,
                                           const mms::data& v) {
  if (foreign(r, s)) return dae::object_access_denied;
  // A reservation kept for this client's address is taken over by its new association.
  if (r.owner == 0 && !r.held_for.empty()) {
    r.owner = s.id;
    r.held_for.clear();
    ++r.hold_gen;
    r.resv_timer.cancel();
  }
  const auto config_locked = [&]() -> std::optional<dae> {
    if (r.rpt_ena) return dae::temporarily_unavailable;
    return std::nullopt;
  };
  const bool ed1 = model.edition() == model::edition::ed1;
  std::optional<dae> result;
  // URCB: writing any attribute reserves it (7-2 Ed.2 §17.2.4.2).
  auto reserve = [&] {
    if (!r.buffered) {
      r.owner = s.id;
      r.resv = true;
    }
  };

  if (attr == "Resv" && !r.buffered) {
    auto b = v.as_boolean();
    if (!b) return dae::type_inconsistent;
    if (*b) {
      reserve();
    } else if (r.rpt_ena) {
      return dae::temporarily_unavailable;
    } else {
      r.resv = false;
      r.owner = 0;
    }
  } else if (attr == "ResvTms" && r.buffered && !ed1) {
    if (auto e = config_locked()) return e;
    auto x = v.as_int64();
    if (!x) return dae::type_inconsistent;
    if (*x < 0 || *x > std::numeric_limits<std::int16_t>::max()) return dae::object_value_invalid;
    r.resv_tms = static_cast<std::int32_t>(*x);
    if (r.resv_tms > 0) {
      r.owner = s.id;
    } else if (r.owner == s.id) {
      r.owner = 0;
    }
  } else if (attr == "RptID") {
    if (auto e = config_locked()) return e;
    auto x = v.as_visible_string();
    if (!x) return dae::type_inconsistent;
    if (x->size() > (ed1 ? 65U : 129U)) return dae::object_value_invalid;
    reserve();
    r.rpt_id = std::string(*x);
  } else if (attr == "DatSet") {
    if (auto e = config_locked()) return e;
    auto x = v.as_visible_string();
    if (!x) return dae::type_inconsistent;
    std::shared_ptr<data_set> ds;
    if (!x->empty()) {
      ds = find_data_set(&s, *x);
      if (!ds) return dae::object_value_invalid;
    }
    reserve();
    if (ds != r.ds) {
      r.ds = ds;
      r.dat_set = ds ? ds->mms_text : std::string{};
      ++r.conf_rev;
      r.pending.assign(ds ? ds->members.size() : 0, std::nullopt);
      r.pending_count = 0;
      r.buffer.clear();
      r.next_send = 0;
    }
  } else if (attr == "OptFlds") {
    if (auto e = config_locked()) return e;
    auto x = model::optional_fields::from_mms(v);
    if (!x) return dae::type_inconsistent;
    reserve();
    r.opt = *x;
    r.opt.set(optional_field::segmentation, false);
  } else if (attr == "BufTm" || attr == "IntgPd") {
    if (auto e = config_locked()) return e;
    const auto x = as_u32(v);
    if (!x) return v.type() == mms::data_type::unsigned_ || v.type() == mms::data_type::integer
                       ? dae::object_value_invalid
                       : dae::type_inconsistent;
    reserve();
    (attr == "BufTm" ? r.buf_tm : r.intg_pd) = *x;
  } else if (attr == "TrgOps") {
    if (auto e = config_locked()) return e;
    auto x = model::trigger_conditions::from_mms(v);
    if (!x) return dae::type_inconsistent;
    reserve();
    r.trg = model::trigger_conditions::from_raw(
        static_cast<std::uint8_t>(x->raw() & ~static_cast<unsigned>(trigger::application_trigger)));
  } else if (attr == "PurgeBuf" && r.buffered) {
    if (auto e = config_locked()) return e;
    auto b = v.as_boolean();
    if (!b) return dae::type_inconsistent;
    if (*b) {
      r.buffer.clear();
      r.next_send = 0;
      r.overflow_next = false;
    }
  } else if (attr == "EntryID" && r.buffered) {
    if (auto e = config_locked()) return e;
    auto id = model::entry_id::from_mms(v);
    if (!id) return id.error() == openiec61850::errc::invalid_state ? dae::type_inconsistent
                                                                     : dae::object_value_invalid;
    // 7-2 §17.2.2.13: resume after the identified entry; zero: from the oldest one. An entry no
    // longer buffered (overwritten) resumes from the oldest with BufOvfl set.
    r.entry = *id;
    if (id->is_zero()) {
      r.next_send = 0;
    } else {
      const auto it = std::find_if(r.buffer.begin(), r.buffer.end(),
                                   [&](const report_entry& e) { return e.id == *id; });
      if (it != r.buffer.end()) {
        r.next_send = static_cast<std::size_t>(it - r.buffer.begin()) + 1;
      } else {
        r.next_send = 0;
        r.overflow_next = true;
      }
    }
  } else if (attr == "RptEna") {
    auto b = v.as_boolean();
    if (!b) return dae::type_inconsistent;
    if (*b) {
      if (!r.ds) return dae::object_attribute_inconsistent;
      reserve();
      r.owner = s.id;
      if (!r.rpt_ena) {
        r.rpt_ena = true;
        if (r.buffered && !r.ever_enabled) {
          r.ever_enabled = true;
          r.buffer.clear();
          r.next_send = 0;
        }
        start_integrity(r);
        if (r.buffered && !r.pump_posted) {
          r.pump_posted = true;
          asio::post(strand, [w = weak_from_this(), p = &r] {
            auto self = w.lock();
            if (!self) return;
            p->pump_posted = false;
            self->pump(*p);
          });
        }
      }
    } else if (r.rpt_ena) {
      disable(r);
      if (r.buffered && r.resv_tms <= 0) r.owner = 0;
    }
  } else if (attr == "GI") {
    auto b = v.as_boolean();
    if (!b) return dae::type_inconsistent;
    if (*b && r.rpt_ena && r.trg.general_interrogation()) {
      asio::post(strand, [w = weak_from_this(), p = &r] {
        if (auto self = w.lock()) self->general_interrogation(*p);
      });
    }
  } else {
    // ConfRev, SqNum, TimeOfEntry, Owner and attributes of the other RCB kind.
    result = dae::object_access_denied;
  }
  sync(r);
  return result;
}

void server_state::before_change(node_id holder) {
  for (auto& rp : rcbs) {
    auto& r = *rp;
    if (!r.ds || r.pending_count == 0) continue;
    const auto it = r.ds->by_holder.find(holder);
    if (it == r.ds->by_holder.end()) continue;
    for (const auto idx : it->second) {
      if (r.pending[idx] && r.pending[idx]->tick != tick) {
        // 7-2 §17.2.2.5: a second change of a member within the buffer time sends the pending
        // report first.
        flush(r);
        break;
      }
    }
  }
}

void server_state::on_change(node_id holder, model::trigger_conditions reasons) {
  for (auto& rp : rcbs) {
    auto& r = *rp;
    if (!r.ds || !active(r)) continue;
    const auto bits = static_cast<std::uint8_t>(reasons.raw() & r.trg.raw() & event_triggers);
    if (bits == 0) continue;
    const auto it = r.ds->by_holder.find(holder);
    if (it == r.ds->by_holder.end()) continue;
    for (const auto idx : it->second) {
      auto& p = r.pending[idx];
      if (!p) {
        p = pending_member{};
        ++r.pending_count;
      }
      p->reason = model::trigger_conditions::from_raw(static_cast<std::uint8_t>(p->reason.raw() | bits));
      p->tick = tick;
    }
    schedule_flush(r);
  }
}

void server_state::schedule_flush(rcb& r) {
  if (r.buf_tm == 0) {
    if (r.flush_posted) return;
    r.flush_posted = true;
    asio::post(strand, [w = weak_from_this(), p = &r] {
      auto self = w.lock();
      if (!self) return;
      p->flush_posted = false;
      self->flush(*p);
    });
    return;
  }
  if (r.buf_running) return;
  r.buf_running = true;
  const auto gen = ++r.buf_gen;
  r.buf_timer.expires_after(std::chrono::milliseconds(r.buf_tm));
  r.buf_timer.async_wait([w = weak_from_this(), p = &r, gen](std::error_code ec) {
    auto self = w.lock();
    if (!self || ec || gen != p->buf_gen) return;
    p->buf_running = false;
    self->flush(*p);
  });
}

void server_state::flush(rcb& r) {
  if (r.buf_running) {
    r.buf_running = false;
    ++r.buf_gen;
    r.buf_timer.cancel();
  }
  if (r.pending_count == 0 || !r.ds) return;
  report_entry e;
  e.members.resize(r.ds->members.size());
  for (std::size_t i = 0; i < r.pending.size() && i < e.members.size(); ++i) {
    if (!r.pending[i]) continue;
    auto v = value_of(r.ds->members[i].t);
    if (v) e.members[i] = included{std::move(*v), r.pending[i]->reason};
    r.pending[i].reset();
  }
  r.pending_count = 0;
  if (!active(r)) return;
  emit(r, std::move(e));
}

report_entry server_state::snapshot_all(rcb& r, model::trigger_conditions reason) {
  report_entry e;
  if (!r.ds) return e;
  e.members.resize(r.ds->members.size());
  for (std::size_t i = 0; i < e.members.size(); ++i) {
    auto v = value_of(r.ds->members[i].t);
    if (v) e.members[i] = included{std::move(*v), reason};
  }
  return e;
}

void server_state::general_interrogation(rcb& r) {
  if (!r.rpt_ena || !r.ds) return;
  flush(r);
  emit(r, snapshot_all(r, model::trigger_conditions::of({trigger::general_interrogation})));
}

void server_state::integrity(rcb& r) {
  if (!r.rpt_ena || !r.ds) return;
  flush(r);
  emit(r, snapshot_all(r, model::trigger_conditions::of({trigger::integrity})));
}

void server_state::start_integrity(rcb& r) {
  const auto gen = ++r.intg_gen;
  if (!r.rpt_ena || !r.trg.integrity() || r.intg_pd == 0) {
    r.intg_timer.cancel();
    return;
  }
  r.intg_timer.expires_after(std::chrono::milliseconds(r.intg_pd));
  r.intg_timer.async_wait([w = weak_from_this(), p = &r, gen](std::error_code ec) {
    auto self = w.lock();
    if (!self || ec || gen != p->intg_gen) return;
    self->integrity(*p);
    self->start_integrity(*p);
  });
}

void server_state::emit(rcb& r, report_entry e) {
  e.sq_num = r.sq_num;
  r.sq_num = (r.sq_num + 1) & (r.buffered ? 0xFFFFU : 0xFFU);
  e.time = now_entry_time();
  if (r.buffered) {
    std::array<std::uint8_t, 8> id{};
    const auto n = ++next_entry;
    for (std::size_t i = 0; i < 8; ++i) id[7 - i] = static_cast<std::uint8_t>(n >> (8 * i));
    e.id = model::entry_id(id);
    const std::size_t cap = options.brcb_buffer_capacity > 0 ? options.brcb_buffer_capacity : 1;
    while (r.buffer.size() >= cap) {
      if (r.next_send > 0) {
        --r.next_send;
      } else {
        r.overflow_next = true;
      }
      r.buffer.pop_front();
    }
    r.buffer.push_back(std::move(e));
    pump(r);
  } else if (r.rpt_ena) {
    if (auto* s = find_session(r.owner)) send_report(*s, r, e, false);
  }
  sync(r);
}

void server_state::pump(rcb& r) {
  if (!r.buffered || !r.rpt_ena) return;
  auto* s = find_session(r.owner);
  if (s == nullptr) return;
  while (r.next_send < r.buffer.size()) {
    if (s->reports_blocked()) {
      s->reports_paused = !s->closed;
      break;
    }
    const auto& e = r.buffer[r.next_send];
    const bool overflow = r.overflow_next;
    r.overflow_next = false;
    send_report(*s, r, e, overflow);
    if (s->closed) {  // the entry is still to be delivered
      r.overflow_next = overflow;
      break;
    }
    r.entry = e.id;
    r.time_of_entry = e.time;
    ++r.next_send;
  }
  sync(r);
}

void server_state::send_report(session& s, rcb& r, const report_entry& e, bool overflow) {
  if (!r.ds || !s.assoc) return;
  const auto edition = model.edition();
  auto opt = r.opt;
  opt.set(optional_field::segmentation, false);
  if (!r.buffered) {
    opt.set(optional_field::buffer_overflow, false);
    opt.set(optional_field::entry_id, false);
  }
  std::vector<std::size_t> included_idx;
  for (std::size_t i = 0; i < e.members.size(); ++i) {
    if (e.members[i]) included_idx.push_back(i);
  }
  if (included_idx.empty()) return;
  const std::string& rpt_id = r.rpt_id.empty() ? r.mms_ref : r.rpt_id;
  const std::size_t n = e.members.size();

  auto build = [&](std::span<const std::size_t> part, std::optional<std::uint32_t> sub,
                   bool more) {
    auto o = opt;
    o.set(optional_field::segmentation, sub.has_value());
    std::vector<mms::data> items;
    items.push_back(mms::data::visible_string(rpt_id));
    items.push_back(o.to_mms());
    if (o.sequence_number()) items.push_back(mms::data::unsigned_integer(e.sq_num));
    if (o.report_time_stamp()) items.push_back(mms::data::binary_time(e.time));
    if (o.data_set_name()) items.push_back(mms::data::visible_string(r.dat_set));
    if (o.buffer_overflow()) items.push_back(mms::data::boolean(overflow));
    if (o.entry_id()) items.push_back(e.id.to_mms());
    if (o.conf_revision()) items.push_back(mms::data::unsigned_integer(r.conf_rev));
    if (sub) {
      items.push_back(mms::data::unsigned_integer(*sub));
      items.push_back(mms::data::boolean(more));
    }
    std::vector<bool> inclusion(n, false);
    for (const auto i : part) inclusion[i] = true;
    items.push_back(make_bits(inclusion));
    if (o.data_reference()) {
      for (const auto i : part) items.push_back(mms::data::visible_string(r.ds->members[i].mms_ref));
    }
    for (const auto i : part) items.push_back(e.members[i]->value);
    if (o.reason_for_inclusion()) {
      for (const auto i : part) {
        auto code = e.members[i]->reason.to_mms_reason_code(edition);
        items.push_back(code ? std::move(*code) : e.members[i]->reason.to_mms());
      }
    }
    return items;
  };
  // The last PDU of a buffered entry stands for the entry.
  auto send = [&](byte_buffer pdu, bool last) {
    s.send_unconfirmed(std::move(pdu), last && r.buffered ? &r : nullptr);
  };

  auto whole = encode_report(build(included_idx, std::nullopt, false));
  if (s.max_pdu == 0 || whole.size() <= s.max_pdu) {
    send(std::move(whole), true);
    return;
  }

  // 8-1 §17.2.3.3: segmentation. Members are packed greedily by their encoded size; each segment
  // is checked once encoded.
  const auto header = build({}, 0, true);
  const std::size_t header_size = pdu_size(header) + 8;
  const bool with_ref = opt.data_reference();
  const bool with_reason = opt.reason_for_inclusion();
  std::vector<std::vector<std::size_t>> segments(1);
  std::size_t used = header_size;
  for (const auto i : included_idx) {
    std::size_t cost = encoded_size(e.members[i]->value);
    if (with_ref) cost += r.ds->members[i].mms_ref.size() + 4;
    if (with_reason) cost += 4;
    if (!segments.back().empty() && used + cost > s.max_pdu) {
      segments.emplace_back();
      used = header_size;
    }
    segments.back().push_back(i);
    used += cost;
  }
  for (std::size_t k = 0; k < segments.size(); ++k) {
    const bool more = k + 1 < segments.size();
    auto pdu = encode_report(build(segments[k], static_cast<std::uint32_t>(k), more));
    if (pdu.size() > s.max_pdu) continue;  // a single member larger than the PDU
    send(std::move(pdu), !more);
  }
}

void server_state::disable(rcb& r) {
  if (r.buffered) flush(r);  // pending events still go to the buffer
  r.rpt_ena = false;
  ++r.intg_gen;
  r.intg_timer.cancel();
  if (!r.buffered) {
    for (auto& p : r.pending) p.reset();
    r.pending_count = 0;
    r.buf_running = false;
    ++r.buf_gen;
    r.buf_timer.cancel();
  }
  sync(r);
}

void server_state::release_session_rcbs(session& s) {
  for (auto& rp : rcbs) {
    auto& r = *rp;
    if (r.owner != s.id) continue;
    if (r.rpt_ena) disable(r);
    r.owner = 0;
    if (!r.buffered) {
      r.resv = false;
    } else if (r.resv_tms > 0) {
      // 7-2 Ed.2 §17.2.2.12: the reservation survives the association for ResvTms seconds.
      r.held_for = s.address;
      r.held_bytes = s.address_bytes;
      const auto gen = ++r.hold_gen;
      r.resv_timer.expires_after(std::chrono::seconds(r.resv_tms));
      r.resv_timer.async_wait([w = weak_from_this(), p = &r, gen](std::error_code ec) {
        auto self = w.lock();
        if (!self || ec || gen != p->hold_gen) return;
        p->held_for.clear();
        p->held_bytes.clear();
        self->sync(*p);
      });
    }
    sync(r);
  }
}

void server_state::rewind_unwritten(session& s) {
  for (const auto& [p, count] : s.unwritten) {
    auto& r = *p;
    if (count == 0 || r.owner != s.id) continue;
    r.next_send -= std::min(count, r.next_send);
    r.entry = r.next_send > 0 ? r.buffer[r.next_send - 1].id : model::entry_id{};
    if (r.next_send > 0) r.time_of_entry = r.buffer[r.next_send - 1].time;
    sync(r);
  }
  s.unwritten.clear();
}

void server_state::resume_reports(session& s) {
  s.reports_paused = false;
  for (auto& rp : rcbs) {
    if (rp->owner == s.id && rp->buffered) pump(*rp);
  }
}

void server_state::data_set_deleted(const std::shared_ptr<data_set>& ds) {
  for (auto& rp : rcbs) {
    auto& r = *rp;
    if (r.ds != ds) continue;
    if (r.rpt_ena) disable(r);
    r.ds.reset();
    r.dat_set.clear();
    r.pending.clear();
    r.pending_count = 0;
    sync(r);
  }
}

}  // namespace openiec61850::server::detail
