// Logs (IEC 61850-7-2 §17.3, IEC 61850-8-1 §17.3): log control blocks "LN$LG$name" feeding
// bounded in-memory logs, read through the MMS journal services (ReadJournal, InitializeJournal,
// ReportJournalStatus) on the journal "LN$LogName" of the LD's domain.
//
// An LCB with LogEna = true logs, for each apply() (a client write or an application update
// batch), one entry holding the data set members changed with a trigger in its TrgOps
// (dchg / qchg / dupd), and every IntgPd ms (TrgOps integrity) one entry with all members. Each
// value is a Journal-Variable tagged with its data reference "LD/LN$FC$DO$DA" followed by one
// tagged "ReasonCode" (8-1 §17.3.3).

#include <algorithm>
#include <chrono>
#include <limits>
#include <map>
#include <utility>

#include "detail.hpp"
#include "values.hpp"

namespace openiec61850::server::detail {

namespace {

using model::trigger;
namespace ec = mms::error_code;

constexpr std::uint8_t event_triggers =
    static_cast<std::uint8_t>(trigger::data_change) |
    static_cast<std::uint8_t>(trigger::quality_change) |
    static_cast<std::uint8_t>(trigger::data_update);

std::uint64_t time_key(const mms::binary_time& t) noexcept {
  return std::uint64_t{t.days.value_or(0)} * 86'400'000U + t.ms_of_day;
}

model::entry_time now_entry_time() {
  auto t = mms::binary_time::from_time_point(std::chrono::system_clock::now());
  return t ? *t : model::entry_time{0, std::uint16_t{0}};
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

log_store* find_log(server_state& st, const mms::object_name& name) {
  if (name.scope != mms::object_scope::domain_specific) return nullptr;
  const auto it = st.logs.find({std::string(name.domain_id), std::string(name.item_id)});
  return it == st.logs.end() ? nullptr : it->second.get();
}

std::size_t find_entry(const log_store& log, byte_view id) {
  for (std::size_t i = 0; i < log.entries.size(); ++i) {
    const auto& b = log.entries[i].id.bytes();
    if (id.size() == b.size() && std::equal(b.begin(), b.end(), id.begin())) return i;
  }
  return log.entries.size();
}

}  // namespace

void server_state::init_logs() {
  for (const auto& def : model.logs()) {
    auto log = std::make_unique<log_store>();
    log->domain = at(model.logical_device_of(def.ln)).name;
    log->item = at(def.ln).name + "$" + def.name;
    logs.emplace(std::make_pair(log->domain, log->item), std::move(log));
  }
  for (const auto& def : model.log_controls()) {
    auto l = std::make_unique<lcb>(strand);
    l->node = def.node;
    l->ln = def.ln;
    for (const auto c : at(def.node).children) l->attrs.emplace(at(c).name, c);
    const auto& s = def.settings;
    const node_id ld = model.logical_device_of(def.ln);
    if (!s.log_name.empty()) {
      const std::string ln_name = s.log_ln.empty() ? at(def.ln).name : s.log_ln;
      const auto it = logs.find({at(ld).name, ln_name + "$" + s.log_name});
      if (it != logs.end()) {
        l->log = it->second.get();
        l->log_ref = it->first.first + "/" + it->first.second;
      }
    }
    if (!s.data_set.empty()) {
      const auto it = data_sets.find({at(ld).name, at(def.ln).name + "$" + s.data_set});
      if (it != data_sets.end()) {
        l->ds = it->second;
        l->dat_set = it->second->mms_text;
      }
    }
    l->trg = model::trigger_conditions::from_raw(static_cast<std::uint8_t>(
        s.trg_ops.raw() & ~static_cast<unsigned>(trigger::application_trigger)));
    l->intg_pd = s.intg_pd;
    l->ena = s.log_ena && l->ds && l->log != nullptr;
    lcb_of[def.node] = l.get();
    sync(*l);
    if (l->ena) start_log_integrity(*l);
    lcbs.push_back(std::move(l));
  }
}

void server_state::sync(lcb& l) {
  auto set = [&](std::string_view name, mms::data v) {
    if (const auto it = l.attrs.find(name); it != l.attrs.end()) values[it->second] = std::move(v);
  };
  set("LogEna", mms::data::boolean(l.ena));
  set("LogRef", mms::data::visible_string(l.log_ref));
  set("DatSet", mms::data::visible_string(l.dat_set));
  const model::entry_time zero{0, std::uint16_t{0}};
  const bool any = l.log != nullptr && !l.log->entries.empty();
  set("OldEntrTm", mms::data::binary_time(any ? l.log->entries.front().time : zero));
  set("NewEntrTm", mms::data::binary_time(any ? l.log->entries.back().time : zero));
  set("OldEnt", any ? l.log->entries.front().id.to_mms() : model::entry_id{}.to_mms());
  set("NewEnt", any ? l.log->entries.back().id.to_mms() : model::entry_id{}.to_mms());
  set("TrgOps", l.trg.to_mms());
  set("IntgPd", mms::data::unsigned_integer(l.intg_pd));
}

std::optional<dae> server_state::write_lcb(session& s, lcb& l, std::string_view attr,
                                           const mms::data& v) {
  std::optional<dae> out;
  if (attr == "LogEna") {
    auto b = v.as_boolean();
    if (!b) return dae::type_inconsistent;
    if (*b && (!l.ds || l.log == nullptr)) return dae::object_attribute_inconsistent;
    if (*b != l.ena) {
      l.ena = *b;
      start_log_integrity(l);
    }
  } else if (attr == "DatSet") {
    if (l.ena) return dae::temporarily_unavailable;
    auto x = v.as_visible_string();
    if (!x) return dae::type_inconsistent;
    std::shared_ptr<data_set> ds;
    if (!x->empty()) {
      if (x->starts_with('@')) return dae::object_value_invalid;  // would vanish with the client
      ds = find_data_set(&s, *x);
      if (!ds) return dae::object_value_invalid;
    }
    l.ds = ds;
    l.dat_set = ds ? ds->mms_text : std::string{};
  } else if (attr == "TrgOps") {
    if (l.ena) return dae::temporarily_unavailable;
    auto x = model::trigger_conditions::from_mms(v);
    if (!x) return dae::type_inconsistent;
    l.trg = model::trigger_conditions::from_raw(
        static_cast<std::uint8_t>(x->raw() & ~static_cast<unsigned>(trigger::application_trigger)));
  } else if (attr == "IntgPd") {
    const auto x = as_u32(v);
    if (!x) return v.type() == mms::data_type::unsigned_ || v.type() == mms::data_type::integer
                       ? dae::object_value_invalid
                       : dae::type_inconsistent;
    l.intg_pd = *x;
    start_log_integrity(l);
  } else {
    out = dae::object_access_denied;
  }
  sync(l);
  return out;
}

void server_state::add_log_entry(lcb& l, std::vector<logged_value> vals) {
  if (l.log == nullptr || vals.empty()) return;
  log_entry e;
  std::array<std::uint8_t, 8> id{};
  const auto n = ++next_entry;
  for (std::size_t i = 0; i < 8; ++i) id[7 - i] = static_cast<std::uint8_t>(n >> (8 * i));
  e.id = model::entry_id(id);
  e.time = now_entry_time();
  e.values = std::move(vals);
  auto& entries = l.log->entries;
  entries.push_back(std::move(e));
  const std::size_t cap = options.log_capacity > 0 ? options.log_capacity : 1;
  while (entries.size() > cap) entries.pop_front();
  for (auto& other : lcbs) {
    if (other->log == l.log) sync(*other);
  }
}

void server_state::log_changes(
    const std::vector<std::pair<node_id, model::trigger_conditions>>& changes) {
  for (auto& lp : lcbs) {
    auto& l = *lp;
    if (!l.ena || !l.ds || l.log == nullptr) continue;
    std::map<std::size_t, std::uint8_t> members;
    for (const auto& [holder, reasons] : changes) {
      const auto bits = static_cast<std::uint8_t>(reasons.raw() & l.trg.raw() & event_triggers);
      if (bits == 0) continue;
      const auto it = l.ds->by_holder.find(holder);
      if (it == l.ds->by_holder.end()) continue;
      for (const auto idx : it->second) members[idx] |= bits;
    }
    if (members.empty()) continue;
    std::vector<logged_value> vals;
    for (const auto& [idx, bits] : members) {
      const auto& m = l.ds->members[idx];
      auto v = value_of(m.t);
      if (!v) continue;
      vals.push_back({m.mms_ref, std::move(*v), model::trigger_conditions::from_raw(bits)});
    }
    add_log_entry(l, std::move(vals));
  }
}

void server_state::log_integrity(lcb& l) {
  if (!l.ena || !l.ds) return;
  std::vector<logged_value> vals;
  for (const auto& m : l.ds->members) {
    auto v = value_of(m.t);
    if (!v) continue;
    vals.push_back({m.mms_ref, std::move(*v), model::trigger_conditions::of({trigger::integrity})});
  }
  add_log_entry(l, std::move(vals));
}

void server_state::start_log_integrity(lcb& l) {
  const auto gen = ++l.intg_gen;
  if (!l.ena || !l.trg.integrity() || l.intg_pd == 0) {
    l.intg_timer.cancel();
    return;
  }
  l.intg_timer.expires_after(std::chrono::milliseconds(l.intg_pd));
  l.intg_timer.async_wait([w = weak_from_this(), p = &l, gen](std::error_code e) {
    auto self = w.lock();
    if (!self || e || gen != p->intg_gen) return;
    self->log_integrity(*p);
    self->start_log_integrity(*p);
  });
}

// --- journal services

void server_state::dispatch_ext(session& s, const mms::read_journal_request& r, reply& out) {
  auto* log = find_log(*this, r.journal_name);
  if (log == nullptr) {
    out.fail(mms::error_class::definition, ec::definition::object_undefined);
    return;
  }
  const auto& entries = log->entries;
  std::size_t first = 0;
  if (r.starting_entry) {
    first = find_entry(*log, *r.starting_entry);
  } else if (r.starting_time) {
    const auto k = time_key(*r.starting_time);
    while (first < entries.size() && time_key(entries[first].time) < k) ++first;
  }
  if (r.start_after) {
    std::size_t after = find_entry(*log, r.start_after->entry);
    if (after < entries.size()) {
      ++after;
    } else {
      const auto k = time_key(r.start_after->time);
      after = 0;
      while (after < entries.size() && time_key(entries[after].time) <= k) ++after;
    }
    first = std::max(first, after);
  }
  std::vector<std::string_view> filter;
  if (r.variables) {
    for (const auto v : *r.variables) filter.push_back(v);
  }
  const std::size_t budget = s.max_pdu > 128 ? s.max_pdu - 64 : std::numeric_limits<std::size_t>::max();
  std::size_t used = 0;
  std::size_t count = 0;
  bool more = false;
  const auto edition = model.edition();
  for (std::size_t i = first; i < entries.size(); ++i) {
    const auto& e = entries[i];
    if (r.ending_time && time_key(e.time) > time_key(*r.ending_time)) break;
    if (r.number_of_entries && *r.number_of_entries >= 0 &&
        count >= static_cast<std::size_t>(*r.number_of_entries)) {
      break;
    }
    std::size_t cost = 40;
    std::vector<mms::journal_variable> vars;
    for (const auto& v : e.values) {
      if (!filter.empty() && std::find(filter.begin(), filter.end(), v.reference) == filter.end()) {
        continue;
      }
      auto code = v.reason.to_mms_reason_code(edition);
      out.data.push_back(code ? std::move(*code) : v.reason.to_mms());
      vars.push_back({v.reference, mms::data_ref(v.value)});
      vars.push_back({"ReasonCode", mms::data_ref(out.data.back())});
      cost += v.reference.size() + encoded_size(v.value) + 32;
    }
    if (count > 0 && used + cost > budget) {
      more = true;
      break;
    }
    used += cost;
    ++count;
    out.ids.push_back(e.id.bytes());
    out.journal_vars.push_back(std::move(vars));
    mms::journal_entry je;
    je.entry_id = out.ids.back();
    je.occurrence_time = e.time;
    je.variables = out.journal_vars.back();
    out.journal.push_back(je);
  }
  out.response = mms::read_journal_response{out.journal, more};
}

void server_state::dispatch_ext(session&, const mms::initialize_journal_request& r, reply& out) {
  auto* log = find_log(*this, r.journal_name);
  if (log == nullptr) {
    out.fail(mms::error_class::definition, ec::definition::object_undefined);
    return;
  }
  auto& entries = log->entries;
  std::size_t n = entries.size();
  if (r.limiting_time) {
    n = 0;
    const auto k = time_key(*r.limiting_time);
    while (n < entries.size() && time_key(entries[n].time) <= k) ++n;
    if (r.limiting_entry) {
      const auto pos = find_entry(*log, *r.limiting_entry);
      if (pos < entries.size()) n = std::min(n, pos + 1);
    }
  }
  entries.erase(entries.begin(), entries.begin() + static_cast<std::ptrdiff_t>(n));
  for (auto& l : lcbs) {
    if (l->log == log) sync(*l);
  }
  out.response = mms::initialize_journal_response{static_cast<std::uint32_t>(n)};
}

void server_state::dispatch_ext(session&, const mms::report_journal_status_request& r, reply& out) {
  auto* log = find_log(*this, r.journal_name);
  if (log == nullptr) {
    out.fail(mms::error_class::definition, ec::definition::object_undefined);
    return;
  }
  out.response =
      mms::report_journal_status_response{static_cast<std::uint32_t>(log->entries.size()), false};
}

}  // namespace openiec61850::server::detail
