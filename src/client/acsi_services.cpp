// Setting groups (7-2 §16 / 8-1 §16), logs (7-2 §17.3 / 8-1 §17.3), files (7-2 §23 / 8-1 §23)
// and GoCB attributes (7-2 §18.2 / 8-1 §18.1).

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <limits>
#include <span>
#include <string_view>
#include <utility>

#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>

#include "detail.hpp"

namespace openiec61850::client::detail {

using asio::awaitable;
using model::fc;

namespace {

constexpr auto violation = openiec61850::errc::protocol_violation;
constexpr auto misuse = openiec61850::errc::invalid_state;

std::error_code err(errc e) noexcept { return make_error_code(e); }

template <typename R>
const R* response_as(const association::service_response& r) noexcept {
  return std::get_if<R>(&r.service());
}

result<model::mms_variable> variable(const client_state& s, std::string_view text) {
  auto ref = model::object_reference::parse(text, s.parse);
  if (!ref) return ref.error();
  return model::to_mms_variable(*ref, s.limits);
}

result<model::mms_variable> child_variable(const client_state& s, const model::object_reference& cb,
                                           std::string_view name) {
  auto c = cb.child(name, std::nullopt, s.parse);
  if (!c) return c.error();
  return model::to_mms_variable(*c, s.limits);
}

result<std::uint8_t> to_u8(const mms::data& d) {
  auto v = to_uint64(d);
  if (!v) return v.error();
  if (*v > 255) return openiec61850::errc::value_out_of_range;
  return static_cast<std::uint8_t>(*v);
}

result<std::uint32_t> to_u32(const mms::data& d) {
  auto v = to_uint64(d);
  if (!v) return v.error();
  if (*v > std::numeric_limits<std::uint32_t>::max()) return openiec61850::errc::value_out_of_range;
  return static_cast<std::uint32_t>(*v);
}

std::error_code mismatch(std::error_code e) {
  return e == openiec61850::errc::invalid_state ? err(errc::type_mismatch) : e;
}

template <typename T, typename F>
std::error_code set_from(std::optional<T>& field, F&& convert_fn) {
  auto v = convert_fn();
  if (!v) return mismatch(v.error());
  field = std::move(*v);
  return {};
}

// Reads the named attributes of a control block in one Read; returns them by position (failed
// ones as errors). Fails when every attribute failed.
awaitable<result<std::vector<result<mms::data>>>> read_attributes(
    std::shared_ptr<client_state> s, assoc_ptr a, const model::object_reference& cb,
    std::span<const std::string_view> names) {
  std::vector<model::mms_variable> vars;
  for (const auto n : names) {
    auto v = child_variable(*s, cb, n);
    if (!v) co_return v.error();
    vars.push_back(std::move(*v));
  }
  auto values = co_await read_variables_on(a, std::move(vars));
  if (!values) co_return values.error();
  std::error_code first;
  bool any = false;
  for (const auto& v : *values) {
    if (v) {
      any = true;
    } else if (!first) {
      first = v.error();
    }
  }
  if (!any) co_return first;
  co_return std::move(*values);
}

awaitable<result<void>> write_attribute(std::shared_ptr<client_state> s, assoc_ptr a,
                                        const model::object_reference& cb, std::string_view name,
                                        mms::data value) {
  auto v = child_variable(*s, cb, name);
  if (!v) co_return v.error();
  co_return co_await write_variable_on(a, std::move(*v), std::move(value));
}

awaitable<result<void>> write_sgcb(std::shared_ptr<client_state> s, error_details* d,
                                   std::string ld, std::string_view attr, mms::data value) {
  if (ld.empty()) co_return misuse;
  auto v = variable(*s, ld + "/LLN0.SGCB." + std::string(attr) + "[SP]");
  if (!v) co_return v.error();
  auto a = s->current(d);
  if (!a) co_return a.error();
  co_return co_await write_variable_on(*a, std::move(*v), std::move(value));
}

bool is_cb(const model::object_reference& r, model::functional_constraint f) {
  return r.has_ln() && !r.path().empty() && r.fc() == f && !r.has_index();
}

// The MMS journal name of a log reference "LD/LN.LogName".
result<model::mms_name> journal_name(const model::object_reference& log) {
  if (!log.has_ln() || log.path().size() != 1 || log.fc() || log.has_index()) return misuse;
  return model::mms_name{mms::object_scope::domain_specific, std::string(log.ld()),
                         std::string(log.ln()) + "$" + std::string(log.leaf()->name)};
}

result<log_entry> convert_entry(const mms::journal_entry& j) {
  log_entry out;
  auto id = model::entry_id::from_bytes(j.entry_id);
  if (!id) return violation;
  out.entry_id = *id;
  out.time = j.occurrence_time;
  for (const auto v : j.variables) {
    auto value = mms::data::from_view(v.value.view());
    if (!value) return violation;
    if (v.tag == "ReasonCode" && !out.data.empty()) {
      if (auto r = model::trigger_conditions::from_mms(*value)) out.data.back().reason = *r;
      continue;
    }
    out.data.push_back({std::string(v.tag), std::move(*value), std::nullopt});
  }
  return out;
}

awaitable<result<std::vector<log_entry>>> query(std::shared_ptr<client_state> s, error_details* d,
                                                model::object_reference log,
                                                mms::read_journal_request req,
                                                std::optional<model::entry_id> after) {
  auto name = journal_name(log);
  if (!name) co_return name.error();
  auto a = s->current(d);
  if (!a) co_return a.error();
  req.journal_name = name->view();
  std::array<std::uint8_t, 8> after_id{};
  if (after) {
    after_id = after->bytes();
    req.start_after->entry = after_id;
  }
  std::vector<log_entry> out;
  for (;;) {
    auto r = co_await call_on(*a, req);
    if (!r) co_return r.error();
    const auto* rj = response_as<mms::read_journal_response>(*r);
    if (rj == nullptr) co_return violation;
    std::size_t n = 0;
    for (const auto j : rj->entries) {
      auto e = convert_entry(j);
      if (!e) co_return e.error();
      out.push_back(std::move(*e));
      ++n;
    }
    if (!rj->more_follows) break;
    if (n == 0) co_return violation;  // would loop
    // Continue after the last entry received (entryToStartAfter).
    after_id = out.back().entry_id.bytes();
    req.start_after = mms::journal_start_after{out.back().time, after_id};
    req.starting_entry.reset();
  }
  co_return out;
}

std::optional<std::chrono::system_clock::time_point> parse_generalized_time(std::string_view t) {
  // YYYYMMDDHHMMSS[.fff][Z]
  if (t.size() < 14) return std::nullopt;
  int v[6]{};
  const int widths[6]{4, 2, 2, 2, 2, 2};
  std::size_t pos = 0;
  for (int i = 0; i < 6; ++i) {
    int x = 0;
    for (int k = 0; k < widths[i]; ++k, ++pos) {
      const char c = t[pos];
      if (c < '0' || c > '9') return std::nullopt;
      x = x * 10 + (c - '0');
    }
    v[i] = x;
  }
  using namespace std::chrono;
  const year_month_day ymd{year{v[0]}, month{static_cast<unsigned>(v[1])},
                           day{static_cast<unsigned>(v[2])}};
  if (!ymd.ok()) return std::nullopt;
  auto tp = sys_days{ymd} + hours{v[3]} + minutes{v[4]} + seconds{v[5]};
  if (pos < t.size() && t[pos] == '.') {
    ++pos;
    std::int64_t ms = 0;
    int digits = 0;
    while (pos < t.size() && t[pos] >= '0' && t[pos] <= '9') {
      if (digits < 3) {
        ms = ms * 10 + (t[pos] - '0');
        ++digits;
      }
      ++pos;
    }
    while (digits < 3) {
      ms *= 10;
      ++digits;
    }
    return time_point_cast<system_clock::duration>(tp + milliseconds{ms});
  }
  return time_point_cast<system_clock::duration>(tp);
}

std::string join(const mms::list_view<std::string_view>& name) {
  std::string out;
  bool first = true;
  for (const auto part : name) {
    if (!first) out.push_back('/');
    out.append(part);
    first = false;
  }
  return out;
}

}  // namespace

// --- setting groups

awaitable<result<sgcb_values>> get_sgcb_values_op(std::shared_ptr<client_state> s, error_details* d,
                                                  std::string ld) {
  if (ld.empty()) co_return misuse;
  auto v = variable(*s, ld + "/LLN0.SGCB[SP]");
  if (!v) co_return v.error();
  auto a = s->current(d);
  if (!a) co_return a.error();
  std::vector<model::mms_variable> vars;
  vars.push_back(std::move(*v));
  auto r = co_await read_variables_on(*a, std::move(vars));
  if (!r) co_return r.error();
  auto& value = (*r)[0];
  if (!value) co_return value.error();
  const auto comps = value->elements();
  if (value->type() != mms::data_type::structure || comps.size() < 5) co_return err(errc::type_mismatch);
  sgcb_values out;
  auto num = to_u8(comps[0]);
  auto act = to_u8(comps[1]);
  auto edit = to_u8(comps[2]);
  auto cnf = to_bool(comps[3]);
  if (!num || !act || !edit || !cnf) co_return err(errc::type_mismatch);
  out.num_of_sgs = *num;
  out.act_sg = *act;
  out.edit_sg = *edit;
  out.cnf_edit = *cnf;
  if (auto t = to_timestamp(comps[4])) out.lact_tm = *t;
  if (comps.size() > 5) {
    auto resv = to_uint64(comps[5]);
    if (resv && *resv <= 0xFFFF) out.resv_tms = static_cast<std::uint16_t>(*resv);
  }
  co_return out;
}

awaitable<result<void>> select_active_sg_op(std::shared_ptr<client_state> s, error_details* d,
                                            std::string ld, std::uint8_t sg) {
  co_return co_await write_sgcb(s, d, std::move(ld), "ActSG", mms::data::unsigned_integer(sg));
}

awaitable<result<void>> select_edit_sg_op(std::shared_ptr<client_state> s, error_details* d,
                                          std::string ld, std::uint8_t sg) {
  co_return co_await write_sgcb(s, d, std::move(ld), "EditSG", mms::data::unsigned_integer(sg));
}

awaitable<result<void>> confirm_edit_sg_values_op(std::shared_ptr<client_state> s, error_details* d,
                                                  std::string ld) {
  co_return co_await write_sgcb(s, d, std::move(ld), "CnfEdit", mms::data::boolean(true));
}

awaitable<result<void>> set_edit_sg_value_op(std::shared_ptr<client_state> s, error_details* d,
                                             model::object_reference ref, mms::data value) {
  if (ref.fc() != fc::SE) co_return misuse;
  co_return co_await write_op(std::move(s), d, std::move(ref), std::move(value));
}

awaitable<result<mms::data>> get_edit_sg_value_op(std::shared_ptr<client_state> s, error_details* d,
                                                  model::object_reference ref) {
  if (ref.fc() != fc::SE && ref.fc() != fc::SG) co_return misuse;
  co_return co_await read_op(std::move(s), d, std::move(ref));
}

// --- logs

namespace {
constexpr std::array<std::string_view, 9> lcb_attributes{
    "LogEna", "LogRef", "DatSet", "OldEntrTm", "NewEntrTm", "OldEnt", "NewEnt", "TrgOps", "IntgPd"};
}

awaitable<result<lcb_values>> get_lcb_values_op(std::shared_ptr<client_state> s, error_details* d,
                                                model::object_reference lcb) {
  if (!is_cb(lcb, fc::LG)) co_return misuse;
  auto a = s->current(d);
  if (!a) co_return a.error();
  auto values = co_await read_attributes(s, *a, lcb, lcb_attributes);
  if (!values) co_return values.error();
  lcb_values out;
  for (std::size_t i = 0; i < lcb_attributes.size(); ++i) {
    const auto& v = (*values)[i];
    if (!v) continue;
    std::error_code ec;
    switch (i) {
      case 0: ec = set_from(out.log_ena, [&] { return to_bool(*v); }); break;
      case 1: ec = set_from(out.log_ref, [&] { return to_string(*v); }); break;
      case 2: ec = set_from(out.dat_set, [&] { return to_string(*v); }); break;
      case 3: ec = set_from(out.old_entr_tm, [&] { return to_entry_time(*v); }); break;
      case 4: ec = set_from(out.new_entr_tm, [&] { return to_entry_time(*v); }); break;
      case 5: ec = set_from(out.old_ent, [&] { return to_entry_id(*v); }); break;
      case 6: ec = set_from(out.new_ent, [&] { return to_entry_id(*v); }); break;
      case 7: ec = set_from(out.trg_ops, [&] { return model::trigger_conditions::from_mms(*v); }); break;
      default: ec = set_from(out.intg_pd, [&] { return to_u32(*v); }); break;
    }
    if (ec) co_return ec;
  }
  co_return out;
}

awaitable<result<void>> set_lcb_values_op(std::shared_ptr<client_state> s, error_details* d,
                                          model::object_reference lcb, lcb_settings w) {
  if (!is_cb(lcb, fc::LG)) co_return misuse;
  std::vector<std::pair<std::string_view, mms::data>> writes;
  if (w.dat_set) {
    auto text = model::to_mms_data_set_reference(*w.dat_set, s->limits);
    if (!text) co_return text.error();
    writes.emplace_back("DatSet", mms::data::visible_string(*text));
  }
  if (w.trg_ops) writes.emplace_back("TrgOps", w.trg_ops->to_mms());
  if (w.intg_pd) writes.emplace_back("IntgPd", mms::data::unsigned_integer(*w.intg_pd));
  if (w.log_ena) writes.emplace_back("LogEna", mms::data::boolean(*w.log_ena));
  auto a = s->current(d);
  if (!a) co_return a.error();
  for (auto& [name, value] : writes) {
    auto r = co_await write_attribute(s, *a, lcb, name, std::move(value));
    if (!r) co_return r;
  }
  co_return result<void>{};
}

awaitable<result<std::vector<log_entry>>> query_log_by_time_op(
    std::shared_ptr<client_state> s, error_details* d, model::object_reference log,
    std::optional<model::entry_time> start, std::optional<model::entry_time> stop) {
  mms::read_journal_request req;
  req.starting_time = start;
  req.ending_time = stop;
  co_return co_await query(std::move(s), d, std::move(log), req, std::nullopt);
}

awaitable<result<std::vector<log_entry>>> query_log_after_op(std::shared_ptr<client_state> s,
                                                             error_details* d,
                                                             model::object_reference log,
                                                             model::entry_time time,
                                                             model::entry_id entry) {
  mms::read_journal_request req;
  req.start_after = mms::journal_start_after{time, {}};
  co_return co_await query(std::move(s), d, std::move(log), req, entry);
}

awaitable<result<std::uint32_t>> get_log_status_op(std::shared_ptr<client_state> s, error_details* d,
                                                   model::object_reference log) {
  auto name = journal_name(log);
  if (!name) co_return name.error();
  auto a = s->current(d);
  if (!a) co_return a.error();
  auto r = co_await call_on(*a, mms::report_journal_status_request{name->view()});
  if (!r) co_return r.error();
  const auto* st = response_as<mms::report_journal_status_response>(*r);
  if (st == nullptr) co_return violation;
  co_return st->current_entries;
}

// --- files

awaitable<result<std::vector<file_entry>>> get_file_directory_op(std::shared_ptr<client_state> s,
                                                                 error_details* d,
                                                                 std::string path) {
  auto a = s->current(d);
  if (!a) co_return a.error();
  const std::array<std::string_view, 1> spec{path};
  std::string last;
  std::array<std::string_view, 1> after{};
  std::vector<file_entry> out;
  for (;;) {
    mms::file_directory_request req;
    if (!path.empty()) req.file_specification = mms::list_view<std::string_view>(spec);
    if (!out.empty()) {
      last = out.back().name;
      after[0] = last;
      req.continue_after = mms::list_view<std::string_view>(after);
    }
    auto r = co_await call_on(*a, req);
    if (!r) co_return r.error();
    const auto* dir = response_as<mms::file_directory_response>(*r);
    if (dir == nullptr) co_return violation;
    std::size_t n = 0;
    for (const auto e : dir->entries) {
      file_entry f;
      f.name = join(e.file_name);
      f.size = e.attributes.size;
      if (e.attributes.last_modified) f.last_modified = parse_generalized_time(*e.attributes.last_modified);
      out.push_back(std::move(f));
      ++n;
    }
    if (!dir->more_follows) break;
    if (n == 0) co_return violation;
  }
  co_return out;
}

awaitable<result<std::uint64_t>> get_file_stream_op(std::shared_ptr<client_state> s,
                                                    error_details* d, std::string name,
                                                    std::function<void(byte_buffer)> on_chunk) {
  if (name.empty()) co_return misuse;
  auto a = s->current(d);
  if (!a) co_return a.error();
  const std::array<std::string_view, 1> file{name};
  auto opened = co_await call_on(*a, mms::file_open_request{file, 0});
  if (!opened) co_return opened.error();
  const auto* o = response_as<mms::file_open_response>(*opened);
  if (o == nullptr) co_return violation;
  const auto frsm = o->frsm_id;
  std::uint64_t total = 0;
  std::error_code failure;
  for (;;) {
    auto r = co_await call_on(*a, mms::file_read_request{frsm});
    if (!r) {
      failure = r.error();
      break;
    }
    const auto* chunk = response_as<mms::file_read_response>(*r);
    if (chunk == nullptr) {
      failure = violation;
      break;
    }
    total += chunk->data.size();
    const bool more = chunk->more_follows;
    if (!chunk->data.empty() && on_chunk) on_chunk(byte_buffer(chunk->data.begin(), chunk->data.end()));
    if (!more) break;
    if (chunk->data.empty()) {
      failure = violation;  // would loop
      break;
    }
  }
  auto closed = co_await call_on(*a, mms::file_close_request{frsm});
  if (failure) co_return failure;
  if (!closed) co_return closed.error();
  co_return total;
}

awaitable<result<byte_buffer>> get_file_op(std::shared_ptr<client_state> s, error_details* d,
                                           std::string name) {
  auto content = std::make_shared<byte_buffer>();
  auto r = co_await get_file_stream_op(std::move(s), d, std::move(name), [content](byte_buffer c) {
    content->insert(content->end(), c.begin(), c.end());
  });
  if (!r) co_return r.error();
  co_return std::move(*content);
}

file_source memory_source(byte_buffer content) {
  file_source source;
  source.size = content.size();
  source.read = [c = std::make_shared<const byte_buffer>(std::move(content))](
                    std::uint64_t offset, std::span<std::uint8_t> out) -> result<std::size_t> {
    if (offset >= c->size()) return std::size_t{0};
    const auto n = std::min<std::size_t>(out.size(), c->size() - static_cast<std::size_t>(offset));
    std::copy_n(c->begin() + static_cast<std::ptrdiff_t>(offset), n, out.begin());
    return n;
  };
  return source;
}

awaitable<result<void>> set_file_op(std::shared_ptr<client_state> s, error_details* d,
                                    std::string name, file_source source) {
  if (name.empty() || !source.read) co_return misuse;
  if (source.size > std::numeric_limits<std::uint32_t>::max()) {
    co_return openiec61850::errc::value_out_of_range;
  }
  auto a = s->current(d);
  if (!a) co_return a.error();
  auto file = std::make_shared<offered_file>();
  file->name = source.name.empty() ? name : source.name;
  file->source = std::move(source);
  if (!s->offered.emplace(file->name, file).second) co_return misuse;
  // Withdrawn on every way out, cancellation included.
  struct withdraw {
    client_state* s;
    offered_file* file;
    ~withdraw() {
      s->offered.erase(file->name);
      std::erase_if(s->served, [&](const auto& e) { return e.second.file.get() == file; });
    }
  } guard{s.get(), file.get()};

  const std::array<std::string_view, 1> from{file->name};
  const std::array<std::string_view, 1> to{name};
  auto r = co_await call_on(*a, mms::obtain_file_request{std::nullopt, from, to},
                            s->options.file_transfer_timeout);
  if (!r) co_return r.error();
  if (response_as<mms::obtain_file_response>(*r) == nullptr) co_return violation;
  co_return result<void>{};
}

namespace {

// Largest FileRead answer, and files the server may hold open at once: it decides how much of
// this side's memory and time a set_file() costs.
constexpr std::size_t max_served_chunk = 65000;
constexpr std::size_t max_served_files = 8;

mms::service_error file_error(std::int64_t code) { return {mms::error_class::file, code}; }

awaitable<void> answer_file_open(std::shared_ptr<client_state> s, association::incoming_request req) {
  namespace ec = mms::error_code;
  const auto& r = std::get<mms::file_open_request>(req.service());
  const auto it = s->offered.find(join(r.file_name));
  if (it == s->offered.end()) {
    (void)co_await req.respond_error(file_error(ec::file::file_non_existent));
    co_return;
  }
  const auto size = it->second->source.size;
  if (r.initial_position > size) {
    (void)co_await req.respond_error(file_error(ec::file::position_invalid));
    co_return;
  }
  if (s->served.size() >= max_served_files) {
    (void)co_await req.respond_error({mms::error_class::resource, ec::resource::capability_unavailable});
    co_return;
  }
  std::int32_t id = s->next_frsm;
  while (s->served.contains(id)) id = id == std::numeric_limits<std::int32_t>::max() ? 1 : id + 1;
  s->next_frsm = id == std::numeric_limits<std::int32_t>::max() ? 1 : id + 1;
  s->served.emplace(id, served_file{it->second, r.initial_position});
  mms::file_open_response resp;
  resp.frsm_id = id;
  resp.attributes.size = static_cast<std::uint32_t>(size);
  (void)co_await req.respond(resp);
}

awaitable<void> answer_file_read(std::shared_ptr<client_state> s, association::incoming_request req) {
  const auto it = s->served.find(std::get<mms::file_read_request>(req.service()).frsm_id);
  if (it == s->served.end() || !s->assoc) {
    (void)co_await req.respond_error(file_error(mms::error_code::file::other));
    co_return;
  }
  auto& f = it->second;
  const auto limit = s->assoc->info().negotiated.local_detail_called;
  std::size_t chunk = max_served_chunk;
  if (limit && *limit > 0) {
    chunk = std::min(chunk, std::max<std::size_t>(static_cast<std::size_t>(*limit), 128) - 32);
  }
  chunk = static_cast<std::size_t>(std::min<std::uint64_t>(chunk, f.file->source.size - f.position));
  byte_buffer data(chunk);
  auto n = data.empty() ? result<std::size_t>(std::size_t{0}) : f.file->source.read(f.position, data);
  // A source shorter than announced is a failure, not an end of file.
  if (!n || *n > chunk || (*n == 0 && chunk > 0)) {
    (void)co_await req.respond_error(file_error(mms::error_code::file::other));
    co_return;
  }
  data.resize(*n);
  f.position += *n;
  (void)co_await req.respond(mms::file_read_response{data, f.position < f.file->source.size});
}

awaitable<void> answer_file_close(std::shared_ptr<client_state> s, association::incoming_request req) {
  if (s->served.erase(std::get<mms::file_close_request>(req.service()).frsm_id) == 0) {
    (void)co_await req.respond_error(file_error(mms::error_code::file::other));
  } else {
    (void)co_await req.respond(mms::file_close_response{});
  }
}

awaitable<void> answer_unrecognized(association::incoming_request req) {
  (void)co_await req.reject(mms::reject_code::confirmed_request::unrecognized_service);
}

}  // namespace

void serve_request(const std::shared_ptr<client_state>& s, association::incoming_request req) {
  const auto& service = req.service();
  auto answer = [&]() -> awaitable<void> {
    if (std::holds_alternative<mms::file_open_request>(service)) return answer_file_open(s, std::move(req));
    if (std::holds_alternative<mms::file_read_request>(service)) return answer_file_read(s, std::move(req));
    if (std::holds_alternative<mms::file_close_request>(service)) return answer_file_close(s, std::move(req));
    return answer_unrecognized(std::move(req));
  };
  asio::co_spawn(s->strand, answer(), asio::detached);
}

awaitable<result<void>> delete_file_op(std::shared_ptr<client_state> s, error_details* d,
                                       std::string name) {
  if (name.empty()) co_return misuse;
  auto a = s->current(d);
  if (!a) co_return a.error();
  const std::array<std::string_view, 1> file{name};
  auto r = co_await call_on(*a, mms::file_delete_request{file});
  if (!r) co_return r.error();
  if (response_as<mms::file_delete_response>(*r) == nullptr) co_return violation;
  co_return result<void>{};
}

awaitable<result<void>> rename_file_op(std::shared_ptr<client_state> s, error_details* d,
                                       std::string from, std::string to) {
  if (from.empty() || to.empty()) co_return misuse;
  auto a = s->current(d);
  if (!a) co_return a.error();
  const std::array<std::string_view, 1> current{from};
  const std::array<std::string_view, 1> next{to};
  auto r = co_await call_on(*a, mms::file_rename_request{current, next});
  if (!r) co_return r.error();
  if (response_as<mms::file_rename_response>(*r) == nullptr) co_return violation;
  co_return result<void>{};
}

// --- GoCBs

namespace {
constexpr std::array<std::string_view, 9> gocb_attributes{
    "GoEna", "GoID", "DatSet", "ConfRev", "NdsCom", "DstAddress", "MinTime", "MaxTime", "FixedOffs"};

result<goose_address> to_goose_address(const mms::data& v) {
  const auto c = v.elements();
  if (v.type() != mms::data_type::structure || c.size() < 4) return err(errc::type_mismatch);
  goose_address out;
  auto mac = to_bytes(c[0]);
  auto prio = to_u8(c[1]);
  auto vid = to_uint64(c[2]);
  auto app = to_uint64(c[3]);
  if (!mac || !prio || !vid || !app || *vid > 0xFFFF || *app > 0xFFFF) return err(errc::type_mismatch);
  out.mac = std::move(*mac);
  out.priority = *prio;
  out.vid = static_cast<std::uint16_t>(*vid);
  out.app_id = static_cast<std::uint16_t>(*app);
  return out;
}
}  // namespace

awaitable<result<gocb_values>> get_gocb_values_op(std::shared_ptr<client_state> s, error_details* d,
                                                  model::object_reference gocb) {
  if (!is_cb(gocb, fc::GO)) co_return misuse;
  auto a = s->current(d);
  if (!a) co_return a.error();
  auto values = co_await read_attributes(s, *a, gocb, gocb_attributes);
  if (!values) co_return values.error();
  gocb_values out;
  for (std::size_t i = 0; i < gocb_attributes.size(); ++i) {
    const auto& v = (*values)[i];
    if (!v) continue;
    std::error_code ec;
    switch (i) {
      case 0: ec = set_from(out.go_ena, [&] { return to_bool(*v); }); break;
      case 1: ec = set_from(out.go_id, [&] { return to_string(*v); }); break;
      case 2: ec = set_from(out.dat_set, [&] { return to_string(*v); }); break;
      case 3: ec = set_from(out.conf_rev, [&] { return to_u32(*v); }); break;
      case 4: ec = set_from(out.nds_com, [&] { return to_bool(*v); }); break;
      case 5: ec = set_from(out.dst_address, [&] { return to_goose_address(*v); }); break;
      case 6: ec = set_from(out.min_time, [&] { return to_u32(*v); }); break;
      case 7: ec = set_from(out.max_time, [&] { return to_u32(*v); }); break;
      default: ec = set_from(out.fixed_offs, [&] { return to_bool(*v); }); break;
    }
    if (ec) co_return ec;
  }
  co_return out;
}

awaitable<result<void>> set_gocb_values_op(std::shared_ptr<client_state> s, error_details* d,
                                           model::object_reference gocb, gocb_settings w) {
  if (!is_cb(gocb, fc::GO)) co_return misuse;
  std::vector<std::pair<std::string_view, mms::data>> writes;
  if (w.go_id) writes.emplace_back("GoID", mms::data::visible_string(*w.go_id));
  if (w.dat_set) {
    auto text = model::to_mms_data_set_reference(*w.dat_set, s->limits);
    if (!text) co_return text.error();
    writes.emplace_back("DatSet", mms::data::visible_string(*text));
  }
  if (w.go_ena) writes.emplace_back("GoEna", mms::data::boolean(*w.go_ena));
  auto a = s->current(d);
  if (!a) co_return a.error();
  for (auto& [name, value] : writes) {
    auto r = co_await write_attribute(s, *a, gocb, name, std::move(value));
    if (!r) co_return r;
  }
  co_return result<void>{};
}

}  // namespace openiec61850::client::detail
