// MMS file services over the server's file_store (IEC 61850-8-1 §23, ISO 9506-2 Annex C).
//
// A FileName (SEQUENCE OF GraphicString) is joined with '/' and normalised
// (normalize_file_path), so names are confined to the store. FileOpen creates a file read state
// machine (FRSM) of the association; FileRead returns the next chunk (sized to the negotiated
// PDU size) with moreFollows until the end; FileClose releases it. FileDirectory lists a
// directory recursively (or one file), in name order, paged by the PDU size with continueAfter.
// Open files cannot be deleted or renamed (file-busy).

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <limits>
#include <string>

#include "detail.hpp"

namespace openiec61850::server::detail {

namespace {

namespace ec = mms::error_code;

result<std::string> join(const mms::list_view<std::string_view>& name) {
  std::string text;
  bool first = true;
  for (const auto part : name) {
    if (!first) text.push_back('/');
    text.append(part);
    first = false;
  }
  return normalize_file_path(text);
}

void fail(reply& out, std::error_code e) {
  std::int64_t code = ec::file::other;
  if (e == file_errc::not_found) code = ec::file::file_non_existent;
  if (e == file_errc::access_denied) code = ec::file::file_access_denied;
  if (e == file_errc::exists) code = ec::file::duplicate_filename;
  if (e == file_errc::invalid_name) code = ec::file::filename_syntax_error;
  if (e == file_errc::busy) code = ec::file::file_busy;
  if (e == file_errc::no_space) code = ec::file::insufficient_space_in_filestore;
  out.fail(mms::error_class::file, code);
}

std::string generalized_time(std::chrono::system_clock::time_point t) {
  const std::time_t tt = std::chrono::system_clock::to_time_t(t);
  std::tm tm{};
  gmtime_r(&tt, &tm);
  char buf[32];
  std::snprintf(buf, sizeof buf, "%04d%02d%02d%02d%02d%02dZ", tm.tm_year + 1900, tm.tm_mon + 1,
                tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
  return buf;
}

bool is_open(const server_state& st, std::string_view path) {
  for (const auto& [id, s] : st.sessions) {
    for (const auto& [frsm, f] : s->files) {
      if (f.path == path) return true;
    }
  }
  return false;
}

std::uint32_t clamp32(std::uint64_t v) {
  return static_cast<std::uint32_t>(std::min<std::uint64_t>(v, std::numeric_limits<std::uint32_t>::max()));
}

}  // namespace

void server_state::dispatch_ext(session& s, const mms::file_open_request& r, reply& out) {
  if (!options.files) return out.reject(mms::reject_code::confirmed_request::unrecognized_service);
  auto path = join(r.file_name);
  if (!path) return fail(out, path.error());
  if (s.files.size() >= options.max_open_files) {
    return out.fail(mms::error_class::resource, ec::resource::capability_unavailable);
  }
  auto info = options.files->stat(*path);
  if (!info) return fail(out, info.error());
  if (r.initial_position > info->size) {
    return out.fail(mms::error_class::file, ec::file::position_invalid);
  }
  std::int32_t id = s.next_frsm;
  while (s.files.contains(id)) id = id == std::numeric_limits<std::int32_t>::max() ? 1 : id + 1;
  s.next_frsm = id == std::numeric_limits<std::int32_t>::max() ? 1 : id + 1;
  s.files.emplace(id, open_file{*path, r.initial_position, info->size});
  mms::file_open_response resp;
  resp.frsm_id = id;
  resp.attributes.size = clamp32(info->size);
  if (info->last_modified) {
    out.strings.push_back(generalized_time(*info->last_modified));
    resp.attributes.last_modified = out.strings.back();
  }
  out.response = resp;
}

void server_state::dispatch_ext(session& s, const mms::file_read_request& r, reply& out) {
  if (!options.files) return out.reject(mms::reject_code::confirmed_request::unrecognized_service);
  const auto it = s.files.find(r.frsm_id);
  if (it == s.files.end()) return out.fail(mms::error_class::file, ec::file::other);
  auto& f = it->second;
  const std::size_t chunk = s.max_pdu > 0 ? std::max<std::size_t>(s.max_pdu, 128) - 32 : 65000;
  out.bytes.resize(chunk);
  auto n = options.files->read(f.path, f.position, out.bytes);
  if (!n) return fail(out, n.error());
  out.bytes.resize(*n);
  f.position += *n;
  const bool more = *n > 0 && f.position < f.size;
  out.response = mms::file_read_response{out.bytes, more};
}

void server_state::dispatch_ext(session& s, const mms::file_close_request& r, reply& out) {
  if (!options.files) return out.reject(mms::reject_code::confirmed_request::unrecognized_service);
  if (s.files.erase(r.frsm_id) == 0) return out.fail(mms::error_class::file, ec::file::other);
  out.response = mms::file_close_response{};
}

void server_state::dispatch_ext(session&, const mms::file_rename_request& r, reply& out) {
  if (!options.files) return out.reject(mms::reject_code::confirmed_request::unrecognized_service);
  auto from = join(r.current_name);
  if (!from) return fail(out, from.error());
  auto to = join(r.new_name);
  if (!to) return fail(out, to.error());
  if (from->empty() || to->empty()) return fail(out, make_error_code(file_errc::invalid_name));
  if (is_open(*this, *from)) return fail(out, make_error_code(file_errc::busy));
  if (auto e = options.files->rename(*from, *to); !e) return fail(out, e.error());
  out.response = mms::file_rename_response{};
}

void server_state::dispatch_ext(session&, const mms::file_delete_request& r, reply& out) {
  if (!options.files) return out.reject(mms::reject_code::confirmed_request::unrecognized_service);
  auto path = join(r.file_name);
  if (!path) return fail(out, path.error());
  if (path->empty()) return fail(out, make_error_code(file_errc::invalid_name));
  if (is_open(*this, *path)) return fail(out, make_error_code(file_errc::busy));
  if (auto e = options.files->remove(*path); !e) return fail(out, e.error());
  out.response = mms::file_delete_response{};
}

void server_state::dispatch_ext(session& s, const mms::file_directory_request& r, reply& out) {
  if (!options.files) return out.reject(mms::reject_code::confirmed_request::unrecognized_service);
  std::string spec;
  if (r.file_specification) {
    std::string text;
    bool first = true;
    for (const auto part : *r.file_specification) {
      if (!first) text.push_back('/');
      text.append(part);
      first = false;
    }
    // A trailing "*" wildcard lists its directory.
    if (text == "*" || text.ends_with("/*")) text.resize(text.size() - 1);
    auto n = normalize_file_path(text);
    if (!n) return fail(out, n.error());
    spec = std::move(*n);
  }
  std::optional<std::string> after;
  if (r.continue_after) {
    auto n = join(*r.continue_after);
    if (!n) return fail(out, n.error());
    after = std::move(*n);
  }
  auto list = options.files->list(spec);
  if (!list) return fail(out, list.error());
  const std::size_t budget =
      s.max_pdu > 128 ? s.max_pdu - 48 : std::numeric_limits<std::size_t>::max();
  std::size_t used = 0;
  bool more = false;
  for (const auto& f : *list) {
    if (after && f.name <= *after) continue;
    std::string modified;
    if (f.last_modified) modified = generalized_time(*f.last_modified);
    const std::size_t cost = f.name.size() + modified.size() + 24;
    if (!out.directory.empty() && used + cost > budget) {
      more = true;
      break;
    }
    used += cost;
    out.strings.push_back(f.name);
    out.file_names.push_back({out.strings.back()});
    mms::directory_entry e;
    e.file_name = out.file_names.back();
    e.attributes.size = clamp32(f.size);
    if (f.last_modified) {
      out.strings.push_back(std::move(modified));
      e.attributes.last_modified = out.strings.back();
    }
    out.directory.push_back(e);
  }
  out.response = mms::file_directory_response{out.directory, more};
}

}  // namespace openiec61850::server::detail
