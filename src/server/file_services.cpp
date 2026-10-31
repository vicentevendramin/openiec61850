// MMS file services over the server's file_store (IEC 61850-8-1 §23, ISO 9506-2 Annex C).
//
// A FileName (SEQUENCE OF GraphicString) is joined with '/' and normalised
// (normalize_file_path), so names are confined to the store. FileOpen creates a file read state
// machine (FRSM) of the association; FileRead returns the next chunk (sized to the negotiated
// PDU size) with moreFollows until the end; FileClose releases it. FileDirectory lists a
// directory recursively (or one file), in name order, paged by the PDU size with continueAfter.
// Open files cannot be deleted or renamed (file-busy).
//
// ObtainFile (ISO 9506-2 Annex C, SetFile) reverses the roles: the request stays outstanding while
// the server, on the same association, reads the file from the client with FileOpen, FileRead and
// FileClose. The file is held in memory, bounded by max_obtain_file_size and the size the client
// declared, and reaches the store only once complete.

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <limits>
#include <string>

#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>

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

std::int64_t file_error_code(std::error_code e) {
  if (e == file_errc::not_found) return ec::file::file_non_existent;
  if (e == file_errc::access_denied) return ec::file::file_access_denied;
  if (e == file_errc::exists) return ec::file::duplicate_filename;
  if (e == file_errc::invalid_name) return ec::file::filename_syntax_error;
  if (e == file_errc::busy) return ec::file::file_busy;
  if (e == file_errc::no_space) return ec::file::insufficient_space_in_filestore;
  return ec::file::other;
}

void fail(reply& out, std::error_code e) { out.fail(mms::error_class::file, file_error_code(e)); }

// A file error of ObtainFile, naming the file it is about (ObtainFile-Error).
mms::service_error obtain_error(std::int64_t code, bool source) {
  mms::service_error e(mms::error_class::file, code);
  if (source) {
    e.service_specific_info = mms::obtain_file_error::source_file;
  } else {
    e.service_specific_info = mms::obtain_file_error::destination_file;
  }
  return e;
}

void fail_obtain(reply& out, std::int64_t code, bool source) {
  out.type = reply::kind::error;
  out.error = obtain_error(code, source);
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

void server_state::dispatch_ext(session& s, const mms::obtain_file_request& r, reply& out) {
  if (!options.files || !options.files->writable() || options.max_obtain_file_size == 0 ||
      !options.on_obtain_file) {
    return out.reject(mms::reject_code::confirmed_request::unrecognized_service);
  }
  // The file comes from this client: a third party (sourceFileServer) is not reached.
  if (r.source_file_server) return fail_obtain(out, ec::file::other, true);
  std::string source;
  bool first = true;
  for (const auto part : r.source_file) {
    if (!first) source.push_back('/');
    source.append(part);
    first = false;
  }
  if (source.empty()) return fail_obtain(out, ec::file::filename_syntax_error, true);
  auto path = join(r.destination_file);
  if (!path) return fail_obtain(out, file_error_code(path.error()), false);
  if (path->empty()) return fail_obtain(out, ec::file::filename_syntax_error, false);
  if (s.obtaining) return out.fail(mms::error_class::resource, ec::resource::capability_unavailable);
  if (is_open(*this, *path) || std::ranges::find(incoming_files, *path) != incoming_files.end()) {
    return fail_obtain(out, ec::file::file_busy, false);
  }
  if (auto info = options.files->stat(*path); info) {
    return fail_obtain(out, ec::file::duplicate_filename, false);
  } else if (info.error() != file_errc::not_found) {
    return fail_obtain(out, file_error_code(info.error()), false);
  }
  {
    const auto refused = options.on_obtain_file({s.id, std::move(source), *path});
    if (refused && *refused != file_errc::ok) {
      return fail_obtain(out, file_error_code(*refused), false);
    }
  }
  out.type = reply::kind::deferred;
  out.destination = std::move(*path);
}

namespace {

// Copies the source file of the request from the client; an error names what the client hears.
struct pulled_file {
  byte_buffer content;
  std::optional<mms::service_error> error;
};

// What a reverse request failed with, as an error about the source file.
mms::service_error source_failure(const association::request_error& e) {
  if (e.service_error && e.service_error->cls == mms::error_class::file) {
    return obtain_error(e.service_error->code, true);
  }
  return obtain_error(ec::file::other, true);
}

asio::awaitable<pulled_file> pull_file(std::shared_ptr<server_state> st, std::shared_ptr<session> s,
                                       mms::list_view<std::string_view> source) {
  const auto started = clock::now();
  const auto budget = st->options.obtain_file_timeout;
  const auto default_timeout = st->options.association.request_timeout;
  // What is left of the transfer for one request; negative when it has run out.
  auto timeout = [&] {
    if (budget.count() <= 0) return default_timeout;
    const auto left =
        budget - std::chrono::duration_cast<std::chrono::milliseconds>(clock::now() - started);
    if (left.count() <= 0) return std::chrono::milliseconds(-1);
    return default_timeout.count() > 0 ? std::min(left, default_timeout) : left;
  };

  pulled_file out;
  auto opened = co_await s->assoc->request(mms::file_open_request{source, 0}, timeout());
  if (!opened) {
    out.error = source_failure(opened.failure());
    co_return out;
  }
  const auto* o = std::get_if<mms::file_open_response>(&opened->service());
  if (o == nullptr) {
    out.error = obtain_error(ec::file::other, true);
    co_return out;
  }
  const auto frsm = o->frsm_id;
  const std::uint64_t size = o->attributes.size;
  if (size > st->options.max_obtain_file_size) {
    out.error = obtain_error(ec::file::insufficient_space_in_filestore, false);
  }
  while (!out.error) {
    const auto left = timeout();
    if (left.count() < 0) {
      out.error = obtain_error(ec::file::other, true);
      break;
    }
    auto r = co_await s->assoc->request(mms::file_read_request{frsm}, left);
    if (!r) {
      out.error = source_failure(r.failure());
      break;
    }
    const auto* chunk = std::get_if<mms::file_read_response>(&r->service());
    // The declared size bounds the file: more data than that, a read that makes no progress or
    // a file that ends early are all failures of the client.
    if (chunk == nullptr || chunk->data.size() > size - out.content.size() ||
        (chunk->more_follows && chunk->data.empty()) ||
        (!chunk->more_follows && out.content.size() + chunk->data.size() != size)) {
      out.error = obtain_error(ec::file::other, true);
      break;
    }
    out.content.insert(out.content.end(), chunk->data.begin(), chunk->data.end());
    if (!chunk->more_follows) break;
  }
  (void)co_await s->assoc->request(mms::file_close_request{frsm});
  co_return out;
}

// Plain functions: GCC 13 crashes on these braced temporaries inside a coroutine.
void respond_done(session& s, association::incoming_request& req) {
  respond(s, req, mms::confirmed_response{req.invoke_id(), mms::obtain_file_response{}});
}

void respond_error(session& s, association::incoming_request& req, const mms::service_error& e) {
  respond(s, req, mms::confirmed_error{req.invoke_id(), std::nullopt, e});
}

asio::awaitable<void> obtain_file(std::shared_ptr<server_state> st, std::shared_ptr<session> s,
                                  association::incoming_request req, std::string destination) {
  const auto& r = std::get<mms::obtain_file_request>(req.service());
  auto pulled = co_await pull_file(st, s, r.source_file);
  if (!pulled.error && !s->closed) {
    if (auto w = st->options.files->write(destination, pulled.content); !w) {
      pulled.error = obtain_error(file_error_code(w.error()), false);
    }
  }
  if (pulled.error) {
    respond_error(*s, req, *pulled.error);
  } else {
    respond_done(*s, req);
  }
  s->obtaining = false;
  std::erase(st->incoming_files, destination);
  task_done(*st);
}

}  // namespace

void start_obtain_file(std::shared_ptr<server_state> st, std::shared_ptr<session> s,
                       association::incoming_request req, std::string destination) {
  s->obtaining = true;
  st->incoming_files.push_back(destination);
  st->live_tasks.fetch_add(1);
  auto strand = st->strand;
  asio::co_spawn(strand, obtain_file(std::move(st), std::move(s), std::move(req), std::move(destination)),
                 asio::detached);
}

}  // namespace openiec61850::server::detail
