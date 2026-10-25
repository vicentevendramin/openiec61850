// File stores of the server (see openiec61850/server/files.hpp).

#include "openiec61850/server/files.hpp"

#include <algorithm>
#include <fstream>

namespace openiec61850::server {

namespace {

class file_category final : public std::error_category {
 public:
  const char* name() const noexcept override { return "openiec61850.server.file"; }
  std::string message(int ev) const override {
    switch (static_cast<file_errc>(ev)) {
      case file_errc::ok: return "success";
      case file_errc::not_found: return "file not found";
      case file_errc::access_denied: return "file access denied";
      case file_errc::exists: return "file already exists";
      case file_errc::invalid_name: return "invalid file name";
      case file_errc::busy: return "file busy";
      case file_errc::no_space: return "insufficient space in the file store";
    }
    return "unknown file error";
  }
};

std::error_code ferr(file_errc e) { return make_error_code(e); }

// True when `name` equals `dir` or lies below it ("" is the root).
bool below(std::string_view name, std::string_view dir) {
  if (dir.empty()) return true;
  return name == dir || (name.size() > dir.size() && name.starts_with(dir) && name[dir.size()] == '/');
}

}  // namespace

const std::error_category& file_error_category() noexcept {
  static const file_category c;
  return c;
}

result<std::string> normalize_file_path(std::string_view path) {
  if (path.starts_with('/')) path.remove_prefix(1);
  if (path.ends_with('/')) path.remove_suffix(1);
  if (path.empty()) return std::string{};
  std::size_t from = 0;
  for (;;) {
    const auto p = path.find('/', from);
    const auto seg = path.substr(from, p == std::string_view::npos ? p : p - from);
    if (seg.empty() || seg == "." || seg == "..") return ferr(file_errc::invalid_name);
    if (p == std::string_view::npos) break;
    from = p + 1;
  }
  for (const char c : path) {
    const auto u = static_cast<unsigned char>(c);
    if (u < 0x20 || u == 0x7F || c == '\\' || c == ':') return ferr(file_errc::invalid_name);
  }
  return std::string(path);
}

// --- memory_file_store

result<void> memory_file_store::put(std::string_view path, byte_buffer content,
                                    std::optional<std::chrono::system_clock::time_point> modified) {
  auto p = normalize_file_path(path);
  if (!p) return p.error();
  if (p->empty()) return ferr(file_errc::invalid_name);
  const std::lock_guard lock(mutex_);
  files_.insert_or_assign(std::move(*p), entry{std::move(content), modified});
  return {};
}

std::optional<byte_buffer> memory_file_store::get(std::string_view path) const {
  auto p = normalize_file_path(path);
  if (!p) return std::nullopt;
  const std::lock_guard lock(mutex_);
  const auto it = files_.find(*p);
  if (it == files_.end()) return std::nullopt;
  return it->second.content;
}

result<std::vector<file_info>> memory_file_store::list(std::string_view directory) {
  auto d = normalize_file_path(directory);
  if (!d) return d.error();
  const std::lock_guard lock(mutex_);
  std::vector<file_info> out;
  for (const auto& [name, e] : files_) {
    if (below(name, *d)) out.push_back({name, e.content.size(), e.modified});
  }
  if (out.empty() && !d->empty()) return ferr(file_errc::not_found);
  return out;
}

result<file_info> memory_file_store::stat(std::string_view path) {
  const std::lock_guard lock(mutex_);
  const auto it = files_.find(path);
  if (it == files_.end()) return ferr(file_errc::not_found);
  return file_info{it->first, it->second.content.size(), it->second.modified};
}

result<std::size_t> memory_file_store::read(std::string_view path, std::uint64_t offset,
                                            std::span<std::uint8_t> out) {
  const std::lock_guard lock(mutex_);
  const auto it = files_.find(path);
  if (it == files_.end()) return ferr(file_errc::not_found);
  const auto& c = it->second.content;
  if (offset >= c.size()) return std::size_t{0};
  const auto n = std::min<std::size_t>(out.size(), c.size() - static_cast<std::size_t>(offset));
  std::copy_n(c.begin() + static_cast<std::ptrdiff_t>(offset), n, out.begin());
  return n;
}

result<void> memory_file_store::remove(std::string_view path) {
  const std::lock_guard lock(mutex_);
  const auto it = files_.find(path);
  if (it == files_.end()) return ferr(file_errc::not_found);
  files_.erase(it);
  return {};
}

result<void> memory_file_store::rename(std::string_view from, std::string_view to) {
  if (to.empty()) return ferr(file_errc::invalid_name);
  const std::lock_guard lock(mutex_);
  const auto it = files_.find(from);
  if (it == files_.end()) return ferr(file_errc::not_found);
  if (files_.contains(to)) return ferr(file_errc::exists);
  auto e = std::move(it->second);
  files_.erase(it);
  files_.emplace(std::string(to), std::move(e));
  return {};
}

// --- directory_file_store

namespace fs = std::filesystem;

namespace {

std::optional<std::chrono::system_clock::time_point> modified_of(const fs::path& p) {
  std::error_code ec;
  const auto t = fs::last_write_time(p, ec);
  if (ec) return std::nullopt;
  return std::chrono::time_point_cast<std::chrono::system_clock::duration>(std::chrono::file_clock::to_sys(t));
}

bool inside(const fs::path& root, const fs::path& p) {
  auto r = root.begin();
  auto q = p.begin();
  for (; r != root.end(); ++r, ++q) {
    if (q == p.end() || *r != *q) return false;
  }
  return true;
}

}  // namespace

directory_file_store::directory_file_store(fs::path canonical_root) : root_(std::move(canonical_root)) {}

result<std::shared_ptr<directory_file_store>> directory_file_store::open(const fs::path& root) {
  std::error_code ec;
  auto canonical = fs::canonical(root, ec);
  if (ec || !fs::is_directory(canonical, ec)) return openiec61850::errc::invalid_state;
  return std::make_shared<directory_file_store>(std::move(canonical));
}

result<fs::path> directory_file_store::resolve(std::string_view path, bool must_exist) const {
  auto n = normalize_file_path(path);
  if (!n) return n.error();
  const fs::path full = root_ / fs::path(*n);
  std::error_code ec;
  // weakly_canonical follows the symbolic links of the existing prefix.
  const auto real = fs::weakly_canonical(full, ec);
  if (ec || !inside(root_, real)) return ferr(file_errc::access_denied);
  if (must_exist) {
    const auto st = fs::status(real, ec);
    if (ec || !fs::exists(st)) return ferr(file_errc::not_found);
    if (!fs::is_regular_file(st)) return ferr(file_errc::access_denied);
  }
  return real;
}

result<std::vector<file_info>> directory_file_store::list(std::string_view directory) {
  auto base = resolve(directory, false);
  if (!base) return base.error();
  std::error_code ec;
  std::vector<file_info> out;
  auto add = [&](const fs::path& p) {
    std::error_code e2;
    const auto real = fs::weakly_canonical(p, e2);
    if (e2 || !inside(root_, real) || !fs::is_regular_file(real, e2)) return;
    const auto size = fs::file_size(real, e2);
    if (e2) return;
    out.push_back({p.lexically_relative(root_).generic_string(), size, modified_of(real)});
  };
  if (fs::is_regular_file(*base, ec)) {
    add(*base);
  } else if (fs::is_directory(*base, ec)) {
    for (fs::recursive_directory_iterator it(*base, fs::directory_options::skip_permission_denied, ec), end;
         !ec && it != end; it.increment(ec)) {
      if (it->is_symlink(ec) && it->is_directory(ec)) it.disable_recursion_pending();
      add(it->path());
    }
  } else {
    return ferr(file_errc::not_found);
  }
  std::sort(out.begin(), out.end(), [](const file_info& a, const file_info& b) { return a.name < b.name; });
  return out;
}

result<file_info> directory_file_store::stat(std::string_view path) {
  auto p = resolve(path, true);
  if (!p) return p.error();
  std::error_code ec;
  const auto size = fs::file_size(*p, ec);
  if (ec) return ferr(file_errc::access_denied);
  auto n = normalize_file_path(path);
  return file_info{std::move(*n), size, modified_of(*p)};
}

result<std::size_t> directory_file_store::read(std::string_view path, std::uint64_t offset,
                                               std::span<std::uint8_t> out) {
  auto p = resolve(path, true);
  if (!p) return p.error();
  std::ifstream in(*p, std::ios::binary);
  if (!in) return ferr(file_errc::access_denied);
  in.seekg(static_cast<std::streamoff>(offset));
  if (!in) return std::size_t{0};
  in.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(out.size()));
  return static_cast<std::size_t>(in.gcount());
}

result<void> directory_file_store::remove(std::string_view path) {
  auto p = resolve(path, true);
  if (!p) return p.error();
  std::error_code ec;
  if (!fs::remove(*p, ec) || ec) return ferr(file_errc::access_denied);
  return {};
}

result<void> directory_file_store::rename(std::string_view from, std::string_view to) {
  auto src = resolve(from, true);
  if (!src) return src.error();
  auto dst = resolve(to, false);
  if (!dst) return dst.error();
  if (dst->empty() || *dst == root_) return ferr(file_errc::invalid_name);
  std::error_code ec;
  if (fs::exists(*dst, ec)) return ferr(file_errc::exists);
  if (!fs::is_directory(dst->parent_path(), ec)) return ferr(file_errc::not_found);
  fs::rename(*src, *dst, ec);
  if (ec) return ferr(file_errc::access_denied);
  return {};
}

}  // namespace openiec61850::server
