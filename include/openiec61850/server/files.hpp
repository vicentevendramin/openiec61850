#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include "openiec61850/core/bytes.hpp"
#include "openiec61850/core/result.hpp"

// The server's file store (IEC 61850-7-2 §23 file transfer, mapped onto the MMS file services by
// IEC 61850-8-1 §23): a pluggable virtual filesystem behind FileOpen / FileRead / FileClose /
// FileDirectory / FileDelete / FileRename.
//
// Paths are relative to the store's root, '/'-separated, without empty, "." or ".." segments
// (see normalize_file_path()); the server normalises every name received from a client before
// calling the store. The calls run on the server strand: implementations must not block for long.

namespace openiec61850::server {

// Errors of a file store, mapped by the server onto MMS file errors (ISO 9506-2 §7.5.4):
// not_found -> file-non-existent, access_denied -> file-access-denied, exists ->
// duplicate-filename, invalid_name -> filename-syntax-error, busy -> file-busy, no_space ->
// insufficient-space-in-filestore. Other codes become file/other.
enum class file_errc {
  ok = 0,
  not_found,
  access_denied,
  exists,
  invalid_name,
  busy,
  no_space,
};

[[nodiscard]] const std::error_category& file_error_category() noexcept;

[[nodiscard]] inline std::error_code make_error_code(file_errc e) noexcept {
  return {static_cast<int>(e), file_error_category()};
}

struct file_info {
  std::string name;  // path relative to the root
  std::uint64_t size = 0;
  std::optional<std::chrono::system_clock::time_point> last_modified;

  friend bool operator==(const file_info&, const file_info&) = default;
};

class file_store {
 public:
  virtual ~file_store() = default;

  // The files below `directory` ("" for the whole store), recursively, or the single file when it
  // names one; sorted by name. file_errc::not_found when nothing has that name.
  [[nodiscard]] virtual result<std::vector<file_info>> list(std::string_view directory) = 0;
  [[nodiscard]] virtual result<file_info> stat(std::string_view path) = 0;
  // Reads up to out.size() octets at `offset`; returns the count (0 at the end of the file).
  [[nodiscard]] virtual result<std::size_t> read(std::string_view path, std::uint64_t offset,
                                                 std::span<std::uint8_t> out) = 0;
  [[nodiscard]] virtual result<void> remove(std::string_view path) = 0;
  // file_errc::exists when `to` exists.
  [[nodiscard]] virtual result<void> rename(std::string_view from, std::string_view to) = 0;
};

// "a//b/./c" style names are refused: the result has no leading '/', no empty, "." or ".."
// segment, no '\\', ':' or control character (file_errc::invalid_name). A leading '/' and one
// trailing '/' are removed; "" (or "/") is the root.
[[nodiscard]] result<std::string> normalize_file_path(std::string_view path);

// In-memory store, e.g. for tests or generated files. Thread-safe.
class memory_file_store final : public file_store {
 public:
  // Adds or replaces a file (the name is normalised; errors as normalize_file_path()).
  result<void> put(std::string_view path, byte_buffer content,
                   std::optional<std::chrono::system_clock::time_point> modified = std::nullopt);
  [[nodiscard]] std::optional<byte_buffer> get(std::string_view path) const;

  result<std::vector<file_info>> list(std::string_view directory) override;
  result<file_info> stat(std::string_view path) override;
  result<std::size_t> read(std::string_view path, std::uint64_t offset,
                           std::span<std::uint8_t> out) override;
  result<void> remove(std::string_view path) override;
  result<void> rename(std::string_view from, std::string_view to) override;

 private:
  struct entry {
    byte_buffer content;
    std::optional<std::chrono::system_clock::time_point> modified;
  };
  mutable std::mutex mutex_;
  std::map<std::string, entry, std::less<>> files_;
};

// A directory of the local filesystem. Every operation stays inside the root: names are
// normalised and the resolved path (symbolic links followed) must lie below the canonical root,
// otherwise file_errc::access_denied. Only regular files are listed, read, renamed or deleted.
class directory_file_store final : public file_store {
 public:
  // errc::invalid_state when `root` is not an existing directory.
  [[nodiscard]] static result<std::shared_ptr<directory_file_store>> open(
      const std::filesystem::path& root);

  [[nodiscard]] const std::filesystem::path& root() const noexcept { return root_; }

  result<std::vector<file_info>> list(std::string_view directory) override;
  result<file_info> stat(std::string_view path) override;
  result<std::size_t> read(std::string_view path, std::uint64_t offset,
                           std::span<std::uint8_t> out) override;
  result<void> remove(std::string_view path) override;
  result<void> rename(std::string_view from, std::string_view to) override;

  explicit directory_file_store(std::filesystem::path canonical_root);

 private:
  // The confined absolute path of a normalised name; `must_exist` checks it is a regular file.
  result<std::filesystem::path> resolve(std::string_view path, bool must_exist) const;

  std::filesystem::path root_;
};

}  // namespace openiec61850::server

template <>
struct std::is_error_code_enum<openiec61850::server::file_errc> : std::true_type {};
