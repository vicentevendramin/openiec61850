#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

// Problems found while loading or instantiating an SCL file. Loading and instantiation collect
// every problem instead of stopping at the first one; the strict/lenient options decide whether
// errors make the whole operation fail.

namespace openiec61850::scl {

enum class severity : std::uint8_t {
  warning,  // the file is usable; the construct was ignored or a default was applied
  error,    // the construct is unusable and was dropped (lenient) or the operation failed (strict)
};

enum class diagnostic_code : std::uint16_t {
  xml_syntax,             // not well-formed XML
  not_scl,                // root element is not SCL
  limit_exceeded,         // input size, nesting depth or instantiated node count limit
  missing_attribute,      // required attribute absent or empty
  invalid_attribute,      // attribute value does not match its type
  invalid_name,           // name is not a valid identifier / LN name
  duplicate_name,         // two siblings (or two types) share a name / id
  unknown_type,           // lnType / type reference does not resolve
  circular_type,          // a DOType or DAType contains itself
  unknown_btype,          // bType value not defined by IEC 61850-6
  unknown_fc,             // fc value not defined by IEC 61850-7-2
  type_mismatch,          // e.g. LN class differs from LNodeType, Struct DA without type
  unresolved_reference,   // dataset, FCDA, DOI/DAI, ConnectedAP, ServerAt not found
  invalid_value,          // Val text does not match the attribute type / enumeration
  not_found,              // requested IED / access point / server absent
};

[[nodiscard]] std::string_view to_string(diagnostic_code c) noexcept;
[[nodiscard]] std::string_view to_string(severity s) noexcept;

struct diagnostic {
  severity level = severity::error;
  diagnostic_code code = diagnostic_code::xml_syntax;
  std::uint32_t line = 0;  // 1-based line in the SCL text; 0 when unknown
  std::string message;
};

// "line 12: error: unknown_type: ..." (without line when unknown).
[[nodiscard]] std::string to_string(const diagnostic& d);

class diagnostics {
 public:
  void add(severity level, diagnostic_code code, std::uint32_t line, std::string message);
  void warning(diagnostic_code code, std::uint32_t line, std::string message) {
    add(severity::warning, code, line, std::move(message));
  }
  void error(diagnostic_code code, std::uint32_t line, std::string message) {
    add(severity::error, code, line, std::move(message));
  }

  [[nodiscard]] const std::vector<diagnostic>& items() const noexcept { return items_; }
  [[nodiscard]] auto begin() const noexcept { return items_.begin(); }
  [[nodiscard]] auto end() const noexcept { return items_.end(); }
  [[nodiscard]] std::size_t size() const noexcept { return items_.size(); }
  [[nodiscard]] bool empty() const noexcept { return items_.empty(); }
  [[nodiscard]] std::size_t error_count() const noexcept { return errors_; }
  [[nodiscard]] std::size_t warning_count() const noexcept { return warnings_; }
  [[nodiscard]] bool has_errors() const noexcept { return errors_ != 0; }
  // Number of diagnostics with the given code.
  [[nodiscard]] std::size_t count(diagnostic_code code) const noexcept;
  [[nodiscard]] std::size_t count(diagnostic_code code, severity level) const noexcept;
  // Appends the diagnostics of `other`.
  void merge(const diagnostics& other);
  // Diagnostics beyond this number are counted but not stored (0 = unlimited).
  void set_limit(std::size_t max_items) noexcept { limit_ = max_items; }
  [[nodiscard]] std::size_t dropped() const noexcept { return dropped_; }

 private:
  std::vector<diagnostic> items_;
  std::size_t errors_ = 0;
  std::size_t warnings_ = 0;
  std::size_t limit_ = 0;
  std::size_t dropped_ = 0;
};

}  // namespace openiec61850::scl
