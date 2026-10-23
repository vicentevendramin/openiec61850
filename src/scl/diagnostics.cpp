#include "openiec61850/scl/diagnostics.hpp"

#include <algorithm>

namespace openiec61850::scl {

std::string_view to_string(diagnostic_code c) noexcept {
  switch (c) {
    case diagnostic_code::xml_syntax: return "xml_syntax";
    case diagnostic_code::not_scl: return "not_scl";
    case diagnostic_code::limit_exceeded: return "limit_exceeded";
    case diagnostic_code::missing_attribute: return "missing_attribute";
    case diagnostic_code::invalid_attribute: return "invalid_attribute";
    case diagnostic_code::invalid_name: return "invalid_name";
    case diagnostic_code::duplicate_name: return "duplicate_name";
    case diagnostic_code::unknown_type: return "unknown_type";
    case diagnostic_code::circular_type: return "circular_type";
    case diagnostic_code::unknown_btype: return "unknown_btype";
    case diagnostic_code::unknown_fc: return "unknown_fc";
    case diagnostic_code::type_mismatch: return "type_mismatch";
    case diagnostic_code::unresolved_reference: return "unresolved_reference";
    case diagnostic_code::invalid_value: return "invalid_value";
    case diagnostic_code::not_found: return "not_found";
  }
  return "unknown";
}

std::string_view to_string(severity s) noexcept {
  return s == severity::warning ? "warning" : "error";
}

std::string to_string(const diagnostic& d) {
  std::string out;
  if (d.line != 0) {
    out += "line ";
    out += std::to_string(d.line);
    out += ": ";
  }
  out += to_string(d.level);
  out += ": ";
  out += to_string(d.code);
  out += ": ";
  out += d.message;
  return out;
}

void diagnostics::add(severity level, diagnostic_code code, std::uint32_t line,
                      std::string message) {
  if (level == severity::error) {
    ++errors_;
  } else {
    ++warnings_;
  }
  if (limit_ != 0 && items_.size() >= limit_) {
    ++dropped_;
    return;
  }
  items_.push_back({level, code, line, std::move(message)});
}

std::size_t diagnostics::count(diagnostic_code code) const noexcept {
  return static_cast<std::size_t>(
      std::count_if(items_.begin(), items_.end(), [&](const auto& d) { return d.code == code; }));
}

std::size_t diagnostics::count(diagnostic_code code, severity level) const noexcept {
  return static_cast<std::size_t>(std::count_if(items_.begin(), items_.end(), [&](const auto& d) {
    return d.code == code && d.level == level;
  }));
}

void diagnostics::merge(const diagnostics& other) {
  for (const auto& d : other.items_) add(d.level, d.code, d.line, d.message);
  dropped_ += other.dropped_;
}

}  // namespace openiec61850::scl
