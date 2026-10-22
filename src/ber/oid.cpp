#include "openiec61850/ber/oid.hpp"

#include <charconv>

namespace openiec61850::ber {

result<oid> oid::from_string(std::string_view text) {
  oid out;
  std::size_t pos = 0;
  for (;;) {
    const std::size_t dot = text.find('.', pos);
    const std::string_view arc = text.substr(pos, dot == std::string_view::npos ? text.size() - pos : dot - pos);
    if (arc.empty() || (arc.size() > 1 && arc[0] == '0')) return errc::malformed_encoding;
    std::uint32_t value = 0;
    const auto [end, ec] = std::from_chars(arc.data(), arc.data() + arc.size(), value);
    if (ec != std::errc{} || end != arc.data() + arc.size()) return errc::malformed_encoding;
    if (!out.push_back(value)) return errc::unsupported;
    if (dot == std::string_view::npos) break;
    pos = dot + 1;
  }
  if (!out.valid()) return errc::malformed_encoding;
  return out;
}

std::string oid::to_string() const {
  std::string s;
  s.reserve(size_ * 6);
  char digits[10];
  for (std::size_t i = 0; i < size_; ++i) {
    if (i != 0) s.push_back('.');
    const auto [end, ec] = std::to_chars(digits, digits + sizeof digits, arcs_[i]);
    s.append(digits, end);
  }
  return s;
}

}  // namespace openiec61850::ber
