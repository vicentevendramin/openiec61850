#pragma once

#include <charconv>
#include <cstdint>
#include <optional>
#include <string_view>
#include <system_error>

// Small text helpers shared by the SCL sources.

namespace openiec61850::scl::detail {

[[nodiscard]] constexpr bool is_space(char c) noexcept {
  return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

[[nodiscard]] constexpr std::string_view trim(std::string_view s) noexcept {
  while (!s.empty() && is_space(s.front())) s.remove_prefix(1);
  while (!s.empty() && is_space(s.back())) s.remove_suffix(1);
  return s;
}

// Decimal integer of the whole (trimmed) text; a leading '+' is accepted.
template <typename T>
[[nodiscard]] std::optional<T> parse_integer(std::string_view s) noexcept {
  s = trim(s);
  if (!s.empty() && s.front() == '+') s.remove_prefix(1);
  if (s.empty()) return std::nullopt;
  T v{};
  const auto* end = s.data() + s.size();
  const auto [p, ec] = std::from_chars(s.data(), end, v);
  if (ec != std::errc{} || p != end) return std::nullopt;
  return v;
}

[[nodiscard]] inline std::optional<std::uint32_t> parse_hex_u32(std::string_view s) noexcept {
  s = trim(s);
  if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s.remove_prefix(2);
  if (s.empty()) return std::nullopt;
  std::uint32_t v = 0;
  const auto* end = s.data() + s.size();
  const auto [p, ec] = std::from_chars(s.data(), end, v, 16);
  if (ec != std::errc{} || p != end) return std::nullopt;
  return v;
}

// xs:boolean: "true", "false", "1", "0".
[[nodiscard]] constexpr std::optional<bool> parse_bool(std::string_view s) noexcept {
  s = trim(s);
  if (s == "true" || s == "1") return true;
  if (s == "false" || s == "0") return false;
  return std::nullopt;
}

[[nodiscard]] constexpr int hex_digit(char c) noexcept {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

}  // namespace openiec61850::scl::detail
