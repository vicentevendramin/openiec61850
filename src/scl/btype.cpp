#include "openiec61850/scl/btype.hpp"

#include <array>
#include <charconv>
#include <cmath>
#include <limits>
#include <utility>

#include "text.hpp"

namespace openiec61850::scl {
namespace {

using model::basic_type;

struct fixed_btype {
  std::string_view name;
  btype_info info;
};

constexpr std::array<fixed_btype, 30> fixed{{
    {"BOOLEAN", {basic_type::boolean, 0, false}},
    {"INT8", {basic_type::int8, 0, false}},
    {"INT16", {basic_type::int16, 0, false}},
    {"INT24", {basic_type::int24, 0, false}},
    {"INT32", {basic_type::int32, 0, false}},
    {"INT64", {basic_type::int64, 0, false}},
    {"INT128", {basic_type::int128, 0, false}},
    {"INT8U", {basic_type::int8u, 0, false}},
    {"INT16U", {basic_type::int16u, 0, false}},
    {"INT24U", {basic_type::int24u, 0, false}},
    {"INT32U", {basic_type::int32u, 0, false}},
    {"FLOAT32", {basic_type::float32, 0, false}},
    {"FLOAT64", {basic_type::float64, 0, false}},
    {"Enum", {basic_type::enumerated, 0, false}},
    {"Dbpos", {basic_type::dbpos, 0, false}},
    {"Tcmd", {basic_type::tcmd, 0, false}},
    {"Check", {basic_type::check, 0, false}},
    {"Quality", {basic_type::quality, 0, false}},
    {"Timestamp", {basic_type::timestamp, 0, false}},
    {"EntryTime", {basic_type::entry_time, 0, false}},
    {"ObjRef", {basic_type::object_reference, 0, false}},
    {"EntryID", {basic_type::entry_id, 0, false}},
    {"TrgOps", {basic_type::trigger_conditions, 0, false}},
    {"OptFlds", {basic_type::optional_fields, 0, false}},
    {"Currency", {basic_type::visible_string, 3, false}},
    {"Struct", {std::nullopt, 0, true}},
    {"PhyComAddr", {std::nullopt, 0, false}},
    {"SvOptFlds", {std::nullopt, 0, false}},
    {"LogOptFlds", {std::nullopt, 0, false}},
    {"INT64U", {std::nullopt, 0, false}},
}};

std::optional<std::uint32_t> sized(std::string_view btype, std::string_view stem) {
  if (btype.size() <= stem.size() || btype.substr(0, stem.size()) != stem) return std::nullopt;
  const auto digits = btype.substr(stem.size());
  if (digits.front() == '0') return std::nullopt;
  for (char c : digits) {
    if (c < '0' || c > '9') return std::nullopt;
  }
  auto n = detail::parse_integer<std::uint32_t>(digits);
  if (!n || *n == 0) return std::nullopt;
  return n;
}

bool is_integer_text(std::string_view text) {
  auto t = detail::trim(text);
  if (!t.empty() && (t.front() == '+' || t.front() == '-')) t.remove_prefix(1);
  return !t.empty() && t.find_first_not_of("0123456789") == std::string_view::npos;
}

result<scalar> parse_signed(std::string_view text, unsigned bits) {
  const auto v = detail::parse_integer<std::int64_t>(text);
  // INT128 values beyond 64 bits are valid but not representable here.
  if (!v) return is_integer_text(text) ? errc::value_out_of_range : errc::malformed_encoding;
  if (bits < 64) {
    const auto hi = (std::int64_t{1} << (bits - 1)) - 1;
    if (*v < -hi - 1 || *v > hi) return errc::value_out_of_range;
  }
  return scalar{*v};
}

result<scalar> parse_unsigned(std::string_view text, unsigned bits) {
  const auto t = detail::trim(text);
  if (!t.empty() && t.front() == '-') {
    return is_integer_text(t) ? errc::value_out_of_range : errc::malformed_encoding;
  }
  const auto v = detail::parse_integer<std::uint64_t>(t);
  if (!v) return is_integer_text(t) ? errc::value_out_of_range : errc::malformed_encoding;
  if (*v > ((std::uint64_t{1} << bits) - 1)) return errc::value_out_of_range;
  return scalar{*v};
}

result<scalar> parse_float(std::string_view text, bool single) {
  auto t = detail::trim(text);
  if (!t.empty() && t.front() == '+') t.remove_prefix(1);
  if (t == "INF") return scalar{std::numeric_limits<double>::infinity()};
  if (t == "-INF") return scalar{-std::numeric_limits<double>::infinity()};
  if (t == "NaN") return scalar{std::numeric_limits<double>::quiet_NaN()};
  if (t.empty()) return errc::malformed_encoding;
  double v = 0;
  const auto* end = t.data() + t.size();
  const auto [p, ec] = std::from_chars(t.data(), end, v);
  if (p != end) return errc::malformed_encoding;
  if (ec == std::errc::result_out_of_range) return errc::value_out_of_range;
  if (ec != std::errc{}) return errc::malformed_encoding;
  if (single && std::isfinite(v) && std::fabs(v) > static_cast<double>(std::numeric_limits<float>::max())) {
    return errc::value_out_of_range;
  }
  return scalar{v};
}

}  // namespace

std::optional<btype_info> parse_btype(std::string_view btype) noexcept {
  for (const auto& f : fixed) {
    if (f.name == btype) return f.info;
  }
  if (auto n = sized(btype, "VisString")) return btype_info{basic_type::visible_string, *n, false};
  if (auto n = sized(btype, "Unicode")) return btype_info{basic_type::unicode_string, *n, false};
  if (auto n = sized(btype, "Octet")) return btype_info{basic_type::octet_string, *n, false};
  return std::nullopt;
}

result<scalar> parse_value(model::basic_type type, std::string_view text,
                           const enum_type* enumeration) {
  switch (type) {
    case basic_type::boolean: {
      const auto b = detail::parse_bool(text);
      if (!b) return errc::malformed_encoding;
      return scalar{*b};
    }
    case basic_type::int8: return parse_signed(text, 8);
    case basic_type::int16: return parse_signed(text, 16);
    case basic_type::int24: return parse_signed(text, 24);
    case basic_type::int32: return parse_signed(text, 32);
    case basic_type::int64: return parse_signed(text, 64);
    case basic_type::int128: return parse_signed(text, 128);
    case basic_type::int8u: return parse_unsigned(text, 8);
    case basic_type::int16u: return parse_unsigned(text, 16);
    case basic_type::int24u: return parse_unsigned(text, 24);
    case basic_type::int32u: return parse_unsigned(text, 32);
    case basic_type::float32: return parse_float(text, true);
    case basic_type::float64: return parse_float(text, false);
    case basic_type::enumerated: {
      const auto t = detail::trim(text);
      if (enumeration != nullptr) {
        if (const auto* v = enumeration->find_text(t)) {
          return scalar{std::int64_t{v->ord}};
        }
      }
      // Some tools write the ord instead of the literal.
      if (const auto ord = detail::parse_integer<std::int32_t>(t)) {
        if (enumeration == nullptr || enumeration->find_ord(*ord) != nullptr) {
          return scalar{std::int64_t{*ord}};
        }
        return errc::value_out_of_range;
      }
      return errc::malformed_encoding;
    }
    default: return scalar{std::string{text}};
  }
}

}  // namespace openiec61850::scl
