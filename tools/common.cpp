#include "common.hpp"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <ctime>

namespace openiec61850::tools {

namespace {

std::string hex(byte_view bytes) {
  static constexpr char digits[] = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2);
  for (auto b : bytes) {
    out.push_back(digits[b >> 4]);
    out.push_back(digits[b & 0x0F]);
  }
  return out;
}

std::string bits(const ber::bit_string_view& b) {
  std::string out = "b'";
  for (std::size_t i = 0; i < b.bit_count; ++i) out.push_back(b.test(i) ? '1' : '0');
  out.push_back('\'');
  return out;
}

std::string quoted(std::string_view s) {
  std::string out = "\"";
  for (char c : s) {
    if (c == '"' || c == '\\') out.push_back('\\');
    out.push_back(c);
  }
  out.push_back('"');
  return out;
}

std::string utc(const mms::utc_time& t) {
  const auto secs = static_cast<std::time_t>(t.seconds);
  std::tm tm{};
  gmtime_r(&secs, &tm);
  char buf[64];
  const auto ms = (std::uint64_t{t.fraction} * 1000U) >> 24;
  std::snprintf(buf, sizeof buf, "%04d-%02d-%02dT%02d:%02d:%02d.%03uZ", tm.tm_year + 1900,
                tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
                static_cast<unsigned>(ms));
  return buf;
}

std::string number(double v) {
  char buf[64];
  std::snprintf(buf, sizeof buf, "%.7g", v);
  return buf;
}

std::string lower(std::string_view s) {
  std::string out(s);
  std::transform(out.begin(), out.end(), out.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return out;
}

std::optional<long long> to_signed(std::string_view text) {
  const std::string s(text);
  if (s.empty()) return std::nullopt;
  char* end = nullptr;
  errno = 0;
  const long long v = std::strtoll(s.c_str(), &end, 10);
  if (errno != 0 || end == s.c_str() || *end != '\0') return std::nullopt;
  return v;
}

std::optional<unsigned long long> to_unsigned(std::string_view text) {
  const std::string s(text);
  if (s.empty() || s.front() == '-') return std::nullopt;
  char* end = nullptr;
  errno = 0;
  const unsigned long long v = std::strtoull(s.c_str(), &end, 10);
  if (errno != 0 || end == s.c_str() || *end != '\0') return std::nullopt;
  return v;
}

}  // namespace

std::string format_value(const mms::data& v) {
  switch (v.type()) {
    case mms::data_type::array:
    case mms::data_type::structure: {
      const bool arr = v.type() == mms::data_type::array;
      std::string out = arr ? "[" : "{";
      bool first = true;
      for (const auto& e : v.elements()) {
        if (!first) out += ", ";
        first = false;
        out += format_value(e);
      }
      out += arr ? "]" : "}";
      return out;
    }
    case mms::data_type::boolean: return *v.as_boolean() ? "true" : "false";
    case mms::data_type::bit_string: return bits(*v.as_bit_string());
    case mms::data_type::boolean_array: return bits(*v.as_boolean_array());
    case mms::data_type::integer: return std::to_string(*v.as_int64());
    case mms::data_type::unsigned_: return std::to_string(*v.as_uint64());
    case mms::data_type::bcd: return std::to_string(*v.as_bcd());
    case mms::data_type::floating_point: return number(*v.as_double());
    case mms::data_type::octet_string: return "0x" + hex(*v.as_octet_string());
    case mms::data_type::visible_string: return quoted(*v.as_visible_string());
    case mms::data_type::mms_string: return quoted(*v.as_mms_string());
    case mms::data_type::generalized_time: return std::string(*v.as_generalized_time());
    case mms::data_type::utc_time: return utc(*v.as_utc_time());
    case mms::data_type::binary_time: {
      const auto bt = *v.as_binary_time();
      auto tp = bt.to_time_point();
      if (!tp) return "time-of-day " + std::to_string(bt.ms_of_day) + " ms";
      const auto ms = tp->time_since_epoch().count();
      mms::utc_time u{static_cast<std::uint32_t>(ms / 1000),
                      static_cast<std::uint32_t>(((ms % 1000) << 24) / 1000), 0};
      return utc(u);
    }
    case mms::data_type::obj_id: {
      auto o = v.as_obj_id();
      return o ? "oid" : "?";
    }
    case mms::data_type::invalid: break;
  }
  return "<invalid>";
}

result<mms::data> parse_value(std::string_view text, mms::data_type type, std::size_t bit_count) {
  switch (type) {
    case mms::data_type::boolean: {
      const auto t = lower(text);
      if (t == "true" || t == "1" || t == "on") return mms::data::boolean(true);
      if (t == "false" || t == "0" || t == "off") return mms::data::boolean(false);
      return errc::malformed_encoding;
    }
    case mms::data_type::integer: {
      auto v = to_signed(text);
      if (!v) return errc::malformed_encoding;
      return mms::data::integer(*v);
    }
    case mms::data_type::unsigned_: {
      auto v = to_unsigned(text);
      if (!v) return errc::malformed_encoding;
      return mms::data::unsigned_integer(*v);
    }
    case mms::data_type::bcd: {
      auto v = to_unsigned(text);
      if (!v) return errc::malformed_encoding;
      return mms::data::bcd(*v);
    }
    case mms::data_type::floating_point: {
      const std::string s(text);
      char* end = nullptr;
      const double d = std::strtod(s.c_str(), &end);
      if (s.empty() || *end != '\0' || !std::isfinite(d)) return errc::malformed_encoding;
      return mms::data::floating_point(static_cast<float>(d));
    }
    case mms::data_type::visible_string: return mms::data::visible_string(text);
    case mms::data_type::mms_string: return mms::data::mms_string(text);
    case mms::data_type::bit_string:
    case mms::data_type::boolean_array: {
      std::string_view t = text;
      if (t.size() >= 3 && t.substr(0, 2) == "b'" && t.back() == '\'') t = t.substr(2, t.size() - 3);
      if (t.empty() || (bit_count != 0 && t.size() != bit_count)) return errc::malformed_encoding;
      byte_buffer bytes((t.size() + 7) / 8, 0);
      for (std::size_t i = 0; i < t.size(); ++i) {
        if (t[i] == '1') {
          bytes[i / 8] = static_cast<std::uint8_t>(bytes[i / 8] | (0x80U >> (i % 8)));
        } else if (t[i] != '0') {
          return errc::malformed_encoding;
        }
      }
      return type == mms::data_type::bit_string ? mms::data::bit_string(bytes, t.size())
                                                : mms::data::boolean_array(bytes, t.size());
    }
    case mms::data_type::octet_string: {
      std::string_view t = text;
      if (t.size() >= 2 && (t.substr(0, 2) == "0x" || t.substr(0, 2) == "0X")) t = t.substr(2);
      if (t.size() % 2 != 0) return errc::malformed_encoding;
      byte_buffer bytes;
      for (std::size_t i = 0; i < t.size(); i += 2) {
        const std::string pair(t.substr(i, 2));
        char* end = nullptr;
        const long b = std::strtol(pair.c_str(), &end, 16);
        if (*end != '\0' || !std::isxdigit(static_cast<unsigned char>(pair[0]))) {
          return errc::malformed_encoding;
        }
        bytes.push_back(static_cast<std::uint8_t>(b));
      }
      return mms::data::octet_string(bytes);
    }
    default: return errc::unsupported;
  }
}

result<mms::data> parse_value_like(std::string_view text, const mms::data& like) {
  std::size_t n = 0;
  if (like.type() == mms::data_type::bit_string) n = like.as_bit_string()->bit_count;
  if (like.type() == mms::data_type::boolean_array) n = like.as_boolean_array()->bit_count;
  auto v = parse_value(text, like.type(), n);
  if (v && like.type() == mms::data_type::floating_point && like.is_double()) {
    return mms::data::floating_point(*v->as_double());
  }
  return v;
}

arguments::arguments(int argc, char** argv, std::initializer_list<std::string_view> valued) {
  bool options_done = false;
  for (int i = 1; i < argc; ++i) {
    const std::string a = argv[i];
    if (options_done || a.size() < 3 || a.substr(0, 2) != "--") {
      if (a == "-h") {
        options_.emplace_back("help", std::nullopt);
        continue;
      }
      positional_.push_back(a);
      continue;
    }
    if (a == "--") {
      options_done = true;
      continue;
    }
    auto name = a.substr(2);
    std::optional<std::string> val;
    if (const auto eq = name.find('='); eq != std::string::npos) {
      val = name.substr(eq + 1);
      name = name.substr(0, eq);
    } else if (std::find(valued.begin(), valued.end(), name) != valued.end()) {
      if (i + 1 >= argc) {
        missing_ = name;
      } else {
        val = argv[++i];
      }
    }
    options_.emplace_back(std::move(name), std::move(val));
  }
}

std::optional<std::string> arguments::value(std::string_view name) const {
  std::optional<std::string> out;
  for (const auto& [n, v] : options_) {
    if (n == name && v) out = v;
  }
  return out;
}

bool arguments::flag(std::string_view name) const {
  return std::any_of(options_.begin(), options_.end(), [&](const auto& o) { return o.first == name; });
}

std::optional<std::string> arguments::unknown(std::initializer_list<std::string_view> known) const {
  for (const auto& o : options_) {
    if (o.first == "help") continue;
    if (std::find(known.begin(), known.end(), o.first) == known.end()) return o.first;
  }
  return std::nullopt;
}

std::optional<long long> parse_number(std::string_view text, long long min, long long max) {
  auto v = to_signed(text);
  if (!v || *v < min || *v > max) return std::nullopt;
  return v;
}

}  // namespace openiec61850::tools
