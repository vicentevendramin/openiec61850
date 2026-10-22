#pragma once

#include <cstdint>

#include "openiec61850/mms/data.hpp"

namespace mms_fuzz {

namespace mms = openiec61850::mms;

inline void check(bool condition) {
  if (!condition) __builtin_trap();
}

// Exercises every accessor of a validated view and checks that the owning copy is stable:
// encode(from_view(v)) parses back to a value that encodes identically.
inline void walk(const mms::data_view& v, std::size_t depth = 0) {
  check(v.valid());
  (void)v.as_boolean();
  (void)v.as_bit_string();
  (void)v.as_boolean_array();
  (void)v.as_int64();
  (void)v.as_uint64();
  (void)v.as_integer<std::int8_t>();
  (void)v.as_float();
  (void)v.as_double();
  (void)v.as_octet_string();
  (void)v.as_visible_string();
  (void)v.as_generalized_time();
  (void)v.as_mms_string();
  (void)v.as_bcd();
  (void)v.as_obj_id();
  if (auto t = v.as_utc_time()) (void)t->to_time_point();
  if (auto t = v.as_binary_time()) (void)t->to_time_point();

  std::size_t n = 0;
  for (const auto& e : v.elements()) {
    walk(e, depth + 1);
    ++n;
  }
  check(n == v.size());
  check(v.is_constructed() || n == 0);

  if (depth == 0) {
    auto owned = mms::data::from_view(v);
    if (!owned) return;  // e.g. a floating-point format other than single/double
    openiec61850::byte_buffer first;
    check(static_cast<bool>(mms::encode_data(*owned, first)));
    auto reparsed = mms::data_view::parse(first, {.max_nesting = 1024});
    check(reparsed.has_value());
    auto again = mms::data::from_view(*reparsed);
    check(again.has_value());
    openiec61850::byte_buffer second;
    check(static_cast<bool>(mms::encode_data(*again, second)));
    check(first == second);
  }
}

}  // namespace mms_fuzz
