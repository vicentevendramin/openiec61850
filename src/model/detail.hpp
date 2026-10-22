#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>

#include "openiec61850/mms/data.hpp"

namespace openiec61850::model::detail {

inline result<ber::bit_string_view> as_bit_string(const mms::data_ref& d) noexcept {
  if (const auto* owned = d.owned()) return owned->as_bit_string();
  return d.view().as_bit_string();
}

// Bit i of the BIT STRING becomes (1 << i); bits beyond `width` are ignored and missing bits
// read as zero.
inline result<std::uint32_t> bits_from_mms(const mms::data_ref& d, std::size_t width) noexcept {
  auto bs = as_bit_string(d);
  if (!bs) return bs.error();
  std::uint32_t v = 0;
  const std::size_t n = bs->bit_count < width ? bs->bit_count : width;
  for (std::size_t i = 0; i < n; ++i) {
    if (bs->test(i)) v |= 1U << i;
  }
  return v;
}

inline mms::data bits_to_mms(std::uint32_t bits, std::size_t width) {
  std::array<std::uint8_t, 4> bytes{};
  for (std::size_t i = 0; i < width; ++i) {
    if ((bits >> i) & 1U) bytes[i / 8] = static_cast<std::uint8_t>(bytes[i / 8] | (0x80U >> (i % 8)));
  }
  return mms::data::bit_string(byte_view{bytes.data(), (width + 7) / 8}, width);
}

// Signed integer types only.
template <typename T>
result<T> integer_from_mms(const mms::data_ref& d) noexcept {
  if (const auto* owned = d.owned()) {
    auto v = owned->as_int64();
    if (!v) return v.error();
    if (*v < std::numeric_limits<T>::min() || *v > std::numeric_limits<T>::max()) {
      return errc::value_out_of_range;
    }
    return static_cast<T>(*v);
  }
  return d.view().as_integer<T>();
}

}  // namespace openiec61850::model::detail
