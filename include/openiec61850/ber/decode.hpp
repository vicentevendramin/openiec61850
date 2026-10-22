#pragma once

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string_view>
#include <type_traits>

#include "openiec61850/ber/oid.hpp"
#include "openiec61850/ber/tag.hpp"
#include "openiec61850/core/bytes.hpp"
#include "openiec61850/core/result.hpp"

// BER decoding (ITU-T X.690). All functions are zero-copy: returned views point into the input.
//
// Error mapping:
//   truncated_input     identifier/length octets cut short, or missing end-of-contents
//   length_overflow     declared length exceeds the enclosing buffer or size_t
//   malformed_encoding  encoding forbidden by X.690 (e.g. indefinite length in primitive form)
//   unsupported         valid X.690 not handled here (tag numbers or OID arcs above 2^32-1,
//                       constructed/segmented string encodings)
//   nesting_too_deep    constructed nesting beyond decode_options::max_depth
//   value_out_of_range  integer does not fit the requested C++ type
//
// Leniency: BER permits non-minimal long-form lengths (X.690 §8.1.3.5 note 2), any non-zero
// BOOLEAN octet (§8.2.2) and non-zero unused bits in BIT STRING padding (§8.6.2.3); all are
// accepted. Non-minimal INTEGER (§8.3.2), non-minimal OID subidentifiers (§8.19.2) and
// high-tag-number form for numbers below 31 (§8.1.2.2) are forbidden by X.690 and rejected.

namespace openiec61850::ber {

// No dedicated errc exists yet for "value does not fit the target type".
inline constexpr errc value_out_of_range = errc::value_out_of_range;

struct decode_options {
  // Maximum number of nested constructed levels a reader may descend into; also bounds the
  // nesting of indefinite-length encodings scanned to find their end-of-contents.
  std::size_t max_depth = 64;
};

// One decoded element.
struct tlv {
  ber::tag tag;
  byte_view value;     // contents octets (end-of-contents excluded for indefinite length)
  byte_view encoding;  // identifier + length + contents (+ end-of-contents)
  bool indefinite = false;

  [[nodiscard]] bool constructed() const noexcept { return tag.constructed; }
  [[nodiscard]] std::size_t header_size() const noexcept {
    return static_cast<std::size_t>(value.data() - encoding.data());
  }
};

// Decodes the element at the start of `data` (trailing bytes are ignored). `depth` is the
// nesting level of the element itself; it matters only for indefinite-length encodings.
[[nodiscard]] result<tlv> decode_tlv(byte_view data, const decode_options& opts = {},
                                     std::size_t depth = 0) noexcept;

// Decodes only the identifier octets at the start of `data`.
[[nodiscard]] result<tag> decode_tag(byte_view data) noexcept;

// BIT STRING contents (X.690 §8.6). Bit 0 is the most significant bit of the first octet.
struct bit_string_view {
  byte_view bytes;  // data octets, without the leading unused-bits octet
  std::size_t bit_count = 0;

  [[nodiscard]] std::uint8_t unused_bits() const noexcept {
    return static_cast<std::uint8_t>(bytes.size() * 8 - bit_count);
  }
  // Precondition: i < bit_count.
  [[nodiscard]] bool test(std::size_t i) const noexcept {
    return ((static_cast<unsigned>(bytes[i / 8]) >> (7 - i % 8)) & 1U) != 0;
  }
  [[nodiscard]] bool operator[](std::size_t i) const noexcept { return test(i); }
};

// Primitive decoders on contents octets. The tlv overloads also check the form: constructed
// encodings are malformed for types that are always primitive, and unsupported for strings.
[[nodiscard]] result<bool> decode_boolean(byte_view contents) noexcept;
[[nodiscard]] result<std::int64_t> decode_integer(byte_view contents) noexcept;
// Non-negative INTEGER up to 2^64-1 (e.g. 00 FF FF FF FF FF FF FF FF).
[[nodiscard]] result<std::uint64_t> decode_unsigned(byte_view contents) noexcept;
[[nodiscard]] result<std::int64_t> decode_enumerated(byte_view contents) noexcept;
[[nodiscard]] result<void> decode_null(byte_view contents) noexcept;
[[nodiscard]] result<bit_string_view> decode_bit_string(byte_view contents) noexcept;
[[nodiscard]] result<byte_view> decode_octet_string(byte_view contents) noexcept;
[[nodiscard]] result<oid> decode_oid(byte_view contents) noexcept;
// Character strings are returned as raw bytes; the character set is not validated.
[[nodiscard]] result<std::string_view> decode_visible_string(byte_view contents) noexcept;
[[nodiscard]] result<std::string_view> decode_utf8_string(byte_view contents) noexcept;
[[nodiscard]] result<std::string_view> decode_generalized_time(byte_view contents) noexcept;

[[nodiscard]] result<bool> decode_boolean(const tlv& e) noexcept;
[[nodiscard]] result<std::int64_t> decode_integer(const tlv& e) noexcept;
[[nodiscard]] result<std::uint64_t> decode_unsigned(const tlv& e) noexcept;
[[nodiscard]] result<std::int64_t> decode_enumerated(const tlv& e) noexcept;
[[nodiscard]] result<void> decode_null(const tlv& e) noexcept;
[[nodiscard]] result<bit_string_view> decode_bit_string(const tlv& e) noexcept;
[[nodiscard]] result<byte_view> decode_octet_string(const tlv& e) noexcept;
[[nodiscard]] result<oid> decode_oid(const tlv& e) noexcept;
[[nodiscard]] result<std::string_view> decode_visible_string(const tlv& e) noexcept;
[[nodiscard]] result<std::string_view> decode_utf8_string(const tlv& e) noexcept;
[[nodiscard]] result<std::string_view> decode_generalized_time(const tlv& e) noexcept;

// INTEGER range-checked into any integral type.
template <std::integral T>
  requires(!std::same_as<T, bool>)
[[nodiscard]] result<T> decode_integer_as(byte_view contents) noexcept {
  if constexpr (std::is_signed_v<T>) {
    auto v = decode_integer(contents);
    if (!v) return v.error();
    if (*v < std::numeric_limits<T>::min() || *v > std::numeric_limits<T>::max()) {
      return value_out_of_range;
    }
    return static_cast<T>(*v);
  } else {
    auto v = decode_unsigned(contents);
    if (!v) return v.error();
    if (*v > std::numeric_limits<T>::max()) return value_out_of_range;
    return static_cast<T>(*v);
  }
}

}  // namespace openiec61850::ber
