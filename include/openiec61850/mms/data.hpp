#pragma once

#include <array>
#include <chrono>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <variant>
#include <vector>

#include "openiec61850/ber/decode.hpp"
#include "openiec61850/ber/oid.hpp"
#include "openiec61850/ber/writer.hpp"
#include "openiec61850/core/bytes.hpp"
#include "openiec61850/core/result.hpp"
#include "openiec61850/mms/list_view.hpp"

// MMS Data (ISO 9506-2 §14.4.2):
//
//   Data ::= CHOICE {
//     array            [1]  IMPLICIT SEQUENCE OF Data,
//     structure        [2]  IMPLICIT SEQUENCE OF Data,
//     boolean          [3]  IMPLICIT BOOLEAN,
//     bit-string       [4]  IMPLICIT BIT STRING,
//     integer          [5]  IMPLICIT INTEGER,
//     unsigned         [6]  IMPLICIT INTEGER,       -- non-negative
//     floating-point   [7]  IMPLICIT FloatingPoint, -- OCTET STRING: exponent width, IEEE 754
//                                                   -- [8] (real) is reserved
//     octet-string     [9]  IMPLICIT OCTET STRING,
//     visible-string   [10] IMPLICIT VisibleString,
//     generalized-time [11] IMPLICIT GeneralizedTime,
//     binary-time      [12] IMPLICIT TimeOfDay,     -- 4 or 6 octets
//     bcd              [13] IMPLICIT INTEGER,       -- non-negative
//     booleanArray     [14] IMPLICIT BIT STRING,
//     objId            [15] IMPLICIT OBJECT IDENTIFIER,
//     mMSString        [16] IMPLICIT MMSString,     -- UTF-8
//     utc-time         [17] IMPLICIT UtcTime }      -- 8 octets
//
// All tags are context-specific; array and structure are constructed, all others primitive.
// INTEGER values are limited to 64 bits (signed for integer, unsigned for unsigned and bcd);
// wider values are rejected with errc::value_out_of_range when the data is parsed.
// Accessors called on the wrong alternative fail with errc::invalid_state.

namespace openiec61850::mms {

// The CHOICE alternative, numerically equal to its context tag.
enum class data_type : std::uint8_t {
  invalid = 0,  // default-constructed value or view
  array = 1,
  structure = 2,
  boolean = 3,
  bit_string = 4,
  integer = 5,
  unsigned_ = 6,
  floating_point = 7,
  octet_string = 9,
  visible_string = 10,
  generalized_time = 11,
  binary_time = 12,
  bcd = 13,
  boolean_array = 14,
  obj_id = 15,
  mms_string = 16,
  utc_time = 17,
};

struct decode_options {
  // Maximum number of nested array/structure levels in a Data value or TypeDescription
  // (a scalar is level 0). Deeper input fails with errc::nesting_too_deep.
  std::size_t max_nesting = 32;
};

// UtcTime (IEC 61850-8-1 §8.1.3.7, IEC 61850-7-2 TimeStamp): 4 octets of seconds since
// 1970-01-01T00:00:00Z, 3 octets of binary fraction of a second, 1 octet of time quality.
struct utc_time {
  static constexpr std::uint8_t leap_seconds_known = 0x80;
  static constexpr std::uint8_t clock_failure = 0x40;
  static constexpr std::uint8_t clock_not_synchronized = 0x20;
  static constexpr std::uint8_t accuracy_mask = 0x1F;  // number of significant fraction bits
  static constexpr std::uint8_t accuracy_unspecified = 0x1F;

  std::uint32_t seconds = 0;
  std::uint32_t fraction = 0;  // 24 bits, in units of 2^-24 s
  std::uint8_t quality = 0;

  [[nodiscard]] constexpr std::uint8_t accuracy() const noexcept {
    return static_cast<std::uint8_t>(quality & accuracy_mask);
  }

  // The fraction is rounded to the nearest 2^-24 s. Instants before 1970 or after
  // 2106-02-07T06:28:15Z fail with errc::value_out_of_range.
  template <typename Duration>
  [[nodiscard]] static result<utc_time> from_time_point(std::chrono::sys_time<Duration> tp,
                                                        std::uint8_t quality = 0) noexcept {
    using namespace std::chrono;
    const auto secs = floor<std::chrono::seconds>(tp);
    const auto count = secs.time_since_epoch().count();
    if (count < 0 || static_cast<std::uint64_t>(count) > std::numeric_limits<std::uint32_t>::max()) {
      return errc::value_out_of_range;
    }
    const auto ns = static_cast<std::uint64_t>(floor<nanoseconds>(tp - secs).count());
    std::uint64_t frac = ((ns << 24) + 500'000'000U) / 1'000'000'000U;
    if (frac > 0xFFFFFFU) frac = 0xFFFFFFU;
    return utc_time{static_cast<std::uint32_t>(count), static_cast<std::uint32_t>(frac), quality};
  }
  // The fraction is rounded to the nearest nanosecond.
  [[nodiscard]] std::chrono::sys_time<std::chrono::nanoseconds> to_time_point() const noexcept {
    const std::uint64_t ns = ((std::uint64_t{fraction & 0xFFFFFFU} * 1'000'000'000U) + (1U << 23)) >> 24;
    return std::chrono::sys_time<std::chrono::nanoseconds>{
        std::chrono::seconds{seconds} + std::chrono::nanoseconds{static_cast<std::int64_t>(ns)}};
  }

  [[nodiscard]] std::array<std::uint8_t, 8> to_bytes() const noexcept;
  [[nodiscard]] static utc_time from_bytes(std::span<const std::uint8_t, 8> b) noexcept;

  friend constexpr bool operator==(const utc_time&, const utc_time&) noexcept = default;
};

// TimeOfDay (ISO 9506-2 §14.4.2): milliseconds since midnight, optionally followed by the number
// of days since 1984-01-01 (6-octet form).
struct binary_time {
  std::uint32_t ms_of_day = 0;
  std::optional<std::uint16_t> days;

  static constexpr std::chrono::sys_days epoch{std::chrono::year{1984} / 1 / 1};

  // 6-octet form; instants before 1984 or after 2163-06-05 fail with errc::value_out_of_range.
  template <typename Duration>
  [[nodiscard]] static result<binary_time> from_time_point(
      std::chrono::sys_time<Duration> tp) noexcept {
    using namespace std::chrono;
    const auto day = floor<std::chrono::days>(tp);
    const auto d = (day - epoch).count();
    if (d < 0 || d > std::numeric_limits<std::uint16_t>::max()) return errc::value_out_of_range;
    const auto ms = floor<milliseconds>(tp - day).count();
    return binary_time{static_cast<std::uint32_t>(ms), static_cast<std::uint16_t>(d)};
  }
  // Fails with errc::invalid_state for the 4-octet form (no date).
  [[nodiscard]] result<std::chrono::sys_time<std::chrono::milliseconds>> to_time_point()
      const noexcept {
    if (!days) return errc::invalid_state;
    return std::chrono::sys_time<std::chrono::milliseconds>{
        epoch + std::chrono::days{*days} + std::chrono::milliseconds{ms_of_day}};
  }

  friend constexpr bool operator==(const binary_time&, const binary_time&) noexcept = default;
};

class data;

// Zero-copy view of an encoded Data value. Views obtained from data_view::parse or from the PDU
// decoders refer to validated input: walking elements() never fails and never allocates.
// The viewed bytes must outlive the view.
class data_view {
 public:
  data_view() noexcept = default;

  // Validates exactly one complete Data encoding (trailing bytes are malformed).
  [[nodiscard]] static result<data_view> parse(byte_view encoding,
                                               const decode_options& opts = {}) noexcept;
  // Validates an already-split element (e.g. one taken from a ber::reader).
  [[nodiscard]] static result<data_view> parse(const ber::tlv& element,
                                               const decode_options& opts = {}) noexcept;

  [[nodiscard]] data_type type() const noexcept { return type_; }
  [[nodiscard]] bool valid() const noexcept { return type_ != data_type::invalid; }
  [[nodiscard]] bool is_constructed() const noexcept {
    return type_ == data_type::array || type_ == data_type::structure;
  }
  // Identifier + length + contents.
  [[nodiscard]] byte_view encoding() const noexcept { return encoding_; }
  [[nodiscard]] byte_view contents() const noexcept { return contents_; }

  // Array elements or structure components; empty for the other alternatives.
  [[nodiscard]] list_view<data_view> elements() const noexcept;
  // Number of elements (O(n)).
  [[nodiscard]] std::size_t size() const noexcept { return elements().size(); }
  // Element i (O(i)); errc::value_out_of_range when there is no such element.
  [[nodiscard]] result<data_view> at(std::size_t i) const noexcept;

  [[nodiscard]] result<bool> as_boolean() const noexcept;
  [[nodiscard]] result<ber::bit_string_view> as_bit_string() const noexcept;
  [[nodiscard]] result<ber::bit_string_view> as_boolean_array() const noexcept;
  // integer or unsigned, range-checked into T (errc::value_out_of_range).
  template <std::integral T>
    requires(!std::same_as<T, bool>)
  [[nodiscard]] result<T> as_integer() const noexcept {
    if (type_ != data_type::integer && type_ != data_type::unsigned_) return errc::invalid_state;
    return ber::decode_integer_as<T>(contents_);
  }
  [[nodiscard]] result<std::int64_t> as_int64() const noexcept {
    return as_integer<std::int64_t>();
  }
  [[nodiscard]] result<std::uint64_t> as_uint64() const noexcept {
    return as_integer<std::uint64_t>();
  }
  // Single precision only (exponent width 8); a double fails with errc::value_out_of_range.
  [[nodiscard]] result<float> as_float() const noexcept;
  // Single or double precision.
  [[nodiscard]] result<double> as_double() const noexcept;
  // True when the floating-point value is double precision (exponent width 11).
  [[nodiscard]] bool is_double() const noexcept;
  [[nodiscard]] result<byte_view> as_octet_string() const noexcept;
  [[nodiscard]] result<std::string_view> as_visible_string() const noexcept;
  [[nodiscard]] result<std::string_view> as_generalized_time() const noexcept;
  [[nodiscard]] result<std::string_view> as_mms_string() const noexcept;
  [[nodiscard]] result<binary_time> as_binary_time() const noexcept;
  [[nodiscard]] result<std::uint64_t> as_bcd() const noexcept;
  [[nodiscard]] result<ber::oid> as_obj_id() const noexcept;
  [[nodiscard]] result<utc_time> as_utc_time() const noexcept;

  // Builds a view of an element without validating it; the input must have passed validation.
  [[nodiscard]] static data_view unchecked(const ber::tlv& element) noexcept;

 private:
  data_type type_ = data_type::invalid;
  byte_view encoding_;
  byte_view contents_;
};

// Owning Data value (a tree) for building values to write or report.
class data {
 public:
  data() = default;  // data_type::invalid; cannot be encoded

  [[nodiscard]] static data array(std::vector<data> elements);
  [[nodiscard]] static data structure(std::vector<data> components);
  [[nodiscard]] static data boolean(bool v);
  // `bytes` is resized to ceil(bit_count / 8) octets (zero-filled) and padding bits are cleared.
  [[nodiscard]] static data bit_string(byte_view bytes, std::size_t bit_count);
  [[nodiscard]] static data integer(std::int64_t v);
  [[nodiscard]] static data unsigned_integer(std::uint64_t v);
  [[nodiscard]] static data floating_point(float v);
  [[nodiscard]] static data floating_point(double v);
  [[nodiscard]] static data octet_string(byte_view v);
  [[nodiscard]] static data visible_string(std::string_view v);
  [[nodiscard]] static data generalized_time(std::string_view v);
  [[nodiscard]] static data binary_time(const mms::binary_time& v);
  [[nodiscard]] static data bcd(std::uint64_t v);
  [[nodiscard]] static data boolean_array(byte_view bytes, std::size_t bit_count);
  [[nodiscard]] static data obj_id(const ber::oid& v);
  [[nodiscard]] static data mms_string(std::string_view v);
  [[nodiscard]] static data utc_time(const mms::utc_time& v);

  // Deep copy of a decoded value.
  [[nodiscard]] static result<data> from_view(const data_view& v);

  [[nodiscard]] data_type type() const noexcept { return type_; }
  [[nodiscard]] bool valid() const noexcept { return type_ != data_type::invalid; }

  // Array elements or structure components; empty for the other alternatives.
  [[nodiscard]] std::span<const data> elements() const noexcept;
  // Mutable children; errc::invalid_state unless array or structure.
  [[nodiscard]] result<std::vector<data>*> mutable_elements() noexcept;

  [[nodiscard]] result<bool> as_boolean() const noexcept;
  [[nodiscard]] result<ber::bit_string_view> as_bit_string() const noexcept;
  [[nodiscard]] result<ber::bit_string_view> as_boolean_array() const noexcept;
  [[nodiscard]] result<std::int64_t> as_int64() const noexcept;
  [[nodiscard]] result<std::uint64_t> as_uint64() const noexcept;
  [[nodiscard]] result<float> as_float() const noexcept;
  [[nodiscard]] result<double> as_double() const noexcept;
  [[nodiscard]] bool is_double() const noexcept;
  [[nodiscard]] result<byte_view> as_octet_string() const noexcept;
  [[nodiscard]] result<std::string_view> as_visible_string() const noexcept;
  [[nodiscard]] result<std::string_view> as_generalized_time() const noexcept;
  [[nodiscard]] result<std::string_view> as_mms_string() const noexcept;
  [[nodiscard]] result<mms::binary_time> as_binary_time() const noexcept;
  [[nodiscard]] result<std::uint64_t> as_bcd() const noexcept;
  [[nodiscard]] result<ber::oid> as_obj_id() const noexcept;
  [[nodiscard]] result<mms::utc_time> as_utc_time() const noexcept;

  // Fails with errc::invalid_state for an invalid value (or one containing an invalid value or an
  // invalid OBJECT IDENTIFIER); `w`'s buffer is then left with a partial encoding.
  [[nodiscard]] result<void> encode(ber::writer& w) const;

  friend bool operator==(const data& a, const data& b) noexcept;

 private:
  using storage = std::variant<std::monostate, bool, std::int64_t, std::uint64_t, float, double,
                               std::string, byte_buffer, ber::oid, mms::utc_time, mms::binary_time,
                               std::vector<data>>;
  data(data_type t, storage v, std::size_t bits = 0) : type_(t), value_(std::move(v)), bits_(bits) {}

  data_type type_ = data_type::invalid;
  storage value_;
  std::size_t bits_ = 0;  // bit-string and booleanArray
};

// Either a decoded view or a borrowed owning value, for encoders that accept both.
class data_ref {
 public:
  data_ref() noexcept = default;
  data_ref(const data_view& v) noexcept : view_(v) {}  // NOLINT(google-explicit-constructor)
  data_ref(const data& d) noexcept : owned_(&d) {}     // NOLINT(google-explicit-constructor)

  // The view (invalid when this refers to an owning value).
  [[nodiscard]] const data_view& view() const noexcept { return view_; }
  [[nodiscard]] const data* owned() const noexcept { return owned_; }
  [[nodiscard]] data_type type() const noexcept {
    return owned_ != nullptr ? owned_->type() : view_.type();
  }
  [[nodiscard]] result<void> encode(ber::writer& w) const;

 private:
  data_view view_;
  const data* owned_ = nullptr;
};

// Encodes a value into `out` (appending).
[[nodiscard]] result<void> encode_data(const data& v, byte_buffer& out);

// FloatingPoint helpers (ISO 9506-2 §14.4.2): exponent-width octet + IEEE 754 big-endian.
[[nodiscard]] std::array<std::uint8_t, 5> encode_float(float v) noexcept;
[[nodiscard]] std::array<std::uint8_t, 9> encode_double(double v) noexcept;

}  // namespace openiec61850::mms
