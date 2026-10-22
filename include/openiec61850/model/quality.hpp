#pragma once

#include <array>
#include <cstdint>
#include <string>

#include "openiec61850/core/result.hpp"
#include "openiec61850/mms/data.hpp"

// Quality (IEC 61850-7-3 §6.2, IEC 61850-8-1 §8.1.3.6): MMS BIT STRING of 13 bits.
//
//   bit  0-1  validity: 00 good, 01 invalid, 10 reserved, 11 questionable (bit 0 is the MSB)
//   bit  2    detailQual.overflow
//   bit  3    detailQual.outOfRange
//   bit  4    detailQual.badReference
//   bit  5    detailQual.oscillatory
//   bit  6    detailQual.failure
//   bit  7    detailQual.oldData
//   bit  8    detailQual.inconsistent
//   bit  9    detailQual.inaccurate
//   bit 10    source: 0 process, 1 substituted
//   bit 11    test
//   bit 12    operatorBlocked
//
// Bit 0 is the first (most significant) bit of the first octet, so "invalid" encodes as
// 84 03 03 40 00 and "operatorBlocked" as 84 03 03 00 08.

namespace openiec61850::model {

enum class validity : std::uint8_t { good = 0, invalid = 1, reserved = 2, questionable = 3 };
enum class source : std::uint8_t { process = 0, substituted = 1 };

// Single-bit members of Quality; the value is the mask in quality::raw().
enum class quality_flag : std::uint16_t {
  overflow = 1U << 2,
  out_of_range = 1U << 3,
  bad_reference = 1U << 4,
  oscillatory = 1U << 5,
  failure = 1U << 6,
  old_data = 1U << 7,
  inconsistent = 1U << 8,
  inaccurate = 1U << 9,
  substituted = 1U << 10,
  test = 1U << 11,
  operator_blocked = 1U << 12,
};

class quality {
 public:
  static constexpr std::size_t bit_count = 13;
  static constexpr std::uint16_t mask = (1U << bit_count) - 1;

  constexpr quality() noexcept = default;
  // Bit i of the BIT STRING is (1 << i) in `raw`; bits above 12 are dropped.
  [[nodiscard]] static constexpr quality from_raw(std::uint16_t raw) noexcept {
    quality q;
    q.bits_ = static_cast<std::uint16_t>(raw & mask);
    return q;
  }
  [[nodiscard]] constexpr std::uint16_t raw() const noexcept { return bits_; }

  [[nodiscard]] constexpr model::validity validity() const noexcept {
    return static_cast<model::validity>(((bits_ & 1U) << 1) | ((bits_ >> 1) & 1U));
  }
  constexpr quality& set_validity(model::validity v) noexcept {
    const auto n = static_cast<unsigned>(v);
    bits_ = static_cast<std::uint16_t>((bits_ & ~3U) | ((n >> 1) & 1U) | ((n & 1U) << 1));
    return *this;
  }
  [[nodiscard]] constexpr bool is_good() const noexcept { return validity() == validity::good; }

  [[nodiscard]] constexpr bool has(quality_flag f) const noexcept {
    return (bits_ & static_cast<std::uint16_t>(f)) != 0;
  }
  constexpr quality& set(quality_flag f, bool on = true) noexcept {
    const auto m = static_cast<unsigned>(f);
    bits_ = static_cast<std::uint16_t>(on ? (bits_ | m) : (bits_ & ~m));
    return *this;
  }

  [[nodiscard]] constexpr bool overflow() const noexcept { return has(quality_flag::overflow); }
  [[nodiscard]] constexpr bool out_of_range() const noexcept {
    return has(quality_flag::out_of_range);
  }
  [[nodiscard]] constexpr bool bad_reference() const noexcept {
    return has(quality_flag::bad_reference);
  }
  [[nodiscard]] constexpr bool oscillatory() const noexcept {
    return has(quality_flag::oscillatory);
  }
  [[nodiscard]] constexpr bool failure() const noexcept { return has(quality_flag::failure); }
  [[nodiscard]] constexpr bool old_data() const noexcept { return has(quality_flag::old_data); }
  [[nodiscard]] constexpr bool inconsistent() const noexcept {
    return has(quality_flag::inconsistent);
  }
  [[nodiscard]] constexpr bool inaccurate() const noexcept {
    return has(quality_flag::inaccurate);
  }
  [[nodiscard]] constexpr model::source source() const noexcept {
    return has(quality_flag::substituted) ? source::substituted : source::process;
  }
  constexpr quality& set_source(model::source s) noexcept {
    return set(quality_flag::substituted, s == source::substituted);
  }
  [[nodiscard]] constexpr bool test() const noexcept { return has(quality_flag::test); }
  [[nodiscard]] constexpr bool operator_blocked() const noexcept {
    return has(quality_flag::operator_blocked);
  }

  // The two BIT STRING data octets.
  [[nodiscard]] constexpr std::array<std::uint8_t, 2> to_bytes() const noexcept {
    std::uint16_t v = 0;
    for (std::size_t i = 0; i < bit_count; ++i) {
      if ((bits_ >> i) & 1U) v = static_cast<std::uint16_t>(v | (0x8000U >> i));
    }
    return {static_cast<std::uint8_t>(v >> 8), static_cast<std::uint8_t>(v & 0xFFU)};
  }

  [[nodiscard]] mms::data to_mms() const;
  // Any BIT STRING is accepted: missing bits read as zero and bits beyond 12 are ignored.
  // errc::invalid_state when the value is not a bit-string.
  [[nodiscard]] static result<quality> from_mms(const mms::data_ref& d) noexcept;

  friend constexpr bool operator==(quality, quality) noexcept = default;

 private:
  std::uint16_t bits_ = 0;
};

// "good", "invalid|oldData|test", "questionable|substituted"...
[[nodiscard]] std::string to_string(quality q);

}  // namespace openiec61850::model
