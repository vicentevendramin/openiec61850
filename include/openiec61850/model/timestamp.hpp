#pragma once

#include <chrono>
#include <cstdint>
#include <optional>

#include "openiec61850/core/result.hpp"
// Declares basic_type::entry_time before the model::entry_time alias below; the reverse order
// trips -Wshadow.
#include "openiec61850/model/basic_type.hpp"
#include "openiec61850/mms/data.hpp"

// TimeStamp (IEC 61850-7-2 §6.1.2.9, IEC 61850-8-1 §8.1.3.7): MMS UtcTime, 8 octets.
//
//   octets 0-3  SecondSinceEpoch (1970-01-01T00:00:00Z, leap seconds not counted)
//   octets 4-6  FractionOfSecond, units of 2^-24 s
//   octet  7    TimeQuality: bit 7 LeapSecondsKnown, bit 6 ClockFailure,
//               bit 5 ClockNotSynchronized, bits 4-0 TimeAccuracy
//
// TimeAccuracy is the number of significant bits of the fraction (0..24); 31 means unspecified
// and 25..30 are invalid.

namespace openiec61850::model {

// Time accuracy classes (IEC 61850-5 / 7-2), as numbers of significant fraction bits.
namespace time_accuracy_class {
inline constexpr std::uint8_t t0 = 7;   // ~10 ms
inline constexpr std::uint8_t t1 = 10;  // ~1 ms
inline constexpr std::uint8_t t2 = 14;  // ~100 us
inline constexpr std::uint8_t t3 = 16;  // ~25 us
inline constexpr std::uint8_t t4 = 18;  // ~4 us
inline constexpr std::uint8_t t5 = 20;  // ~1 us
inline constexpr std::uint8_t unspecified = 31;
}  // namespace time_accuracy_class

class timestamp {
 public:
  using time_point = std::chrono::sys_time<std::chrono::nanoseconds>;

  constexpr timestamp() noexcept = default;
  constexpr explicit timestamp(const mms::utc_time& t) noexcept : t_(t) {}

  // The fraction is rounded to the nearest 2^-24 s. errc::value_out_of_range outside
  // 1970-01-01 .. 2106-02-07T06:28:15Z.
  template <typename Duration>
  [[nodiscard]] static result<timestamp> from_time_point(
      std::chrono::sys_time<Duration> tp,
      std::uint8_t accuracy = time_accuracy_class::unspecified) noexcept {
    auto t = mms::utc_time::from_time_point(tp, accuracy & mms::utc_time::accuracy_mask);
    if (!t) return t.error();
    return timestamp{*t};
  }
  // system_clock::now(), with the given accuracy and no other quality flags.
  [[nodiscard]] static timestamp now(
      std::uint8_t accuracy = time_accuracy_class::unspecified) noexcept;

  // Rounded to the nearest nanosecond.
  [[nodiscard]] time_point to_time_point() const noexcept { return t_.to_time_point(); }

  [[nodiscard]] constexpr std::uint32_t seconds() const noexcept { return t_.seconds; }
  [[nodiscard]] constexpr std::uint32_t fraction() const noexcept { return t_.fraction; }
  [[nodiscard]] constexpr std::uint8_t time_quality() const noexcept { return t_.quality; }

  [[nodiscard]] constexpr bool leap_seconds_known() const noexcept {
    return (t_.quality & mms::utc_time::leap_seconds_known) != 0;
  }
  [[nodiscard]] constexpr bool clock_failure() const noexcept {
    return (t_.quality & mms::utc_time::clock_failure) != 0;
  }
  [[nodiscard]] constexpr bool clock_not_synchronized() const noexcept {
    return (t_.quality & mms::utc_time::clock_not_synchronized) != 0;
  }
  [[nodiscard]] constexpr std::uint8_t time_accuracy() const noexcept { return t_.accuracy(); }
  // 2^-accuracy seconds (rounded to nanoseconds); nullopt when unspecified or invalid.
  [[nodiscard]] std::optional<std::chrono::nanoseconds> accuracy() const noexcept;

  constexpr timestamp& set_leap_seconds_known(bool on) noexcept {
    return set_flag(mms::utc_time::leap_seconds_known, on);
  }
  constexpr timestamp& set_clock_failure(bool on) noexcept {
    return set_flag(mms::utc_time::clock_failure, on);
  }
  constexpr timestamp& set_clock_not_synchronized(bool on) noexcept {
    return set_flag(mms::utc_time::clock_not_synchronized, on);
  }
  // Only the low 5 bits are kept.
  constexpr timestamp& set_time_accuracy(std::uint8_t bits) noexcept {
    t_.quality = static_cast<std::uint8_t>((t_.quality & ~mms::utc_time::accuracy_mask) |
                                           (bits & mms::utc_time::accuracy_mask));
    return *this;
  }

  [[nodiscard]] constexpr const mms::utc_time& utc_time() const noexcept { return t_; }
  [[nodiscard]] mms::data to_mms() const { return mms::data::utc_time(t_); }
  // errc::invalid_state when the value is not a utc-time.
  [[nodiscard]] static result<timestamp> from_mms(const mms::data_ref& d) noexcept;

  friend constexpr bool operator==(const timestamp&, const timestamp&) noexcept = default;

 private:
  constexpr timestamp& set_flag(std::uint8_t m, bool on) noexcept {
    t_.quality = static_cast<std::uint8_t>(on ? (t_.quality | m) : (t_.quality & ~m));
    return *this;
  }

  mms::utc_time t_;
};

// EntryTime (IEC 61850-8-1 §8.1.3.8): MMS Binary-Time, 6-octet form with the date.
using entry_time = mms::binary_time;

[[nodiscard]] inline mms::data to_mms(const entry_time& t) { return mms::data::binary_time(t); }
// errc::invalid_state when the value is not a binary-time.
[[nodiscard]] result<entry_time> entry_time_from_mms(const mms::data_ref& d) noexcept;

}  // namespace openiec61850::model
