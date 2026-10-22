#pragma once

#include <cstdint>
#include <string_view>

// basic_type.hpp declares enumerators (basic_type::quality, ::tcmd, ...) named like the types in
// this header; GCC -Wshadow fires when the enumerators come second, so include it first.
#include "openiec61850/model/basic_type.hpp"
#include "openiec61850/core/result.hpp"
#include "openiec61850/mms/data.hpp"

// Enumerated attribute types of IEC 61850-7-2/7-3 and their MMS encodings (IEC 61850-8-1
// §8.1.3): CODED ENUMs are BIT STRINGs whose value is read MSB first (bit 0 is the high bit of
// the value), ENUMERATEDs are MMS integers.
//
// Decoding fails with errc::invalid_state when the MMS value has the wrong type and with
// errc::value_out_of_range for an integer outside the enumeration. Bit strings are read
// tolerantly: missing bits are zero and extra bits are ignored.

namespace openiec61850::model {

// Dbpos (7-3 DPC/DPS stVal): CODED ENUM, BIT STRING(2).
enum class dbpos : std::uint8_t { intermediate = 0, off = 1, on = 2, bad = 3 };

// Tcmd / StepControl (7-3 BSC/ISC ctlVal): CODED ENUM, BIT STRING(2).
enum class step_command : std::uint8_t { stop = 0, lower = 1, higher = 2, reserved = 3 };
using tcmd = step_command;

// orCat (7-3 Originator): ENUMERATED.
enum class orcat : std::uint8_t {
  not_supported = 0,
  bay_control = 1,
  station_control = 2,
  remote_control = 3,
  automatic_bay = 4,
  automatic_station = 5,
  automatic_remote = 6,
  maintenance = 7,
  process = 8,
};

// ctlModel (7-3 controllable CDCs): ENUMERATED.
enum class ctl_model : std::uint8_t {
  status_only = 0,
  direct_with_normal_security = 1,
  sbo_with_normal_security = 2,
  direct_with_enhanced_security = 3,
  sbo_with_enhanced_security = 4,
};

// Mod / Beh stVal (7-4 Annex A): ENUMERATED.
enum class behaviour : std::uint8_t { on = 1, on_blocked = 2, test = 3, test_blocked = 4, off = 5 };

// Health stVal (7-4): ENUMERATED.
enum class health : std::uint8_t { ok = 1, warning = 2, alarm = 3 };

// Check (7-2 §20.2.2, control services): PACKED LIST, BIT STRING(2).
//   bit 0 synchrocheck, bit 1 interlock-check
class check_conditions {
 public:
  static constexpr std::size_t bit_count = 2;

  constexpr check_conditions() noexcept = default;
  constexpr check_conditions(bool synchrocheck, bool interlock_check) noexcept
      : sync_(synchrocheck), interlock_(interlock_check) {}

  [[nodiscard]] constexpr bool synchrocheck() const noexcept { return sync_; }
  [[nodiscard]] constexpr bool interlock_check() const noexcept { return interlock_; }
  constexpr check_conditions& set_synchrocheck(bool on) noexcept {
    sync_ = on;
    return *this;
  }
  constexpr check_conditions& set_interlock_check(bool on) noexcept {
    interlock_ = on;
    return *this;
  }

  [[nodiscard]] mms::data to_mms() const;
  [[nodiscard]] static result<check_conditions> from_mms(const mms::data_ref& d) noexcept;

  friend constexpr bool operator==(check_conditions, check_conditions) noexcept = default;

 private:
  bool sync_ = false;
  bool interlock_ = false;
};

[[nodiscard]] mms::data to_mms(dbpos v);
[[nodiscard]] mms::data to_mms(step_command v);
[[nodiscard]] mms::data to_mms(orcat v);
[[nodiscard]] mms::data to_mms(ctl_model v);
[[nodiscard]] mms::data to_mms(behaviour v);
[[nodiscard]] mms::data to_mms(health v);

[[nodiscard]] result<dbpos> dbpos_from_mms(const mms::data_ref& d) noexcept;
[[nodiscard]] result<step_command> step_command_from_mms(const mms::data_ref& d) noexcept;
[[nodiscard]] result<orcat> orcat_from_mms(const mms::data_ref& d) noexcept;
[[nodiscard]] result<ctl_model> ctl_model_from_mms(const mms::data_ref& d) noexcept;
[[nodiscard]] result<behaviour> behaviour_from_mms(const mms::data_ref& d) noexcept;
[[nodiscard]] result<health> health_from_mms(const mms::data_ref& d) noexcept;

// Names as written in IEC 61850-7-3 / 7-4 ("intermediate-state", "bay-control", "sbo-with-
// enhanced-security", "on-blocked"...).
[[nodiscard]] std::string_view to_string(dbpos v) noexcept;
[[nodiscard]] std::string_view to_string(step_command v) noexcept;
[[nodiscard]] std::string_view to_string(orcat v) noexcept;
[[nodiscard]] std::string_view to_string(ctl_model v) noexcept;
[[nodiscard]] std::string_view to_string(behaviour v) noexcept;
[[nodiscard]] std::string_view to_string(health v) noexcept;

}  // namespace openiec61850::model
