#pragma once

#include <cstdint>
#include <initializer_list>

#include "openiec61850/core/result.hpp"
#include "openiec61850/mms/data.hpp"
#include "openiec61850/model/object_reference.hpp"

// Report control block bit sets (IEC 61850-7-2 §17.2, IEC 61850-8-1 §17.2). In every set bit i of
// the MMS BIT STRING (bit 0 = most significant bit of the first octet) is (1 << i) in raw().
//
// TrgOps / TrgCond, BIT STRING(6), and ReasonCode (ReasonForInclusion in reports):
//   bit 0 reserved
//   bit 1 data-change (dchg)
//   bit 2 quality-change (qchg)
//   bit 3 data-update (dupd)
//   bit 4 integrity
//   bit 5 general-interrogation
//   bit 6 application-trigger -- ReasonCode only, added in Ed.2 (BIT STRING(7)); Ed.1 reason
//                                codes have the six bits above
//
// OptFlds, BIT STRING(10):
//   bit 0 reserved
//   bit 1 sequence-number
//   bit 2 report-time-stamp
//   bit 3 reason-for-inclusion
//   bit 4 data-set-name
//   bit 5 data-reference
//   bit 6 buffer-overflow
//   bit 7 entryID
//   bit 8 conf-revision
//   bit 9 segmentation
//
// Edition notes: the bit positions of TrgOps and OptFlds are the same in Ed.1 and Ed.2; only the
// ReasonCode width differs (above). In both editions buffer-overflow and entryID are meaningful
// for BRCBs only, and segmentation is never configured by the client: the server sets it in the
// OptFlds of a report that is split into segments (SubSeqNum / MoreSegmentsFollow follow).
// optional_fields::configurable() drops the bits a client should not write.
//
// Decoding is tolerant: any BIT STRING length is accepted, missing bits read as zero and extra
// bits are ignored; errc::invalid_state when the value is not a bit-string.

namespace openiec61850::model {

enum class trigger : std::uint8_t {
  data_change = 1U << 1,
  quality_change = 1U << 2,
  data_update = 1U << 3,
  integrity = 1U << 4,
  general_interrogation = 1U << 5,
  application_trigger = 1U << 6,
};

class trigger_conditions {
 public:
  static constexpr std::size_t trg_ops_bit_count = 6;
  static constexpr std::size_t reason_code_bit_count = 7;
  static constexpr std::uint8_t mask = 0x7E;

  constexpr trigger_conditions() noexcept = default;
  // Bit 0 (reserved) and bits above 6 are dropped.
  [[nodiscard]] static constexpr trigger_conditions from_raw(std::uint8_t raw) noexcept {
    trigger_conditions t;
    t.bits_ = static_cast<std::uint8_t>(raw & mask);
    return t;
  }
  [[nodiscard]] static constexpr trigger_conditions of(std::initializer_list<trigger> ts) noexcept {
    trigger_conditions t;
    for (auto x : ts) t.set(x);
    return t;
  }
  [[nodiscard]] constexpr std::uint8_t raw() const noexcept { return bits_; }
  [[nodiscard]] constexpr bool empty() const noexcept { return bits_ == 0; }

  [[nodiscard]] constexpr bool has(trigger t) const noexcept {
    return (bits_ & static_cast<std::uint8_t>(t)) != 0;
  }
  constexpr trigger_conditions& set(trigger t, bool on = true) noexcept {
    const auto m = static_cast<unsigned>(t);
    bits_ = static_cast<std::uint8_t>(on ? (bits_ | m) : (bits_ & ~m));
    return *this;
  }
  [[nodiscard]] constexpr bool data_change() const noexcept { return has(trigger::data_change); }
  [[nodiscard]] constexpr bool quality_change() const noexcept {
    return has(trigger::quality_change);
  }
  [[nodiscard]] constexpr bool data_update() const noexcept { return has(trigger::data_update); }
  [[nodiscard]] constexpr bool integrity() const noexcept { return has(trigger::integrity); }
  [[nodiscard]] constexpr bool general_interrogation() const noexcept {
    return has(trigger::general_interrogation);
  }
  [[nodiscard]] constexpr bool application_trigger() const noexcept {
    return has(trigger::application_trigger);
  }

  // TrgOps, BIT STRING(6); application-trigger is not part of TrgOps and is dropped.
  [[nodiscard]] mms::data to_mms() const;
  // ReasonCode: BIT STRING(7) for Ed.2 and later, BIT STRING(6) for Ed.1 (errc::invalid_state
  // when application-trigger is set for Ed.1).
  [[nodiscard]] result<mms::data> to_mms_reason_code(edition e = edition::ed2) const;
  [[nodiscard]] static result<trigger_conditions> from_mms(const mms::data_ref& d) noexcept;

  friend constexpr bool operator==(trigger_conditions, trigger_conditions) noexcept = default;

 private:
  std::uint8_t bits_ = 0;
};

enum class optional_field : std::uint16_t {
  sequence_number = 1U << 1,
  report_time_stamp = 1U << 2,
  reason_for_inclusion = 1U << 3,
  data_set_name = 1U << 4,
  data_reference = 1U << 5,
  buffer_overflow = 1U << 6,
  entry_id = 1U << 7,
  conf_revision = 1U << 8,
  segmentation = 1U << 9,
};

class optional_fields {
 public:
  static constexpr std::size_t bit_count = 10;
  static constexpr std::uint16_t mask = 0x3FE;

  constexpr optional_fields() noexcept = default;
  // Bit 0 (reserved) and bits above 9 are dropped.
  [[nodiscard]] static constexpr optional_fields from_raw(std::uint16_t raw) noexcept {
    optional_fields o;
    o.bits_ = static_cast<std::uint16_t>(raw & mask);
    return o;
  }
  [[nodiscard]] static constexpr optional_fields of(
      std::initializer_list<optional_field> fs) noexcept {
    optional_fields o;
    for (auto f : fs) o.set(f);
    return o;
  }
  [[nodiscard]] constexpr std::uint16_t raw() const noexcept { return bits_; }

  [[nodiscard]] constexpr bool has(optional_field f) const noexcept {
    return (bits_ & static_cast<std::uint16_t>(f)) != 0;
  }
  constexpr optional_fields& set(optional_field f, bool on = true) noexcept {
    const auto m = static_cast<unsigned>(f);
    bits_ = static_cast<std::uint16_t>(on ? (bits_ | m) : (bits_ & ~m));
    return *this;
  }
  [[nodiscard]] constexpr bool sequence_number() const noexcept {
    return has(optional_field::sequence_number);
  }
  [[nodiscard]] constexpr bool report_time_stamp() const noexcept {
    return has(optional_field::report_time_stamp);
  }
  [[nodiscard]] constexpr bool reason_for_inclusion() const noexcept {
    return has(optional_field::reason_for_inclusion);
  }
  [[nodiscard]] constexpr bool data_set_name() const noexcept {
    return has(optional_field::data_set_name);
  }
  [[nodiscard]] constexpr bool data_reference() const noexcept {
    return has(optional_field::data_reference);
  }
  [[nodiscard]] constexpr bool buffer_overflow() const noexcept {
    return has(optional_field::buffer_overflow);
  }
  [[nodiscard]] constexpr bool entry_id() const noexcept { return has(optional_field::entry_id); }
  [[nodiscard]] constexpr bool conf_revision() const noexcept {
    return has(optional_field::conf_revision);
  }
  [[nodiscard]] constexpr bool segmentation() const noexcept {
    return has(optional_field::segmentation);
  }

  // The bits a client may write to the OptFlds of a BRCB (`buffered`) or URCB.
  [[nodiscard]] constexpr optional_fields configurable(bool buffered) const noexcept {
    auto m = static_cast<std::uint16_t>(mask & ~static_cast<unsigned>(optional_field::segmentation));
    if (!buffered) {
      m = static_cast<std::uint16_t>(m & ~(static_cast<unsigned>(optional_field::buffer_overflow) |
                                           static_cast<unsigned>(optional_field::entry_id)));
    }
    return from_raw(static_cast<std::uint16_t>(bits_ & m));
  }

  [[nodiscard]] mms::data to_mms() const;
  [[nodiscard]] static result<optional_fields> from_mms(const mms::data_ref& d) noexcept;

  friend constexpr bool operator==(optional_fields, optional_fields) noexcept = default;

 private:
  std::uint16_t bits_ = 0;
};

}  // namespace openiec61850::model
