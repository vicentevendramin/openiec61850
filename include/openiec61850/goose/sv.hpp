#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

#include "openiec61850/core/bytes.hpp"
#include "openiec61850/core/result.hpp"
#include "openiec61850/goose/frame.hpp"
#include "openiec61850/mms/data.hpp"
#include "openiec61850/mms/list_view.hpp"
#include "openiec61850/model/quality.hpp"

// Sampled Values APDU (IEC 61850-9-2 §8.5, Table 14):
//
//   savPdu ::= [APPLICATION 0] IMPLICIT SEQUENCE {
//     noASDU    [0] IMPLICIT INTEGER (1..65535),
//     security  [1] ANY OPTIONAL,                 -- reserved for IEC 62351-6
//     asdu      [2] IMPLICIT SEQUENCE OF ASDU }
//
//   ASDU ::= SEQUENCE {
//     svID      [0] IMPLICIT VisibleString,
//     datSet    [1] IMPLICIT VisibleString OPTIONAL,
//     smpCnt    [2] IMPLICIT OCTET STRING (SIZE(2)),   -- INT16U, big endian
//     confRev   [3] IMPLICIT OCTET STRING (SIZE(4)),   -- INT32U
//     refrTm    [4] IMPLICIT UtcTime OPTIONAL,
//     smpSynch  [5] IMPLICIT OCTET STRING (SIZE(1)),   -- 0 none, 1 local, 2 global; Ed.2:
//                                                      -- 5..254 grandmaster identity
//     smpRate   [6] IMPLICIT OCTET STRING (SIZE(2)) OPTIONAL,
//     sample    [7] IMPLICIT OCTET STRING,             -- seqData: data set values, fixed encoding
//     smpMod    [8] IMPLICIT OCTET STRING (SIZE(2)) OPTIONAL,
//     gmIdentity [9] IMPLICIT OCTET STRING (SIZE(8)) OPTIONAL }  -- Ed.2.1
//
// seqData is the fixed-length encoding of the data set members (9-2 §8.6). For the 9-2 LE profile
// ("Implementation guideline for digital interface to instrument transformers using IEC
// 61850-9-2") it is 8 x (INT32 value, 32-bit quality): IA, IB, IC, IN, VA, VB, VC, VN; see
// the le namespace below. The security extension is never generated and only handed out raw.

namespace openiec61850::sv {

using goose::frame_header;
using goose::frame_view;
using goose::mac_address;
using goose::vlan_tag;

// smpMod (9-2 §8.5.2): meaning of smpRate.
enum class sample_mode : std::uint16_t {
  samples_per_period = 0,
  samples_per_second = 1,
  seconds_per_sample = 2,
};

namespace smp_synch {
inline constexpr std::uint8_t none = 0;
inline constexpr std::uint8_t local = 1;
inline constexpr std::uint8_t global = 2;
}  // namespace smp_synch

struct asdu_view {
  std::string_view sv_id;
  std::optional<std::string_view> dat_set;
  std::uint16_t smp_cnt = 0;
  std::uint32_t conf_rev = 0;
  std::optional<mms::utc_time> refr_tm;
  std::uint8_t smp_synch = 0;
  std::optional<std::uint16_t> smp_rate;
  byte_view seq_data;
  std::optional<std::uint16_t> smp_mod;
  std::optional<std::array<std::uint8_t, 8>> gm_identity;
};

// Decodes one ASDU SEQUENCE (the element, including its 0x30 header).
[[nodiscard]] result<asdu_view> decode_asdu(const ber::tlv& element) noexcept;

struct pdu_view {
  std::uint16_t no_asdu = 0;
  std::optional<byte_view> security;
  // Validated ASDUs; there are exactly no_asdu of them.
  mms::list_view<asdu_view> asdus;
};

// Decodes one savPdu. Errors: errc::malformed_encoding (layout, field sizes, noASDU different
// from the number of ASDUs or 0), plus the BER errors.
[[nodiscard]] result<pdu_view> decode_pdu(byte_view apdu) noexcept;

struct message_view {
  frame_view frame;
  pdu_view pdu;
};

// Decodes a whole SV frame (errc::unsupported for another EtherType).
[[nodiscard]] result<message_view> decode(byte_view frame) noexcept;

// Encoder input; strings and seq_data are borrowed.
struct asdu {
  std::string_view sv_id;
  std::optional<std::string_view> dat_set;
  std::uint16_t smp_cnt = 0;
  std::uint32_t conf_rev = 1;
  std::optional<mms::utc_time> refr_tm;
  std::uint8_t smp_synch = smp_synch::none;
  std::optional<std::uint16_t> smp_rate;
  byte_view seq_data;
  std::optional<std::uint16_t> smp_mod;
  std::optional<std::array<std::uint8_t, 8>> gm_identity;
};

// Appends a savPdu with the given ASDUs (errc::invalid_state when empty or more than 65535).
[[nodiscard]] result<void> encode_pdu(std::span<const asdu> asdus, byte_buffer& out);
// Appends a complete frame (header.ether_type is forced to ethertype_sv).
[[nodiscard]] result<void> encode(const frame_header& header, std::span<const asdu> asdus,
                                  byte_buffer& out);

// ------------------------------------------------------------------ fixed-length values

// Quality in seqData (9-2 §8.6, Table 15): 32 bits, big endian, bit i of the 7-3 Quality is
// (1 << i) of the integer except validity, which is the integer value of bits 0-1:
// 0 good, 1 invalid, 2 reserved, 3 questionable. Bit 13 is "derived" (9-2 Ed.2; 9-2 LE).
struct quality32 {
  static constexpr std::uint32_t validity_mask = 0x3;
  static constexpr std::uint32_t derived = 1U << 13;

  std::uint32_t raw = 0;

  [[nodiscard]] constexpr model::validity validity() const noexcept {
    return static_cast<model::validity>(raw & validity_mask);
  }
  [[nodiscard]] constexpr bool is_derived() const noexcept { return (raw & derived) != 0; }

  [[nodiscard]] static constexpr quality32 from_quality(model::quality q,
                                                        bool is_derived = false) noexcept {
    std::uint32_t v = static_cast<std::uint32_t>(q.raw()) & ~validity_mask;
    v |= static_cast<std::uint32_t>(q.validity());
    if (is_derived) v |= derived;
    return {v};
  }
  [[nodiscard]] constexpr model::quality to_quality() const noexcept {
    auto q = model::quality::from_raw(static_cast<std::uint16_t>(raw & 0x1FFCU));
    q.set_validity(validity());
    return q;
  }
  friend constexpr bool operator==(quality32, quality32) noexcept = default;
};

// One INT32 + quality pair (8 octets in seqData).
struct analog_sample {
  std::int32_t value = 0;
  quality32 q;
  friend constexpr bool operator==(const analog_sample&, const analog_sample&) noexcept = default;
};

// Decodes seqData as consecutive INT32 + quality pairs into `out`; returns the number decoded.
// errc::malformed_encoding unless the size is a multiple of 8; errc::buffer_too_small when
// `out` is shorter than the data.
[[nodiscard]] result<std::size_t> decode_analog_samples(byte_view seq_data,
                                                        std::span<analog_sample> out) noexcept;
// Appends the samples as seqData.
void encode_analog_samples(std::span<const analog_sample> samples, byte_buffer& out);

// Big-endian fixed-length helpers for other data set layouts (9-2 §8.6: INT32 4 octets,
// FLOAT32 4 octets IEEE 754, Timestamp 8 octets, BOOLEAN 1 octet...). Preconditions: enough
// octets at `offset`.
[[nodiscard]] std::int32_t load_int32(byte_view data, std::size_t offset) noexcept;
[[nodiscard]] std::uint32_t load_uint32(byte_view data, std::size_t offset) noexcept;
[[nodiscard]] float load_float32(byte_view data, std::size_t offset) noexcept;
void store_int32(byte_buffer& out, std::int32_t v);
void store_uint32(byte_buffer& out, std::uint32_t v);
void store_float32(byte_buffer& out, float v);

// 9-2 LE profile: one ASDU carries 4 currents and 4 voltages, scaled integers.
namespace le {

inline constexpr std::size_t channel_count = 8;
inline constexpr std::size_t seq_data_size = channel_count * 8;  // 64 octets
inline constexpr double amperes_per_lsb = 0.001;  // 1 mA
inline constexpr double volts_per_lsb = 0.01;     // 10 mV
// 80 samples per nominal period, one ASDU per frame (protection); 256 per period, 8 ASDUs per
// frame (metering).
inline constexpr std::uint16_t samples_per_period_protection = 80;
inline constexpr std::uint16_t samples_per_period_metering = 256;

enum channel : std::size_t { ia = 0, ib, ic, in, va, vb, vc, vn };

struct samples {
  std::array<analog_sample, channel_count> channels{};

  [[nodiscard]] double current(std::size_t i) const noexcept {
    return channels[i].value * amperes_per_lsb;
  }
  [[nodiscard]] double voltage(std::size_t i) const noexcept {
    return channels[4 + i].value * volts_per_lsb;
  }
  // Rounded to the nearest LSB and saturated to INT32.
  void set_current(std::size_t i, double amperes, quality32 q = {}) noexcept;
  void set_voltage(std::size_t i, double volts, quality32 q = {}) noexcept;

  friend constexpr bool operator==(const samples&, const samples&) noexcept = default;
};

[[nodiscard]] std::array<std::uint8_t, seq_data_size> encode(const samples& s) noexcept;
// errc::malformed_encoding unless seq_data is exactly 64 octets.
[[nodiscard]] result<samples> decode(byte_view seq_data) noexcept;

// smpCnt wraps at the number of samples per second: 4000 / 4800 (80 per period at 50 / 60 Hz),
// 12800 / 15360 (256 per period).
[[nodiscard]] constexpr std::uint16_t samples_per_second(std::uint16_t per_period,
                                                         std::uint16_t frequency_hz) noexcept {
  return static_cast<std::uint16_t>(per_period * frequency_hz);
}

}  // namespace le

}  // namespace openiec61850::sv
