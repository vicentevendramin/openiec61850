#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "openiec61850/core/bytes.hpp"
#include "openiec61850/core/result.hpp"

// Layer 2 framing shared by GOOSE (IEC 61850-8-1 Annex C) and Sampled Values (IEC 61850-9-2 §5,
// Annex) messages:
//
//   octets  0-5   destination MAC address (multicast 01-0C-CD-01-xx-xx GOOSE, 01-0C-CD-04-xx-xx SV)
//   octets  6-11  source MAC address
//   [octets 12-15 IEEE 802.1Q tag: TPID 0x8100, TCI = priority (3) | DEI (1) | VLAN ID (12)]
//   octets  +0-1  EtherType: 0x88B8 GOOSE, 0x88B9 GSE management, 0x88BA SV
//   octets  +2-3  APPID
//   octets  +4-5  Length: octets from APPID up to the end of the APDU (8 + APDU length)
//   octets  +6-7  Reserved1: bit 15 = Simulation (Ed.2, 8-1 §C.2.3.1 / 9-2 §5.3.3.4), the other
//                 bits are reserved (IEC 62351-6 uses them for the security extension length)
//   octets  +8-9  Reserved2 (IEC 62351-6: CRC of the header)
//   octets +10-   APDU, then padding up to the 60-octet Ethernet minimum (not counted in Length)
//
// The frames handled here never include the Ethernet FCS.

namespace openiec61850::goose {

using mac_address = std::array<std::uint8_t, 6>;

inline constexpr std::uint16_t ethertype_vlan = 0x8100;
inline constexpr std::uint16_t ethertype_goose = 0x88B8;
inline constexpr std::uint16_t ethertype_gse_management = 0x88B9;
inline constexpr std::uint16_t ethertype_sv = 0x88BA;

inline constexpr std::uint16_t reserved1_simulation = 0x8000;

// Header size up to (and including) Reserved2, without / with an 802.1Q tag.
inline constexpr std::size_t header_size = 22;
inline constexpr std::size_t header_size_vlan = 26;
// Minimum Ethernet frame without FCS; shorter frames are zero-padded by the encoders.
inline constexpr std::size_t min_frame_size = 60;

// Recommended multicast ranges (IEC 61850-8-1 Annex B, 9-2 Annex C) and APPID ranges.
inline constexpr mac_address goose_multicast_base{0x01, 0x0C, 0xCD, 0x01, 0x00, 0x00};
inline constexpr mac_address sv_multicast_base{0x01, 0x0C, 0xCD, 0x04, 0x00, 0x00};
inline constexpr std::uint16_t goose_app_id_default = 0x0000;  // GOOSE: 0x0000..0x3FFF
inline constexpr std::uint16_t sv_app_id_default = 0x4000;     // SV: 0x4000..0x7FFF

// IEEE 802.1Q tag control information. Priority 4 is the default of IEC 61850-8-1 for GOOSE
// and 9-2 for SV; VLAN ID 0 means priority tagging only.
struct vlan_tag {
  std::uint8_t priority = 4;  // 0..7
  bool dei = false;
  std::uint16_t id = 0;  // 0..4095

  [[nodiscard]] constexpr std::uint16_t tci() const noexcept {
    return static_cast<std::uint16_t>(((priority & 7U) << 13) | (dei ? 0x1000U : 0U) |
                                      (id & 0x0FFFU));
  }
  [[nodiscard]] static constexpr vlan_tag from_tci(std::uint16_t tci) noexcept {
    return {static_cast<std::uint8_t>(tci >> 13), (tci & 0x1000U) != 0,
            static_cast<std::uint16_t>(tci & 0x0FFFU)};
  }
  friend constexpr bool operator==(const vlan_tag&, const vlan_tag&) noexcept = default;
};

// What an encoder writes in front of an APDU.
struct frame_header {
  mac_address destination{};
  mac_address source{};
  std::optional<vlan_tag> vlan;
  std::uint16_t ether_type = ethertype_goose;
  std::uint16_t app_id = 0;
  std::uint16_t reserved1 = 0;
  std::uint16_t reserved2 = 0;
};

// A decoded frame header; `apdu` points into the input.
struct frame_view {
  mac_address destination{};
  mac_address source{};
  std::optional<vlan_tag> vlan;
  std::uint16_t ether_type = 0;
  std::uint16_t app_id = 0;
  std::uint16_t length = 0;
  std::uint16_t reserved1 = 0;
  std::uint16_t reserved2 = 0;
  byte_view apdu;

  [[nodiscard]] bool simulation() const noexcept { return (reserved1 & reserved1_simulation) != 0; }
};

// Decodes the Ethernet / 802.1Q / APPID header of a GOOSE, GSE management or SV frame.
// Errors: errc::truncated_input (frame shorter than the header), errc::unsupported (another
// EtherType, or stacked 802.1Q tags), errc::length_overflow (Length beyond the frame) and
// errc::malformed_encoding (Length below 8). Octets after Length (padding) are ignored.
[[nodiscard]] result<frame_view> decode_frame(byte_view frame) noexcept;

// Cheap pre-filter: the EtherType of a frame (after an optional 802.1Q tag), or 0.
[[nodiscard]] std::uint16_t peek_ether_type(byte_view frame) noexcept;

// Appends the header with a zero Length and returns the offset of the frame start, to be passed
// to finish_frame() once the APDU has been appended.
std::size_t begin_frame(byte_buffer& out, const frame_header& h);
// Patches Length and pads the frame to min_frame_size. errc::length_overflow when the APDU does
// not fit Length (65535 - 8 octets); errc::invalid_state for an offset not from begin_frame().
result<void> finish_frame(byte_buffer& out, std::size_t frame_start);

// "01-0C-CD-01-00-01" (also accepted: ':' separators or none). errc::malformed_encoding otherwise.
[[nodiscard]] result<mac_address> parse_mac(std::string_view text) noexcept;
// "01-0C-CD-01-00-01".
[[nodiscard]] std::string to_string(const mac_address& mac);

[[nodiscard]] constexpr bool is_multicast(const mac_address& mac) noexcept {
  return (mac[0] & 1U) != 0;
}

}  // namespace openiec61850::goose
