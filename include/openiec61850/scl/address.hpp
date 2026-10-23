#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "openiec61850/ber/oid.hpp"
#include "openiec61850/core/bytes.hpp"
#include "openiec61850/core/result.hpp"
#include "openiec61850/scl/document.hpp"

// Typed views of <Address> P elements (IEC 61850-6 §9.3.3, P types of IEC 61850-8-1 / 9-2).

namespace openiec61850::scl {

// Connection parameters of an MMS access point (ConnectedAP/Address), to fill a client's
// association parameters. Selectors are hex strings in SCL ("0001"); OSI-AP-Title is a list of
// arcs separated by ',' (also accepted: '.' or spaces).
struct ap_address {
  std::string ip;
  std::string ip_subnet;
  std::string ip_gateway;
  byte_buffer t_selector;  // OSI-TSEL
  byte_buffer s_selector;  // OSI-SSEL
  byte_buffer p_selector;  // OSI-PSEL
  std::optional<ber::oid> ap_title;           // OSI-AP-Title
  std::optional<std::int64_t> ae_qualifier;   // OSI-AE-Qualifier
  std::optional<std::int64_t> ap_invoke;      // OSI-AP-Invoke
  std::optional<std::int64_t> ae_invoke;      // OSI-AE-Invoke
};

// Fails with errc::malformed_encoding when a selector, AP-title, qualifier or invoke id is not
// valid; absent P elements leave the members empty.
[[nodiscard]] result<ap_address> parse_ap_address(const address& a);

// The address of ConnectedAP iedName/apName in any subnetwork. errc::invalid_state when the
// ConnectedAP does not exist.
[[nodiscard]] result<ap_address> connected_ap_address(const document& doc,
                                                      std::string_view ied_name,
                                                      std::string_view ap_name);

// Layer 2 address of a GSE / SMV element: MAC-Address "01-0C-CD-01-00-01", APPID "3FFF",
// VLAN-ID "000" (hex), VLAN-PRIORITY "4" (decimal, 0..7).
struct l2_address {
  std::array<std::uint8_t, 6> mac{};
  std::uint16_t app_id = 0;
  std::uint16_t vlan_id = 0;
  std::uint8_t vlan_priority = 4;
};

// MAC-Address and APPID are required (errc::malformed_encoding when absent or invalid).
[[nodiscard]] result<l2_address> parse_l2_address(const address& a);

// Hex string to bytes ("00 01", "0001"); errc::malformed_encoding for odd or non-hex input.
[[nodiscard]] result<byte_buffer> parse_hex_selector(std::string_view text);

}  // namespace openiec61850::scl
