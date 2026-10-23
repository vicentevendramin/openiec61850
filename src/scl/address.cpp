#include "openiec61850/scl/address.hpp"

#include "text.hpp"

namespace openiec61850::scl {
namespace {

result<std::optional<std::int64_t>> optional_int(const address& a, std::string_view type) {
  const auto* v = a.find(type);
  if (v == nullptr || detail::trim(*v).empty()) return std::optional<std::int64_t>{};
  const auto n = detail::parse_integer<std::int64_t>(*v);
  if (!n) return errc::malformed_encoding;
  return std::optional<std::int64_t>{*n};
}

result<byte_buffer> optional_selector(const address& a, std::string_view type) {
  const auto* v = a.find(type);
  if (v == nullptr) return byte_buffer{};
  return parse_hex_selector(*v);
}

// "1,3,9999,23", "1.3.9999.23" or "1 3 9999 23".
result<ber::oid> parse_ap_title(std::string_view text) {
  ber::oid o;
  auto rest = detail::trim(text);
  while (!rest.empty()) {
    const auto sep = rest.find_first_of(",. \t");
    const auto arc = detail::parse_integer<std::uint32_t>(rest.substr(0, sep));
    if (!arc || !o.push_back(*arc)) return errc::malformed_encoding;
    if (sep == std::string_view::npos) break;
    rest = detail::trim(rest.substr(sep + 1));
    if (rest.empty()) return errc::malformed_encoding;
  }
  if (!o.valid()) return errc::malformed_encoding;
  return o;
}

}  // namespace

result<byte_buffer> parse_hex_selector(std::string_view text) {
  byte_buffer out;
  int high = -1;
  for (char c : text) {
    if (detail::is_space(c)) continue;
    const int d = detail::hex_digit(c);
    if (d < 0) return errc::malformed_encoding;
    if (high < 0) {
      high = d;
    } else {
      out.push_back(static_cast<std::uint8_t>((high << 4) | d));
      high = -1;
    }
  }
  if (high >= 0) return errc::malformed_encoding;
  return out;
}

result<ap_address> parse_ap_address(const address& a) {
  ap_address out;
  if (const auto* v = a.find("IP")) out.ip = detail::trim(*v);
  if (const auto* v = a.find("IP-SUBNET")) out.ip_subnet = detail::trim(*v);
  if (const auto* v = a.find("IP-GATEWAY")) out.ip_gateway = detail::trim(*v);

  auto tsel = optional_selector(a, "OSI-TSEL");
  auto ssel = optional_selector(a, "OSI-SSEL");
  auto psel = optional_selector(a, "OSI-PSEL");
  if (!tsel || !ssel || !psel) return errc::malformed_encoding;
  out.t_selector = std::move(*tsel);
  out.s_selector = std::move(*ssel);
  out.p_selector = std::move(*psel);

  if (const auto* v = a.find("OSI-AP-Title"); v != nullptr && !detail::trim(*v).empty()) {
    auto t = parse_ap_title(*v);
    if (!t) return t.error();
    out.ap_title = *t;
  }
  auto aeq = optional_int(a, "OSI-AE-Qualifier");
  auto api = optional_int(a, "OSI-AP-Invoke");
  auto aei = optional_int(a, "OSI-AE-Invoke");
  if (!aeq || !api || !aei) return errc::malformed_encoding;
  out.ae_qualifier = *aeq;
  out.ap_invoke = *api;
  out.ae_invoke = *aei;
  return out;
}

result<ap_address> connected_ap_address(const document& doc, std::string_view ied_name,
                                        std::string_view ap_name) {
  const auto* cap = doc.comm.find(ied_name, ap_name);
  if (cap == nullptr) return errc::invalid_state;
  return parse_ap_address(cap->addr);
}

result<l2_address> parse_l2_address(const address& a) {
  l2_address out;
  const auto* mac = a.find("MAC-Address");
  const auto* appid = a.find("APPID");
  if (mac == nullptr || appid == nullptr) return errc::malformed_encoding;

  // Six hex octets separated by '-' (or ':').
  std::size_t n = 0;
  int digits = 0;
  unsigned octet = 0;
  for (char c : detail::trim(*mac)) {
    if (c == '-' || c == ':') {
      if (digits != 2) return errc::malformed_encoding;
      digits = 0;
      continue;
    }
    const int d = detail::hex_digit(c);
    if (d < 0 || digits == 2 || n == out.mac.size()) return errc::malformed_encoding;
    octet = (octet << 4) | static_cast<unsigned>(d);
    if (++digits == 2) {
      out.mac[n++] = static_cast<std::uint8_t>(octet);
      octet = 0;
    }
  }
  if (n != out.mac.size() || digits != 2) return errc::malformed_encoding;

  const auto id = detail::parse_hex_u32(*appid);
  if (!id || *id > 0xFFFF) return errc::malformed_encoding;
  out.app_id = static_cast<std::uint16_t>(*id);

  if (const auto* v = a.find("VLAN-ID")) {
    const auto vid = detail::parse_hex_u32(*v);
    if (!vid || *vid > 0xFFF) return errc::malformed_encoding;
    out.vlan_id = static_cast<std::uint16_t>(*vid);
  }
  if (const auto* v = a.find("VLAN-PRIORITY")) {
    const auto prio = detail::parse_integer<std::uint32_t>(*v);
    if (!prio || *prio > 7) return errc::malformed_encoding;
    out.vlan_priority = static_cast<std::uint8_t>(*prio);
  }
  return out;
}

}  // namespace openiec61850::scl
