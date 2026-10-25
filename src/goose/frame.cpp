#include "openiec61850/goose/frame.hpp"

#include <algorithm>
#include <cstdio>

namespace openiec61850::goose {

namespace {

std::uint16_t load16(byte_view b, std::size_t off) noexcept {
  return static_cast<std::uint16_t>((static_cast<unsigned>(b[off]) << 8) | b[off + 1]);
}

void store16(byte_buffer& out, std::uint16_t v) {
  out.push_back(static_cast<std::uint8_t>(v >> 8));
  out.push_back(static_cast<std::uint8_t>(v & 0xFFU));
}

bool known_ether_type(std::uint16_t t) noexcept {
  return t == ethertype_goose || t == ethertype_sv || t == ethertype_gse_management;
}

int hex_digit(char c) noexcept {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

}  // namespace

std::uint16_t peek_ether_type(byte_view frame) noexcept {
  if (frame.size() < 14) return 0;
  const auto t = load16(frame, 12);
  if (t != ethertype_vlan) return t;
  if (frame.size() < 18) return 0;
  return load16(frame, 16);
}

result<frame_view> decode_frame(byte_view frame) noexcept {
  if (frame.size() < 14) return errc::truncated_input;
  frame_view v;
  std::copy_n(frame.begin(), 6, v.destination.begin());
  std::copy_n(frame.begin() + 6, 6, v.source.begin());
  std::size_t off = 12;
  std::uint16_t type = load16(frame, off);
  if (type == ethertype_vlan) {
    if (frame.size() < 18) return errc::truncated_input;
    v.vlan = vlan_tag::from_tci(load16(frame, 14));
    off = 16;
    type = load16(frame, off);
    if (type == ethertype_vlan) return errc::unsupported;
  }
  if (!known_ether_type(type)) return errc::unsupported;
  v.ether_type = type;
  off += 2;
  if (frame.size() < off + 8) return errc::truncated_input;
  v.app_id = load16(frame, off);
  v.length = load16(frame, off + 2);
  v.reserved1 = load16(frame, off + 4);
  v.reserved2 = load16(frame, off + 6);
  if (v.length < 8) return errc::malformed_encoding;
  if (v.length > frame.size() - off) return errc::length_overflow;
  v.apdu = frame.subspan(off + 8, v.length - 8U);
  return v;
}

std::size_t begin_frame(byte_buffer& out, const frame_header& h) {
  const std::size_t start = out.size();
  out.reserve(start + min_frame_size);
  out.insert(out.end(), h.destination.begin(), h.destination.end());
  out.insert(out.end(), h.source.begin(), h.source.end());
  if (h.vlan) {
    store16(out, ethertype_vlan);
    store16(out, h.vlan->tci());
  }
  store16(out, h.ether_type);
  store16(out, h.app_id);
  store16(out, 0);  // Length, patched by finish_frame()
  store16(out, h.reserved1);
  store16(out, h.reserved2);
  return start;
}

result<void> finish_frame(byte_buffer& out, std::size_t frame_start) {
  if (frame_start > out.size() || out.size() - frame_start < header_size) {
    return errc::invalid_state;
  }
  const std::size_t appid_off =
      frame_start + (load16(out, frame_start + 12) == ethertype_vlan ? 18 : 14);
  if (out.size() - frame_start < appid_off - frame_start + 8) return errc::invalid_state;
  const std::size_t length = out.size() - appid_off;
  if (length > 0xFFFF) return errc::length_overflow;
  out[appid_off + 2] = static_cast<std::uint8_t>(length >> 8);
  out[appid_off + 3] = static_cast<std::uint8_t>(length & 0xFFU);
  if (out.size() - frame_start < min_frame_size) out.resize(frame_start + min_frame_size, 0);
  return {};
}

result<mac_address> parse_mac(std::string_view text) noexcept {
  mac_address mac{};
  std::size_t i = 0;
  for (std::size_t n = 0; n < 6; ++n) {
    if (n > 0 && i < text.size() && (text[i] == '-' || text[i] == ':')) ++i;
    if (i + 2 > text.size()) return errc::malformed_encoding;
    const int hi = hex_digit(text[i]);
    const int lo = hex_digit(text[i + 1]);
    if (hi < 0 || lo < 0) return errc::malformed_encoding;
    mac[n] = static_cast<std::uint8_t>((hi << 4) | lo);
    i += 2;
  }
  if (i != text.size()) return errc::malformed_encoding;
  return mac;
}

std::string to_string(const mac_address& mac) {
  char buf[18];
  std::snprintf(buf, sizeof buf, "%02X-%02X-%02X-%02X-%02X-%02X", mac[0], mac[1], mac[2], mac[3],
                mac[4], mac[5]);
  return buf;
}

}  // namespace openiec61850::goose
