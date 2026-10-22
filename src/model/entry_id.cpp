#include "openiec61850/model/entry_id.hpp"

#include <algorithm>

namespace openiec61850::model {
namespace {

int hex_value(char c) noexcept {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

}  // namespace

result<entry_id> entry_id::from_bytes(byte_view b) noexcept {
  if (b.size() != size) return errc::value_out_of_range;
  bytes_type out{};
  std::copy(b.begin(), b.end(), out.begin());
  return entry_id{out};
}

result<entry_id> entry_id::parse_hex(std::string_view hex) noexcept {
  if (hex.size() != 2 * size) return errc::malformed_encoding;
  bytes_type out{};
  for (std::size_t i = 0; i < size; ++i) {
    const int hi = hex_value(hex[2 * i]);
    const int lo = hex_value(hex[2 * i + 1]);
    if (hi < 0 || lo < 0) return errc::malformed_encoding;
    out[i] = static_cast<std::uint8_t>((hi << 4) | lo);
  }
  return entry_id{out};
}

result<entry_id> entry_id::from_mms(const mms::data_ref& d) noexcept {
  auto os = d.owned() != nullptr ? d.owned()->as_octet_string() : d.view().as_octet_string();
  if (!os) return os.error();
  return from_bytes(*os);
}

std::string entry_id::to_hex() const {
  static constexpr char digits[] = "0123456789ABCDEF";
  std::string s;
  s.reserve(2 * size);
  for (auto b : bytes_) {
    s.push_back(digits[b >> 4]);
    s.push_back(digits[b & 0x0F]);
  }
  return s;
}

}  // namespace openiec61850::model
