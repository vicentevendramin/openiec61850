#pragma once

#include <array>
#include <compare>
#include <cstdint>
#include <string>
#include <string_view>

#include "openiec61850/core/bytes.hpp"
#include "openiec61850/core/result.hpp"
#include "openiec61850/mms/data.hpp"

// EntryID (IEC 61850-7-2 §17.2.2.13, IEC 61850-8-1 §17.2.2): OCTET STRING(8) identifying an
// entry of a BRCB buffer. The value is opaque to the client: it has no ordering semantics and is
// only echoed back (written to EntryID) to resume reporting after the identified entry. An
// all-zero EntryID denotes "no entry" (reporting restarts from the oldest buffered entry).

namespace openiec61850::model {

class entry_id {
 public:
  static constexpr std::size_t size = 8;
  using bytes_type = std::array<std::uint8_t, size>;

  constexpr entry_id() noexcept = default;
  constexpr explicit entry_id(const bytes_type& b) noexcept : bytes_(b) {}

  // errc::value_out_of_range unless exactly 8 octets.
  [[nodiscard]] static result<entry_id> from_bytes(byte_view b) noexcept;
  // 16 hexadecimal digits (either case); errc::malformed_encoding otherwise.
  [[nodiscard]] static result<entry_id> parse_hex(std::string_view hex) noexcept;
  // errc::invalid_state unless an octet-string; errc::value_out_of_range unless 8 octets.
  [[nodiscard]] static result<entry_id> from_mms(const mms::data_ref& d) noexcept;

  [[nodiscard]] constexpr const bytes_type& bytes() const noexcept { return bytes_; }
  [[nodiscard]] constexpr bool is_zero() const noexcept {
    for (auto b : bytes_) {
      if (b != 0) return false;
    }
    return true;
  }
  // Upper-case hex, 16 digits.
  [[nodiscard]] std::string to_hex() const;
  [[nodiscard]] mms::data to_mms() const { return mms::data::octet_string(bytes_); }

  friend constexpr bool operator==(const entry_id&, const entry_id&) noexcept = default;
  // Lexicographic on the octets, for use as a container key only.
  friend constexpr auto operator<=>(const entry_id&, const entry_id&) noexcept = default;

 private:
  bytes_type bytes_{};
};

}  // namespace openiec61850::model
