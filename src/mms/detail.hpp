#pragma once

#include <cstddef>
#include <string_view>

#include "openiec61850/ber/decode.hpp"
#include "openiec61850/core/bytes.hpp"
#include "openiec61850/core/result.hpp"
#include "openiec61850/mms/data.hpp"

namespace openiec61850::mms::detail {

// Validates one Data element; `depth` is the number of enclosing array/structure levels.
[[nodiscard]] result<void> validate_data(const ber::tlv& e, const decode_options& opts,
                                         std::size_t depth) noexcept;

// list_view element decoder for validated Data.
[[nodiscard]] result<data_view> make_data_view(const ber::tlv& e) noexcept;

[[nodiscard]] inline byte_view as_bytes(std::string_view s) noexcept {
  return {reinterpret_cast<const std::uint8_t*>(s.data()), s.size()};
}

}  // namespace openiec61850::mms::detail
