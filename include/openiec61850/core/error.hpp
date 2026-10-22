#pragma once

#include <system_error>

namespace openiec61850 {

// Library-specific errors. Network and system errors are still reported as Asio's std::error_code.
enum class errc {
  ok = 0,
  truncated_input,     // input ended before the encoding was complete
  malformed_encoding,  // invalid encoding (BER, TPKT, SPDU...)
  length_overflow,     // declared length exceeds the limit or the buffer
  unsupported,         // valid per the standard but not implemented
  protocol_violation,  // the peer violated the protocol state machine
  buffer_too_small,    // output buffer too small for the encoding
  nesting_too_deep,    // TLV nesting exceeds the configured limit
  value_out_of_range,  // decoded value does not fit the requested type
  invalid_state,       // local operation not allowed in the current state
};

[[nodiscard]] const std::error_category& error_category() noexcept;

[[nodiscard]] inline std::error_code make_error_code(errc e) noexcept {
  return {static_cast<int>(e), error_category()};
}

}  // namespace openiec61850

template <>
struct std::is_error_code_enum<openiec61850::errc> : std::true_type {};
