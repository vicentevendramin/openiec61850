#pragma once

#include <system_error>

namespace openiec61850::association {

// Errors of the MMS association layer. Lower layers keep reporting their own codes: socket and
// timeout errors as Asio's std::error_code (asio::error::eof, asio::error::timed_out...),
// COTP refusal as std::errc::connection_refused, and openiec61850::errc for encoding errors,
// protocol violations by the peer and local API misuse (invalid_state).
enum class errc {
  ok = 0,
  connection_refused,     // refused by the peer's session or presentation provider/user (RF, CPR)
                          // without an AARE
  association_rejected,   // AARE with result rejected (other than for authentication)
  authentication_failed,  // AARE rejected with an authentication diagnostic (X.227 §7.1.5.4)
  initiate_error,         // MMS Initiate-ErrorPDU, or no usable Initiate-ResponsePDU
  peer_aborted,           // A-ABORT / P-ABORT / S-ABORT from the peer
  aborted,                // aborted locally (abort() or destruction of the handle)
  released,               // the association has been released (Conclude + A-RELEASE)
  request_timed_out,      // no response within the request timeout
  service_error,          // Confirmed-ErrorPDU (details in request_error::service_error)
  request_rejected,       // RejectPDU (details in request_error::reject)
  conclude_refused,       // Conclude-ErrorPDU: the association stays established
};

[[nodiscard]] const std::error_category& error_category() noexcept;

[[nodiscard]] inline std::error_code make_error_code(errc e) noexcept {
  return {static_cast<int>(e), error_category()};
}

}  // namespace openiec61850::association

template <>
struct std::is_error_code_enum<openiec61850::association::errc> : std::true_type {};
