#pragma once

#include <cstdint>
#include <optional>
#include <system_error>

#include "openiec61850/association/types.hpp"
#include "openiec61850/client/control.hpp"

namespace openiec61850::client {

// What the server said when an operation failed, beyond the error code.
//
// The services return result<T> with a plain std::error_code (client/error.hpp), which cannot
// carry the MMS ServiceError class/code/additionalCode/additionalDescription, the Reject reason
// or the LastApplError of a refused control. Every service of client and control therefore has
// an overload taking an `error_details&` as its last argument: it behaves exactly like the
// overload without it and, before completing, fills `details`:
//
//   code               the operation's error (empty on success, and then every member is empty)
//   service_error      the ServiceError of a Confirmed-ErrorPDU (ISO 9506-2 §7.5.4), with
//   modifier_position  its modifierPosition when sent
//   reject             the RejectPDU naming the request (ISO 9506-2 §7.5.5)
//   last_appl_error    control services: the LastApplError the server sent for the object (a
//                      refusal or a negative CommandTermination)
//
// When an operation issues several requests (enable_reporting(), get_control()...), the members
// describe the last request that failed. They are empty when the error was not a server answer
// (timeouts, connection loss, local misuse, protocol violations). A data access error of one
// item of read_many() / write_many() / get_data_set_values() / set_data_set_values() is not an
// operation failure and leaves `details` empty.
//
// Threading: the object belongs to one call. It is written on the client's strand while the
// operation runs and once more on completion, and must neither be accessed nor destroyed until
// the operation completes (with co_await this holds naturally; with transport::spawn keep it
// alive in the handler, e.g. in a shared_ptr). Concurrent operations use separate objects.
struct error_details {
  std::error_code code;
  std::optional<association::service_error_info> service_error;
  std::optional<std::uint32_t> modifier_position;
  std::optional<association::reject_info> reject;
  std::optional<client::last_appl_error> last_appl_error;

  // True when the server's answer is known (a ServiceError, a Reject or a LastApplError).
  [[nodiscard]] bool from_server() const noexcept {
    return service_error.has_value() || reject.has_value() || last_appl_error.has_value();
  }
};

}  // namespace openiec61850::client
