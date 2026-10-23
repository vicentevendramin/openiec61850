#pragma once

#include <system_error>

#include "openiec61850/mms/pdu.hpp"

namespace openiec61850::client {

// Errors of the ACSI client. The layers below keep reporting their own codes:
// association::errc for the association and request failures (service_error, request_rejected,
// request_timed_out, released, peer_aborted...), socket errors as Asio's std::error_code and
// openiec61850::errc for encoding errors, protocol violations by the server
// (openiec61850::errc::protocol_violation) and local API misuse (openiec61850::errc::invalid_state).
//
// The DataAccessError values (ISO 9506-2 §14.4.3) of Read/Write results map one-to-one onto the
// codes from object_invalidated to value_invalid (object-undefined and object-non-existent both
// map to object_not_found). A Confirmed-ErrorPDU whose class/code names a missing object
// (definition/object-undefined, access/object-non-existent), an access violation
// (access/object-access-denied) or an existing object (definition/object-exists) is mapped to
// object_not_found, access_denied and object_exists; other service errors stay
// association::errc::service_error.
enum class errc {
  ok = 0,
  not_connected,            // no association: recovery in progress, or the client is closed
  object_not_found,         // object-undefined / object-non-existent
  access_denied,            // object-access-denied
  object_exists,            // definition/object-exists (e.g. CreateDataSet on an existing name)
  object_invalidated,
  hardware_fault,
  temporarily_unavailable,
  invalid_address,
  type_unsupported,
  type_inconsistent,
  object_attribute_inconsistent,
  access_unsupported,       // object-access-unsupported
  value_invalid,            // object-value-invalid
  type_mismatch,            // a value has an MMS type other than the one expected
  not_deleted,              // DeleteDataSet matched the data set but the server kept it
  recovery_failed,          // association recovery gave up (see connection_event::failed)
  // Control services (client/control.hpp):
  select_failed,            // Select (Read of SBO) returned "" without a LastApplError
  termination_timeout,      // no CommandTermination within control_options::termination_timeout
  control_model_mismatch,   // the service does not exist in the object's ctlModel
};

[[nodiscard]] const std::error_category& error_category() noexcept;

[[nodiscard]] inline std::error_code make_error_code(errc e) noexcept {
  return {static_cast<int>(e), error_category()};
}

[[nodiscard]] errc to_errc(mms::data_access_error e) noexcept;

}  // namespace openiec61850::client

template <>
struct std::is_error_code_enum<openiec61850::client::errc> : std::true_type {};
