#pragma once

#include <system_error>

namespace openiec61850::server {

// Errors of the server API (model building, application updates). Network and association errors
// keep their own codes (asio, association::errc, openiec61850::errc).
enum class errc {
  ok = 0,
  object_not_found,  // no such LD / LN / DO / DA, data set or control block
  object_exists,     // a sibling with the same name already exists
  type_mismatch,     // a value does not match the type of the attribute
  invalid_model,     // inconsistent model (e.g. a structure without components)
  not_running,       // the server has been stopped
  access_denied,     // the attribute is managed by the server (e.g. RCB attributes)
  overloaded,        // too many updates pending: nothing was applied, try again later
};

[[nodiscard]] const std::error_category& error_category() noexcept;

[[nodiscard]] inline std::error_code make_error_code(errc e) noexcept {
  return {static_cast<int>(e), error_category()};
}

}  // namespace openiec61850::server

template <>
struct std::is_error_code_enum<openiec61850::server::errc> : std::true_type {};
