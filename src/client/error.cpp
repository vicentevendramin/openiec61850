#include "openiec61850/client/error.hpp"

#include <string>

namespace openiec61850::client {
namespace {

class category final : public std::error_category {
 public:
  const char* name() const noexcept override { return "openiec61850.client"; }

  std::string message(int value) const override {
    switch (static_cast<errc>(value)) {
      case errc::ok: return "success";
      case errc::not_connected: return "no association established";
      case errc::object_not_found: return "object not found";
      case errc::access_denied: return "object access denied";
      case errc::object_exists: return "object already exists";
      case errc::object_invalidated: return "object invalidated";
      case errc::hardware_fault: return "hardware fault";
      case errc::temporarily_unavailable: return "temporarily unavailable";
      case errc::invalid_address: return "invalid address";
      case errc::type_unsupported: return "type unsupported";
      case errc::type_inconsistent: return "type inconsistent";
      case errc::object_attribute_inconsistent: return "object attribute inconsistent";
      case errc::access_unsupported: return "object access unsupported";
      case errc::value_invalid: return "object value invalid";
      case errc::type_mismatch: return "unexpected value type";
      case errc::not_deleted: return "object not deleted";
      case errc::recovery_failed: return "association recovery failed";
      case errc::select_failed: return "select failed";
      case errc::termination_timeout: return "command termination timed out";
      case errc::control_model_mismatch: return "service not available in the control model";
    }
    return "unknown error";
  }
};

}  // namespace

const std::error_category& error_category() noexcept {
  static const category instance;
  return instance;
}

errc to_errc(mms::data_access_error e) noexcept {
  using dae = mms::data_access_error;
  switch (e) {
    case dae::object_invalidated: return errc::object_invalidated;
    case dae::hardware_fault: return errc::hardware_fault;
    case dae::temporarily_unavailable: return errc::temporarily_unavailable;
    case dae::object_access_denied: return errc::access_denied;
    case dae::object_undefined: return errc::object_not_found;
    case dae::invalid_address: return errc::invalid_address;
    case dae::type_unsupported: return errc::type_unsupported;
    case dae::type_inconsistent: return errc::type_inconsistent;
    case dae::object_attribute_inconsistent: return errc::object_attribute_inconsistent;
    case dae::object_access_unsupported: return errc::access_unsupported;
    case dae::object_non_existent: return errc::object_not_found;
    case dae::object_value_invalid: return errc::value_invalid;
  }
  return errc::value_invalid;
}

}  // namespace openiec61850::client
