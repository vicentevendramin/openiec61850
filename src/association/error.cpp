#include "openiec61850/association/error.hpp"

#include <string>

namespace openiec61850::association {
namespace {

class category final : public std::error_category {
 public:
  const char* name() const noexcept override { return "openiec61850.association"; }

  std::string message(int value) const override {
    switch (static_cast<errc>(value)) {
      case errc::ok: return "success";
      case errc::connection_refused: return "connection refused by the ISO session/presentation";
      case errc::association_rejected: return "association rejected";
      case errc::authentication_failed: return "authentication failed";
      case errc::initiate_error: return "MMS initiate failed";
      case errc::peer_aborted: return "association aborted by the peer";
      case errc::aborted: return "association aborted";
      case errc::released: return "association released";
      case errc::request_timed_out: return "request timed out";
      case errc::service_error: return "service error";
      case errc::request_rejected: return "request rejected";
      case errc::conclude_refused: return "conclude refused";
    }
    return "unknown error";
  }
};

}  // namespace

const std::error_category& error_category() noexcept {
  static const category instance;
  return instance;
}

}  // namespace openiec61850::association
