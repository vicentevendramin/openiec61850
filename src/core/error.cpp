#include "openiec61850/core/error.hpp"

#include <string>

namespace openiec61850 {
namespace {

class category final : public std::error_category {
 public:
  const char* name() const noexcept override { return "openiec61850"; }

  std::string message(int value) const override {
    switch (static_cast<errc>(value)) {
      case errc::ok: return "success";
      case errc::truncated_input: return "truncated input";
      case errc::malformed_encoding: return "malformed encoding";
      case errc::length_overflow: return "length overflow";
      case errc::unsupported: return "unsupported feature";
      case errc::protocol_violation: return "protocol violation";
      case errc::buffer_too_small: return "buffer too small";
      case errc::nesting_too_deep: return "nesting too deep";
    }
    return "unknown error";
  }
};

}  // namespace

const std::error_category& error_category() noexcept {
  static const category instance;
  return instance;
}

}  // namespace openiec61850
