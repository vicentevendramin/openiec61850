#include "openiec61850/model/functional_constraint.hpp"

#include <array>

namespace openiec61850::model {
namespace {

constexpr std::array<std::string_view, functional_constraint_count> codes{
    "ST", "MX", "SP", "SV", "CF", "DC", "SG", "SE", "SR", "OR", "BL",
    "EX", "CO", "US", "MS", "RP", "BR", "LG", "GO", "GS", "XX"};

}  // namespace

std::string_view to_string(functional_constraint f) noexcept {
  const auto i = static_cast<std::size_t>(f);
  return i < codes.size() ? codes[i] : std::string_view{};
}

std::optional<functional_constraint> parse_functional_constraint(std::string_view code) noexcept {
  if (code.size() != 2) return std::nullopt;
  for (std::size_t i = 0; i < codes.size(); ++i) {
    if (codes[i] == code) return static_cast<functional_constraint>(i);
  }
  return std::nullopt;
}

}  // namespace openiec61850::model
