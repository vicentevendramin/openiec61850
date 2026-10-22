#pragma once

#include <cstdint>
#include <optional>
#include <string_view>

namespace openiec61850::model {

// Functional constraints (IEC 61850-7-2 §6.2 / Ed.2 table 20). The enumerator values are local
// to this library and never appear on the wire; MMS carries the two-letter code (8-1 §8.1.3.3).
enum class functional_constraint : std::uint8_t {
  ST,  // status information
  MX,  // measurands (analogue values)
  SP,  // setting (outside setting groups)
  SV,  // substitution
  CF,  // configuration
  DC,  // description
  SG,  // setting group (read the active group)
  SE,  // setting group editable
  SR,  // service response / service tracking (Ed.2)
  OR,  // operate received (Ed.2)
  BL,  // blocking (Ed.2)
  EX,  // extended definition (naming of the data model)
  CO,  // control
  US,  // unicast sampled value control block
  MS,  // multicast sampled value control block
  RP,  // unbuffered report control block
  BR,  // buffered report control block
  LG,  // log control block
  GO,  // GOOSE control block
  GS,  // GSSE control block (Ed.1 only)
  XX,  // wildcard "all FCs" accepted by some ACSI services; has no MMS mapping
};

inline constexpr std::size_t functional_constraint_count = 21;

using fc = functional_constraint;

// Two-letter code, e.g. "ST".
[[nodiscard]] std::string_view to_string(functional_constraint f) noexcept;
// Exact, case-sensitive match of the two-letter code.
[[nodiscard]] std::optional<functional_constraint> parse_functional_constraint(
    std::string_view code) noexcept;

// True for the FCs naming control blocks (RP, BR, LG, GO, GS, US, MS).
[[nodiscard]] constexpr bool is_control_block_fc(functional_constraint f) noexcept {
  switch (f) {
    case fc::RP: case fc::BR: case fc::LG: case fc::GO: case fc::GS: case fc::US: case fc::MS:
      return true;
    default:
      return false;
  }
}

}  // namespace openiec61850::model
