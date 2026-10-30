#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

#include "openiec61850/core/bytes.hpp"
#include "openiec61850/core/result.hpp"
#include "openiec61850/mms/pdu.hpp"
#include "openiec61850/model/object_reference.hpp"

// Mapping of ACSI object references onto MMS names (IEC 61850-8-1 §8.1.3, §9, §14, §17):
//
//   LD                          -> domain name
//   LN.DO.SDO.DA.BDA [FC]       -> item "LN$FC$DO$SDO$DA$BDA" (domain-specific named variable)
//   LN [FC]                     -> item "LN$FC";  LN -> item "LN"
//   LLN0.brcb01 [BR]            -> item "LLN0$BR$brcb01" (control blocks: BR, RP, LG, GO, MS, US,
//                                  and SP for the SGCB, are ordinary FC-constrained names)
//   data set LD/LN.DS           -> domain-specific NamedVariableList, item "LN$DS"
//   data set @DS                -> aa-specific NamedVariableList "DS"
//
// Array elements: the item id ends at the first indexed name; the index and every name after it
// are expressed as an MMS AlternateAccess (ISO 9506-2 §14.4.1), nested one level per selector:
//
//   LN.DO.arr(2).f.g [MX] -> item "LN$MX$DO$arr",
//     selectAlternateAccess { index 2, selectAlternateAccess { component f, selectAccess
//     component g } }
//
// The textual MMS forms carried inside IEC 61850 data (report DataReference and DatSet, GoCB
// datSet, gocbRef...) are "LD/" followed by the item id, or "@DS".
//
// Errors: errc::invalid_state when the reference cannot be mapped (no FC on a data path, the XX
// wildcard, a data set where data is expected...); errc::length_overflow when a domain or item
// exceeds name_limits::max_mms_identifier; errc::malformed_encoding for MMS names that do not
// follow the mapping; errc::unsupported for AlternateAccess forms other than the above.

namespace openiec61850::model {

// Owning counterpart of mms::object_name.
struct mms_name {
  mms::object_scope scope = mms::object_scope::vmd_specific;
  std::string domain_id;
  std::string item_id;

  [[nodiscard]] mms::object_name view() const noexcept { return {scope, domain_id, item_id}; }
  [[nodiscard]] static mms_name from(const mms::object_name& n) {
    return {n.scope, std::string{n.domain_id}, std::string{n.item_id}};
  }

  friend bool operator==(const mms_name&, const mms_name&) = default;
};

struct mms_variable {
  mms_name name;
  // Contents octets of [5] IMPLICIT AlternateAccess; empty when absent.
  byte_buffer alternate_access;

  // Views into this object, which must outlive the result.
  [[nodiscard]] mms::variable_spec spec() const noexcept {
    return {name.view(), alternate_access};
  }

  friend bool operator==(const mms_variable&, const mms_variable&) = default;
};

inline constexpr name_limits default_limits = name_limits::for_edition(edition::ed2);

// Item id for a reference without array indices (errc::invalid_state when it has one).
[[nodiscard]] result<std::string> to_mms_item_id(const object_reference& ref,
                                                 const name_limits& limits = default_limits);
[[nodiscard]] result<mms_variable> to_mms_variable(const object_reference& ref,
                                                   const name_limits& limits = default_limits);
// Reverse mapping of a domain-specific variable name (and AlternateAccess contents).
[[nodiscard]] result<object_reference> from_mms_variable(const mms::object_name& name,
                                                         byte_view alternate_access = {},
                                                         const parse_options& opts = {});

// AlternateAccess contents for selectors relative to a variable; used by to_mms_variable.
struct access_selector {
  std::string_view component;           // empty for an index selector
  std::optional<std::uint32_t> index;   // set for an index selector
};
[[nodiscard]] result<void> encode_alternate_access(std::span<const access_selector> selectors,
                                                   byte_buffer& out);

[[nodiscard]] result<mms_name> to_mms_named_variable_list(
    const object_reference& data_set, const name_limits& limits = default_limits);
[[nodiscard]] result<object_reference> from_mms_named_variable_list(
    const mms::object_name& name, const parse_options& opts = {});

// "LD/LN$FC$DO$DA" (also control block references such as "LD/LLN0$GO$gcb01").
[[nodiscard]] result<std::string> to_mms_reference(const object_reference& ref,
                                                   const name_limits& limits = default_limits);
[[nodiscard]] result<object_reference> from_mms_reference(std::string_view text,
                                                          const parse_options& opts = {});
// The same text with array indices, as a DataRef of a report or a log entry names an element of an
// array of data objects: "LD/LN$FC$DO(1)$DA".
[[nodiscard]] result<std::string> to_mms_data_reference(const object_reference& ref,
                                                        const name_limits& limits = default_limits);
[[nodiscard]] result<object_reference> from_mms_data_reference(std::string_view text,
                                                               const parse_options& opts = {});
// "LD/LN$DS" or "@DS".
[[nodiscard]] result<std::string> to_mms_data_set_reference(
    const object_reference& data_set, const name_limits& limits = default_limits);
[[nodiscard]] result<object_reference> from_mms_data_set_reference(
    std::string_view text, const parse_options& opts = {});

}  // namespace openiec61850::model
