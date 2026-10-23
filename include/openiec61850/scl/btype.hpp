#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <variant>

#include "openiec61850/core/result.hpp"
#include "openiec61850/model/basic_type.hpp"
#include "openiec61850/scl/document.hpp"

// SCL bType values (IEC 61850-6 tBasicTypeEnum, Ed.1 to Ed.2.1) and their basic types:
//
//   BOOLEAN, INT8..INT128, INT8U..INT32U, FLOAT32, FLOAT64   the numeric basic types
//   Enum                                                     enumerated (type = EnumType id)
//   Dbpos, Tcmd, Check, Quality, Timestamp, EntryTime,       the matching special types
//   ObjRef, EntryID, TrgOps, OptFlds
//   VisString<n>, Octet<n>, Unicode<n>                       string types of maximum length n
//   Currency                                                 VISIBLE STRING 3 (Ed.2.1)
//   Struct                                                   structured (type = DAType id)
//   PhyComAddr, SvOptFlds, LogOptFlds, INT64U                recognised, no basic_type mapping

namespace openiec61850::scl {

struct btype_info {
  std::optional<model::basic_type> type;  // nullopt for Struct and the unmapped types
  std::uint32_t size = 0;                 // maximum length of the string types
  bool is_struct = false;
};

// nullopt when `btype` is not an SCL bType.
[[nodiscard]] std::optional<btype_info> parse_btype(std::string_view btype) noexcept;

// A Val text converted to its natural type:
//   BOOLEAN -> bool ("true"/"false"/"1"/"0"); INTn -> int64; INTnU -> uint64 (range-checked);
//   FLOATn -> double; Enum -> int64 (the ord of the EnumVal whose text matches, or a decimal ord
//   defined in the EnumType); every other type -> the text itself.
using scalar = std::variant<std::monostate, bool, std::int64_t, std::uint64_t, double, std::string>;

// errc::value_out_of_range for numbers outside the type; errc::malformed_encoding for text that
// is not a value of the type (or not a literal of `enumeration`). `enumeration` may be null for
// non-Enum types; for Enum without an EnumType only decimal ords are accepted.
[[nodiscard]] result<scalar> parse_value(model::basic_type type, std::string_view text,
                                         const enum_type* enumeration = nullptr);

}  // namespace openiec61850::scl
