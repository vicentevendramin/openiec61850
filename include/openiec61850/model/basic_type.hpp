#pragma once

#include <cstdint>
#include <optional>
#include <string_view>

#include "openiec61850/core/result.hpp"
#include "openiec61850/mms/type_description.hpp"
#include "openiec61850/model/object_reference.hpp"

// Basic attribute types (IEC 61850-7-2 §6.1, SCL bType of IEC 61850-6) and their MMS
// TypeDescription (IEC 61850-8-1 §8.1.3, table "Mapping of ACSI basic types"):
//
//   BOOLEAN                    boolean
//   INT8 .. INT128             integer 8/16/24/32/64/128
//   INT8U .. INT32U            unsigned 8/16/24/32
//   FLOAT32 / FLOAT64          floating-point (32, 8) / (64, 11)
//   ENUMERATED                 integer 8
//   CODED ENUM, PACKED LIST    bit-string n
//   OCTET STRING n             octet-string -n       (negative: variable length up to n)
//   VISIBLE STRING n           visible-string -n
//   UNICODE STRING n           MMSString -n
//   TimeStamp                  utc-time
//   EntryTime                  binary-time (with date)
//   Quality                    bit-string 13
//   ObjectReference            visible-string -129 (Ed.2) / -65 (Ed.1)
//   EntryID                    octet-string 8
//   Dbpos, Tcmd, Check         bit-string 2
//   TrgOps                     bit-string 6
//   OptFlds                    bit-string 10

namespace openiec61850::model {

enum class basic_type : std::uint8_t {
  boolean,
  int8,
  int16,
  int24,
  int32,
  int64,
  int128,
  int8u,
  int16u,
  int24u,
  int32u,
  float32,
  float64,
  enumerated,
  coded_enum,
  packed_list,
  octet_string,
  visible_string,
  unicode_string,
  timestamp,
  entry_time,
  quality,
  object_reference,
  entry_id,
  dbpos,
  tcmd,
  check,
  trigger_conditions,
  optional_fields,
};

// SCL bType name: "BOOLEAN", "INT32U", "FLOAT32", "Enum", "Dbpos", "VisString", "Octet",
// "Unicode", "Timestamp", "EntryTime", "Quality", "ObjRef", "EntryID", "Tcmd", "Check",
// "TrgOps", "OptFlds"; "CodedEnum" / "PackedList" for the generic bit-string types.
[[nodiscard]] std::string_view to_string(basic_type t) noexcept;

// `size` is the maximum length of a string type and the bit count of CODED ENUM / PACKED LIST;
// it is ignored for the other types. errc::invalid_state when a required size is not positive.
[[nodiscard]] result<mms::type_description> to_mms_type(basic_type t, std::int32_t size = 0,
                                                        edition e = edition::ed2);

// The basic type of a TypeDescription when the mapping identifies it unambiguously, using the
// most generic type when several share an encoding:
//   - octet-string, visible-string and MMSString map to octet_string, visible_string and
//     unicode_string (EntryID and ObjectReference are not inferred);
//   - bit-string 13 maps to quality; other bit-string widths (CODED ENUM, PACKED LIST, Dbpos,
//     Tcmd, Check, TrgOps, OptFlds) are ambiguous;
//   - integer 8 is ambiguous (INT8 or ENUMERATED);
//   - binary-time without a date, generalized-time, bcd, objId, arrays and structures have no
//     basic type.
[[nodiscard]] std::optional<basic_type> deduce_basic_type(const mms::type_description& t) noexcept;

}  // namespace openiec61850::model
