#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "openiec61850/core/bytes.hpp"
#include "openiec61850/core/result.hpp"
#include "openiec61850/mms/data.hpp"
#include "openiec61850/model/basic_type.hpp"
#include "openiec61850/model/entry_id.hpp"
#include "openiec61850/model/enums.hpp"
#include "openiec61850/model/quality.hpp"
#include "openiec61850/model/timestamp.hpp"

// Typed access to values read from a server. Each fails with errc::type_mismatch when the MMS
// type is not the expected one and with openiec61850::errc::value_out_of_range when the value
// does not fit.

namespace openiec61850::client {

[[nodiscard]] result<bool> to_bool(const mms::data& d);
[[nodiscard]] result<std::int64_t> to_int64(const mms::data& d);  // integer or unsigned
[[nodiscard]] result<std::uint64_t> to_uint64(const mms::data& d);
// FLOAT32 values; FLOAT64 values are narrowed (value_out_of_range when not finite in float).
[[nodiscard]] result<float> to_float(const mms::data& d);
[[nodiscard]] result<double> to_double(const mms::data& d);
// visible-string or MMSString (UTF-8).
[[nodiscard]] result<std::string> to_string(const mms::data& d);
[[nodiscard]] result<byte_buffer> to_bytes(const mms::data& d);  // octet-string
[[nodiscard]] result<model::quality> to_quality(const mms::data& d);
[[nodiscard]] result<model::timestamp> to_timestamp(const mms::data& d);
[[nodiscard]] result<model::entry_time> to_entry_time(const mms::data& d);
[[nodiscard]] result<model::entry_id> to_entry_id(const mms::data& d);
[[nodiscard]] result<model::dbpos> to_dbpos(const mms::data& d);

// Component `i` of a structure (or element of an array): errc::type_mismatch for a scalar,
// value_out_of_range when there is no such element.
[[nodiscard]] result<mms::data> component(const mms::data& d, std::size_t i);

}  // namespace openiec61850::client
