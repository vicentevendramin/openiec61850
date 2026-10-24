#pragma once

#include <cstddef>
#include <optional>
#include <span>
#include <variant>
#include <vector>

#include "openiec61850/core/bytes.hpp"
#include "openiec61850/mms/data.hpp"
#include "openiec61850/mms/pdu.hpp"
#include "openiec61850/mms/type_description.hpp"

namespace openiec61850::server::detail {

// Checks `v` against the type and returns it normalised to the type: bit strings resized to the
// declared bit count, integers and unsigned interchangeable within range, floats converted to the
// declared width, a visible-string accepted for an MMSString. A wrong MMS type is
// type_inconsistent, a value out of range or too long is object_value_invalid.
using conformed = std::variant<mms::data, mms::data_access_error>;
[[nodiscard]] conformed conform(const mms::data& v, const mms::type_description& t);

// The bit string `bits` resized to `count` bits (missing bits zero).
[[nodiscard]] mms::data resize_bits(const ber::bit_string_view& bits, std::size_t count);

// A BIT STRING of `count` bits with bits[i] set (bit 0 first).
[[nodiscard]] mms::data make_bits(const std::vector<bool>& bits);

// Encoded size of a Data value.
[[nodiscard]] std::size_t encoded_size(const mms::data& v);

}  // namespace openiec61850::server::detail
