#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "openiec61850/ber/decode.hpp"
#include "openiec61850/ber/writer.hpp"
#include "openiec61850/core/bytes.hpp"
#include "openiec61850/core/result.hpp"
#include "openiec61850/mms/data.hpp"

// TypeDescription (ISO 9506-2 §14.1):
//
//   TypeSpecification ::= CHOICE {
//     typeName         [0] ObjectName,               -- not supported (errc::unsupported)
//     typeDescription  TypeDescription }
//
//   TypeDescription ::= CHOICE {
//     array            [1]  IMPLICIT SEQUENCE {
//                             packed           [0] IMPLICIT BOOLEAN DEFAULT FALSE,
//                             numberOfElements [1] IMPLICIT Unsigned32,
//                             elementType      [2] TypeSpecification },
//     structure        [2]  IMPLICIT SEQUENCE {
//                             packed           [0] IMPLICIT BOOLEAN DEFAULT FALSE,
//                             components       [1] IMPLICIT SEQUENCE OF SEQUENCE {
//                               componentName  [0] IMPLICIT Identifier OPTIONAL,
//                               componentType  [1] TypeSpecification } },
//     boolean          [3]  IMPLICIT NULL,
//     bit-string       [4]  IMPLICIT Integer32,
//     integer          [5]  IMPLICIT Unsigned8,      -- width in bits
//     unsigned         [6]  IMPLICIT Unsigned8,
//     floating-point   [7]  IMPLICIT SEQUENCE { format-width Unsigned8, exponent-width Unsigned8 },
//     octet-string     [9]  IMPLICIT Integer32,
//     visible-string   [10] IMPLICIT Integer32,
//     generalized-time [11] IMPLICIT NULL,
//     binary-time      [12] IMPLICIT BOOLEAN,        -- TRUE: includes the date
//     bcd              [13] IMPLICIT Unsigned8,
//     objId            [15] IMPLICIT NULL,
//     mMSString        [16] IMPLICIT Integer32,
//     utc-time         [17] IMPLICIT NULL }
//
// For the string types a negative size means "variable length, at most -size".

namespace openiec61850::mms {

struct type_component;

struct type_description {
  data_type type = data_type::boolean;  // data_type::boolean_array is not a valid type here
  bool packed = false;                  // array, structure
  std::int32_t size = 0;      // string types: Integer32; integer/unsigned/bcd: width (Unsigned8)
  std::uint8_t format_width = 0;    // floating-point
  std::uint8_t exponent_width = 0;  // floating-point
  bool with_date = false;           // binary-time
  std::uint32_t number_of_elements = 0;  // array
  // Structure components; for an array exactly one (unnamed) element type.
  std::vector<type_component> components;

  [[nodiscard]] static type_description boolean();
  [[nodiscard]] static type_description bit_string(std::int32_t size);
  [[nodiscard]] static type_description integer(std::uint8_t width);
  [[nodiscard]] static type_description unsigned_integer(std::uint8_t width);
  [[nodiscard]] static type_description float32();
  [[nodiscard]] static type_description float64();
  [[nodiscard]] static type_description octet_string(std::int32_t size);
  [[nodiscard]] static type_description visible_string(std::int32_t size);
  [[nodiscard]] static type_description generalized_time();
  [[nodiscard]] static type_description binary_time(bool with_date);
  [[nodiscard]] static type_description bcd(std::uint8_t width);
  [[nodiscard]] static type_description obj_id();
  [[nodiscard]] static type_description mms_string(std::int32_t size);
  [[nodiscard]] static type_description utc_time();
  [[nodiscard]] static type_description array(std::uint32_t number_of_elements,
                                              type_description element);
  [[nodiscard]] static type_description structure(std::vector<type_component> components);

  // Decodes a TypeSpecification element ([0] typeName is errc::unsupported).
  [[nodiscard]] static result<type_description> decode(const ber::tlv& element,
                                                       const decode_options& opts = {});
  [[nodiscard]] static result<type_description> decode(byte_view encoding,
                                                       const decode_options& opts = {});

  // Writes the TypeDescription CHOICE element. Fails with errc::invalid_state for an inconsistent
  // description (e.g. an array without an element type).
  [[nodiscard]] result<void> encode(ber::writer& w) const;

  friend bool operator==(const type_description& a, const type_description& b) noexcept;
};

struct type_component {
  std::string name;  // empty: componentName absent
  type_description type;

  friend bool operator==(const type_component& a, const type_component& b) noexcept;
};

}  // namespace openiec61850::mms
