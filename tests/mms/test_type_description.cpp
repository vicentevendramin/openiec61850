#include <catch2/catch_test_macros.hpp>

#include <vector>

#include "mms_test_util.hpp"
#include "openiec61850/mms/type_description.hpp"

namespace mms = openiec61850::mms;
namespace ber = openiec61850::ber;
using mms_test::hex;
using openiec61850::byte_buffer;
using openiec61850::errc;
using td = mms::type_description;

namespace {

byte_buffer encode(const td& t) {
  byte_buffer out;
  ber::writer w{out};
  REQUIRE(t.encode(w));
  return out;
}

}  // namespace

TEST_CASE("TypeDescription known answers", "[mms]") {
  CHECK(encode(td::boolean()) == hex("83 00"));
  CHECK(encode(td::bit_string(13)) == hex("84 01 0D"));
  CHECK(encode(td::integer(32)) == hex("85 01 20"));
  CHECK(encode(td::unsigned_integer(8)) == hex("86 01 08"));
  CHECK(encode(td::float32()) == hex("A7 06 02 01 20 02 01 08"));
  CHECK(encode(td::float64()) == hex("A7 06 02 01 40 02 01 0B"));
  CHECK(encode(td::octet_string(-64)) == hex("89 01 C0"));
  CHECK(encode(td::visible_string(-255)) == hex("8A 02 FF 01"));
  CHECK(encode(td::generalized_time()) == hex("8B 00"));
  CHECK(encode(td::binary_time(true)) == hex("8C 01 FF"));
  CHECK(encode(td::bcd(4)) == hex("8D 01 04"));
  CHECK(encode(td::obj_id()) == hex("8F 00"));
  CHECK(encode(td::mms_string(-255)) == hex("90 02 FF 01"));
  CHECK(encode(td::utc_time()) == hex("91 00"));
  CHECK(encode(td::array(3, td::integer(8))) == hex("A1 08 81 01 03 A2 03 85 01 08"));
}

TEST_CASE("TypeDescription round trips", "[mms]") {
  auto packed = td::array(2, td::boolean());
  packed.packed = true;
  const std::vector<td> types{
      td::boolean(), td::bit_string(-32), td::integer(64), td::unsigned_integer(32), td::float32(),
      td::float64(), td::octet_string(8), td::visible_string(-129), td::generalized_time(),
      td::binary_time(false), td::bcd(8), td::obj_id(), td::mms_string(-10), td::utc_time(),
      packed,
      td::structure({}),
      td::structure({{"mag", td::structure({{"f", td::float32()}})},
                     {"q", td::bit_string(13)},
                     {"", td::array(4, td::structure({{"x", td::integer(8)}}))}}),
  };
  for (const auto& t : types) {
    const auto bytes = encode(t);
    auto back = td::decode(bytes);
    REQUIRE(back);
    CHECK(*back == t);
    CHECK(encode(*back) == bytes);
  }
}

TEST_CASE("TypeDescription nesting limit and malformed input", "[mms]") {
  td t = td::boolean();
  for (int i = 0; i < 5; ++i) t = td::structure({{"a", t}});
  const auto bytes = encode(t);
  CHECK(td::decode(bytes, {.max_nesting = 5}));
  CHECK(td::decode(bytes, {.max_nesting = 4}).error() == errc::nesting_too_deep);

  CHECK(td::decode(hex("A0 03 80 01 'x'")).error() == errc::unsupported);           // typeName
  CHECK(td::decode(hex("A1 08 81 01 03 A2 03 A0 01 00")).error() != std::error_code{});
  CHECK(td::decode(hex("A1 0A 81 01 03 A2 05 A0 03 80 01 'x'")).error() == errc::unsupported);
  CHECK(td::decode(hex("8E 00")).error() == errc::malformed_encoding);  // booleanArray
  CHECK(td::decode(hex("88 00")).error() == errc::unsupported);
  CHECK(td::decode(hex("A3 00")).error() == errc::malformed_encoding);
  CHECK(td::decode(hex("85 02 01 00")).error() == errc::value_out_of_range);  // Unsigned8
  CHECK(td::decode(hex("A1 03 81 01 03")).error() != std::error_code{});      // no element type
  CHECK(td::decode(hex("83 00 00")).error() == errc::malformed_encoding);
  CHECK(td::decode(hex("A2 05 A1 03 30 01 00")).error() != std::error_code{});

  byte_buffer out;
  ber::writer w{out};
  td bad;
  bad.type = mms::data_type::boolean_array;
  CHECK(bad.encode(w).error() == errc::invalid_state);
  CHECK(td::integer(8).encode(w));
  td wide = td::integer(8);
  wide.size = 300;
  CHECK(wide.encode(w).error() == errc::invalid_state);
}
