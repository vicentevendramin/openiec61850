#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <limits>

#include "ber_test_util.hpp"
#include "openiec61850/ber/decode.hpp"

namespace ber = openiec61850::ber;
using ber_test::bytes;
using ber_test::copy;
using openiec61850::byte_buffer;
using openiec61850::errc;

TEST_CASE("identifier octets in low-tag-number form", "[ber]") {
  auto t = ber::decode_tag(bytes({0x02}));
  REQUIRE(t);
  CHECK(*t == ber::tags::integer);

  t = ber::decode_tag(bytes({0x30}));
  REQUIRE(t);
  CHECK(*t == ber::tags::sequence);

  t = ber::decode_tag(bytes({0xA1}));
  REQUIRE(t);
  CHECK(*t == ber::context(1, true));

  t = ber::decode_tag(bytes({0x7E}));
  REQUIRE(t);
  CHECK(*t == ber::application(30, true));

  t = ber::decode_tag(bytes({0xC5}));
  REQUIRE(t);
  CHECK(*t == ber::private_tag(5));
}

TEST_CASE("identifier octets in high-tag-number form", "[ber]") {
  auto t = ber::decode_tag(bytes({0x5F, 0x1F}));
  REQUIRE(t);
  CHECK(*t == ber::application(31));

  t = ber::decode_tag(bytes({0x9F, 0x81, 0x00}));
  REQUIRE(t);
  CHECK(*t == ber::context(128));

  t = ber::decode_tag(bytes({0xFF, 0xFF, 0x7F}));
  REQUIRE(t);
  CHECK(*t == ber::private_tag(0x3FFF, true));

  t = ber::decode_tag(bytes({0x9F, 0x8F, 0xFF, 0xFF, 0xFF, 0x7F}));
  REQUIRE(t);
  CHECK(t->number == std::numeric_limits<std::uint32_t>::max());
}

TEST_CASE("malformed identifier octets", "[ber]") {
  CHECK(ber::decode_tag(byte_buffer{}).error() == errc::truncated_input);
  CHECK(ber::decode_tag(bytes({0x9F})).error() == errc::truncated_input);
  CHECK(ber::decode_tag(bytes({0x9F, 0x81})).error() == errc::truncated_input);
  // §8.1.2.4.2 c: first subsequent octet must not be 0x80.
  CHECK(ber::decode_tag(bytes({0x9F, 0x80, 0x01})).error() == errc::malformed_encoding);
  // §8.1.2.2: numbers below 31 must use the single-octet form.
  CHECK(ber::decode_tag(bytes({0x9F, 0x1E})).error() == errc::malformed_encoding);
  // 2^32 does not fit the supported tag number range.
  CHECK(ber::decode_tag(bytes({0x9F, 0x90, 0x80, 0x80, 0x80, 0x00})).error() == errc::unsupported);
  byte_buffer endless{0x9F};
  endless.insert(endless.end(), 20, 0xFF);
  endless.push_back(0x7F);
  CHECK(ber::decode_tag(endless).error() == errc::unsupported);
}

TEST_CASE("short and long definite lengths", "[ber]") {
  const auto in1 = bytes({0x04, 0x03, 'a', 'b', 'c', 0xEE});
  auto e = ber::decode_tlv(in1);
  REQUIRE(e);
  CHECK(e->tag == ber::tags::octet_string);
  CHECK(copy(e->value) == bytes({'a', 'b', 'c'}));
  CHECK(e->encoding.size() == 5);
  CHECK(e->header_size() == 2);
  CHECK_FALSE(e->indefinite);

  byte_buffer long_form{0x04, 0x81, 0x80};
  long_form.insert(long_form.end(), 128, 0x55);
  e = ber::decode_tlv(long_form);
  REQUIRE(e);
  CHECK(e->value.size() == 128);
  CHECK(e->header_size() == 3);

  byte_buffer two_octets{0x04, 0x82, 0x01, 0x00};
  two_octets.insert(two_octets.end(), 256, 0x00);
  e = ber::decode_tlv(two_octets);
  REQUIRE(e);
  CHECK(e->value.size() == 256);
  CHECK(e->encoding.size() == 260);
}

TEST_CASE("non-minimal long-form lengths are accepted (BER)", "[ber]") {
  const auto in2 = bytes({0x04, 0x82, 0x00, 0x03, 'a', 'b', 'c'});
  auto e = ber::decode_tlv(in2);
  REQUIRE(e);
  CHECK(e->value.size() == 3);

  const auto in3 = bytes({0x05, 0x81, 0x00});
  e = ber::decode_tlv(in3);
  REQUIRE(e);
  CHECK(e->value.empty());

  // Nine length octets whose leading zeros keep the value small.
  const auto in4 = bytes({0x04, 0x89, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x7A});
  e = ber::decode_tlv(in4);
  REQUIRE(e);
  CHECK(copy(e->value) == bytes({0x7A}));
}

TEST_CASE("malformed length octets", "[ber]") {
  CHECK(ber::decode_tlv(byte_buffer{}).error() == errc::truncated_input);
  CHECK(ber::decode_tlv(bytes({0x04})).error() == errc::truncated_input);
  CHECK(ber::decode_tlv(bytes({0x04, 0x82, 0x01})).error() == errc::truncated_input);
  CHECK(ber::decode_tlv(bytes({0x04, 0x05, 0x01, 0x02})).error() == errc::length_overflow);
  CHECK(ber::decode_tlv(bytes({0x04, 0x84, 0xFF, 0xFF, 0xFF, 0xFF})).error() ==
        errc::length_overflow);
  // More significant length octets than size_t can hold.
  CHECK(ber::decode_tlv(bytes({0x04, 0x89, 0x01, 0, 0, 0, 0, 0, 0, 0, 0})).error() ==
        errc::length_overflow);
  // §8.1.3.5 c: 0xFF is reserved.
  CHECK(ber::decode_tlv(bytes({0x04, 0xFF})).error() == errc::malformed_encoding);
  // §8.1.3.2 a: indefinite length only in constructed form.
  CHECK(ber::decode_tlv(bytes({0x04, 0x80, 0x00, 0x00})).error() == errc::malformed_encoding);
}

TEST_CASE("indefinite length", "[ber]") {
  const auto in5 = bytes({0x30, 0x80, 0x02, 0x01, 0x05, 0x00, 0x00, 0xAA});
  auto e = ber::decode_tlv(in5);
  REQUIRE(e);
  CHECK(e->indefinite);
  CHECK(copy(e->value) == bytes({0x02, 0x01, 0x05}));
  CHECK(e->encoding.size() == 7);

  // Nested indefinite and definite elements, including an element whose contents hold 00 00.
  const auto nested = bytes({0x30, 0x80, 0xA0, 0x80, 0x04, 0x02, 0x00, 0x00, 0x00, 0x00,
                             0x01, 0x01, 0xFF, 0x00, 0x00});
  e = ber::decode_tlv(nested);
  REQUIRE(e);
  CHECK(e->encoding.size() == nested.size());
  CHECK(e->value.size() == nested.size() - 4);

  const auto in6 = bytes({0x30, 0x80, 0x00, 0x00});
  e = ber::decode_tlv(in6);
  REQUIRE(e);
  CHECK(e->value.empty());
}

TEST_CASE("malformed indefinite length", "[ber]") {
  CHECK(ber::decode_tlv(bytes({0x30, 0x80})).error() == errc::truncated_input);
  CHECK(ber::decode_tlv(bytes({0x30, 0x80, 0x02, 0x01, 0x05})).error() == errc::truncated_input);
  CHECK(ber::decode_tlv(bytes({0x30, 0x80, 0x30, 0x80, 0x00, 0x00})).error() ==
        errc::truncated_input);
  CHECK(ber::decode_tlv(bytes({0x30, 0x80, 0x02, 0x05, 0x01, 0x00, 0x00})).error() ==
        errc::length_overflow);
  // End-of-contents with a non-zero length, or in long form.
  CHECK(ber::decode_tlv(bytes({0x30, 0x80, 0x00, 0x01, 0x00})).error() ==
        errc::malformed_encoding);
  CHECK(ber::decode_tlv(bytes({0x30, 0x80, 0x00, 0x81, 0x00})).error() ==
        errc::malformed_encoding);
  // A primitive with indefinite length inside.
  CHECK(ber::decode_tlv(bytes({0x30, 0x80, 0x04, 0x80, 0x00, 0x00})).error() ==
        errc::malformed_encoding);
}

TEST_CASE("UNIVERSAL 0 never starts an element", "[ber]") {
  CHECK(ber::decode_tlv(bytes({0x00, 0x00})).error() == errc::malformed_encoding);
  CHECK(ber::decode_tlv(bytes({0x20, 0x00})).error() == errc::malformed_encoding);
}

TEST_CASE("indefinite nesting is bounded by max_depth", "[ber]") {
  byte_buffer deep;
  for (int i = 0; i < 10; ++i) deep.insert(deep.end(), {0x30, 0x80});
  for (int i = 0; i < 10; ++i) deep.insert(deep.end(), {0x00, 0x00});

  CHECK(ber::decode_tlv(deep, {.max_depth = 10}));
  CHECK(ber::decode_tlv(deep, {.max_depth = 9}).error() == errc::nesting_too_deep);
  CHECK(ber::decode_tlv(deep, {.max_depth = 10}, 1).error() == errc::nesting_too_deep);

  byte_buffer huge;
  for (int i = 0; i < 100000; ++i) huge.insert(huge.end(), {0x30, 0x80});
  CHECK(ber::decode_tlv(huge).error() == errc::nesting_too_deep);
}

TEST_CASE("BOOLEAN", "[ber]") {
  CHECK(*ber::decode_boolean(bytes({0x00})) == false);
  CHECK(*ber::decode_boolean(bytes({0xFF})) == true);
  CHECK(*ber::decode_boolean(bytes({0x01})) == true);  // §8.2.2: any non-zero is TRUE
  CHECK(ber::decode_boolean(byte_buffer{}).error() == errc::malformed_encoding);
  CHECK(ber::decode_boolean(bytes({0x00, 0x00})).error() == errc::malformed_encoding);
}

TEST_CASE("INTEGER known answers", "[ber]") {
  CHECK(*ber::decode_integer(bytes({0x00})) == 0);
  CHECK(*ber::decode_integer(bytes({0x7F})) == 127);
  CHECK(*ber::decode_integer(bytes({0x00, 0x80})) == 128);
  CHECK(*ber::decode_integer(bytes({0x80})) == -128);
  CHECK(*ber::decode_integer(bytes({0xFF, 0x7F})) == -129);
  CHECK(*ber::decode_integer(bytes({0x01, 0x00})) == 256);
  CHECK(*ber::decode_integer(bytes({0xFF})) == -1);
  CHECK(*ber::decode_integer(bytes({0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})) ==
        std::numeric_limits<std::int64_t>::max());
  CHECK(*ber::decode_integer(bytes({0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})) ==
        std::numeric_limits<std::int64_t>::min());
}

TEST_CASE("malformed INTEGER", "[ber]") {
  CHECK(ber::decode_integer(byte_buffer{}).error() == errc::malformed_encoding);
  // §8.3.2: the first nine bits must not be all zeros or all ones.
  CHECK(ber::decode_integer(bytes({0x00, 0x7F})).error() == errc::malformed_encoding);
  CHECK(ber::decode_integer(bytes({0xFF, 0x80})).error() == errc::malformed_encoding);
  CHECK(ber::decode_integer(bytes({0x00, 0x00})).error() == errc::malformed_encoding);
  // Too wide for int64_t.
  CHECK(ber::decode_integer(bytes({0x00, 0x80, 0, 0, 0, 0, 0, 0, 0})).error() ==
        ber::value_out_of_range);
  CHECK(ber::decode_integer(bytes({0x01, 0, 0, 0, 0, 0, 0, 0, 0})).error() ==
        ber::value_out_of_range);
}

TEST_CASE("INTEGER as unsigned", "[ber]") {
  CHECK(*ber::decode_unsigned(bytes({0x00})) == 0);
  CHECK(*ber::decode_unsigned(bytes({0x00, 0x80})) == 128);
  CHECK(*ber::decode_unsigned(bytes({0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})) ==
        std::numeric_limits<std::uint64_t>::max());
  CHECK(*ber::decode_unsigned(bytes({0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})) ==
        static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()));
  CHECK(ber::decode_unsigned(bytes({0x80})).error() == ber::value_out_of_range);
  CHECK(ber::decode_unsigned(bytes({0xFF})).error() == ber::value_out_of_range);
  CHECK(ber::decode_unsigned(bytes({0x01, 0, 0, 0, 0, 0, 0, 0, 0})).error() ==
        ber::value_out_of_range);
  CHECK(ber::decode_unsigned(bytes({0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0})).error() ==
        errc::malformed_encoding);
  CHECK(ber::decode_unsigned(bytes({0x00, 0x80, 0, 0, 0, 0, 0, 0, 0, 0})).error() ==
        ber::value_out_of_range);
  CHECK(ber::decode_unsigned(byte_buffer{}).error() == errc::malformed_encoding);
}

TEST_CASE("INTEGER range-checked into narrow types", "[ber]") {
  CHECK(*ber::decode_integer_as<std::int8_t>(bytes({0x80})) == -128);
  CHECK(ber::decode_integer_as<std::int8_t>(bytes({0xFF, 0x7F})).error() ==
        ber::value_out_of_range);
  CHECK(*ber::decode_integer_as<std::uint8_t>(bytes({0x00, 0xFF})) == 255);
  CHECK(ber::decode_integer_as<std::uint8_t>(bytes({0x01, 0x00})).error() ==
        ber::value_out_of_range);
  CHECK(ber::decode_integer_as<std::uint32_t>(bytes({0xFF})).error() == ber::value_out_of_range);
  CHECK(*ber::decode_integer_as<std::int32_t>(bytes({0x80, 0x00, 0x00, 0x00})) ==
        std::numeric_limits<std::int32_t>::min());
}

TEST_CASE("ENUMERATED and NULL", "[ber]") {
  CHECK(*ber::decode_enumerated(bytes({0x02})) == 2);
  CHECK(ber::decode_enumerated(bytes({0x00, 0x01})).error() == errc::malformed_encoding);
  CHECK(ber::decode_null(byte_buffer{}));
  CHECK(ber::decode_null(bytes({0x00})).error() == errc::malformed_encoding);
}

TEST_CASE("BIT STRING", "[ber]") {
  // X.690 §8.6.4.2 example: '0A3B5F291CD'H (44 bits).
  const auto in7 = bytes({0x04, 0x0A, 0x3B, 0x5F, 0x29, 0x1C, 0xD0});
  auto bs = ber::decode_bit_string(in7);
  REQUIRE(bs);
  CHECK(bs->bit_count == 44);
  CHECK(bs->unused_bits() == 4);
  CHECK(bs->bytes.size() == 6);
  CHECK_FALSE(bs->test(0));
  CHECK(bs->test(4));
  CHECK((*bs)[6]);
  CHECK((*bs)[43]);
  CHECK_FALSE((*bs)[42]);

  const auto in8 = bytes({0x00});
  bs = ber::decode_bit_string(in8);
  REQUIRE(bs);
  CHECK(bs->bit_count == 0);
  CHECK(bs->bytes.empty());

  // BER does not require padding bits to be zero (§8.6.2.3), DER does (§11.2.1).
  const auto in9 = bytes({0x06, 0xFF});
  bs = ber::decode_bit_string(in9);
  REQUIRE(bs);
  CHECK(bs->bit_count == 2);

  CHECK(ber::decode_bit_string(byte_buffer{}).error() == errc::malformed_encoding);
  CHECK(ber::decode_bit_string(bytes({0x08, 0x00})).error() == errc::malformed_encoding);
  CHECK(ber::decode_bit_string(bytes({0x01})).error() == errc::malformed_encoding);
}

TEST_CASE("OCTET STRING and character strings", "[ber]") {
  const auto raw = bytes({'a', 'b', 0x00, 0xC3, 0xA9});
  CHECK(copy(*ber::decode_octet_string(raw)) == raw);
  CHECK(*ber::decode_visible_string(bytes({'L', 'D', '0'})) == "LD0");
  CHECK(*ber::decode_utf8_string(bytes({0xC3, 0xA9})) == "\xC3\xA9");
  CHECK(*ber::decode_generalized_time(bytes({'2', '0', '2', '6', '1', '0', '2', '2', '1', '2',
                                             '0', '0', '0', '0', 'Z'})) == "20261022120000Z");
  CHECK(ber::decode_visible_string(byte_buffer{})->empty());
}

TEST_CASE("tlv overloads check the form", "[ber]") {
  const auto in10 = bytes({0x80, 0x01, 0x07});
  auto prim = ber::decode_tlv(in10);
  REQUIRE(prim);
  CHECK(*ber::decode_integer(*prim) == 7);
  CHECK(*ber::decode_unsigned(*prim) == 7);
  CHECK(*ber::decode_enumerated(*prim) == 7);
  CHECK(*ber::decode_boolean(*prim));
  CHECK(ber::decode_null(*prim).error() == errc::malformed_encoding);
  CHECK(ber::decode_oid(*prim));
  CHECK(ber::decode_octet_string(*prim)->size() == 1);
  CHECK(ber::decode_bit_string(*prim).error() == errc::malformed_encoding);  // 7 unused, no data
  CHECK(*ber::decode_visible_string(*prim) == "\x07");
  CHECK(*ber::decode_utf8_string(*prim) == "\x07");
  CHECK(*ber::decode_generalized_time(*prim) == "\x07");

  // Same contents in constructed form: segmented strings are unsupported, the rest malformed.
  const auto in11 = bytes({0xA0, 0x03, 0x04, 0x01, 0x07});
  auto cons = ber::decode_tlv(in11);
  REQUIRE(cons);
  CHECK(ber::decode_boolean(*cons).error() == errc::malformed_encoding);
  CHECK(ber::decode_integer(*cons).error() == errc::malformed_encoding);
  CHECK(ber::decode_unsigned(*cons).error() == errc::malformed_encoding);
  CHECK(ber::decode_enumerated(*cons).error() == errc::malformed_encoding);
  CHECK(ber::decode_null(*cons).error() == errc::malformed_encoding);
  CHECK(ber::decode_oid(*cons).error() == errc::malformed_encoding);
  CHECK(ber::decode_bit_string(*cons).error() == errc::unsupported);
  CHECK(ber::decode_octet_string(*cons).error() == errc::unsupported);
  CHECK(ber::decode_visible_string(*cons).error() == errc::unsupported);
  CHECK(ber::decode_utf8_string(*cons).error() == errc::unsupported);
  CHECK(ber::decode_generalized_time(*cons).error() == errc::unsupported);
}
