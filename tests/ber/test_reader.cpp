#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <system_error>
#include <utility>

#include "ber_test_util.hpp"
#include "openiec61850/ber/reader.hpp"

namespace ber = openiec61850::ber;
using ber_test::bytes;
using ber_test::copy;
using openiec61850::byte_buffer;
using openiec61850::errc;

TEST_CASE("reader walks a sequence of elements", "[ber]") {
  const auto data = bytes({0x02, 0x01, 0x05, 0x04, 0x02, 'h', 'i', 0x05, 0x00});
  ber::reader rd{data};
  CHECK(rd.remaining() == data.size());
  CHECK(rd.next_is(ber::tags::integer));
  CHECK_FALSE(rd.next_is(ber::tags::octet_string));

  auto t = rd.peek_tag();
  REQUIRE(t);
  CHECK(*t == ber::tags::integer);
  auto peeked = rd.peek();
  REQUIRE(peeked);
  CHECK(rd.remaining() == data.size());

  auto e = rd.next();
  REQUIRE(e);
  CHECK(*ber::decode_integer(*e) == 5);
  CHECK(e->encoding.data() == data.data());

  CHECK(rd.expect(ber::tags::integer).error() == errc::malformed_encoding);
  CHECK(rd.remaining() == 6);
  e = rd.expect(ber::tags::octet_string);
  REQUIRE(e);
  CHECK(copy(e->value) == bytes({'h', 'i'}));

  CHECK(rd.expect_end().error() == errc::malformed_encoding);
  REQUIRE(rd.skip());
  CHECK(rd.empty());
  CHECK(rd.expect_end());
  CHECK(rd.next().error() == errc::truncated_input);
  CHECK(rd.peek().error() == errc::truncated_input);
  CHECK(rd.skip().error() == errc::truncated_input);
  CHECK_FALSE(rd.next_is(ber::tags::null));
}

TEST_CASE("reader descends into constructed elements", "[ber]") {
  // SEQUENCE { [0] IMPLICIT INTEGER 7, [1] SEQUENCE { BOOLEAN TRUE } }, INTEGER 9
  const auto data = bytes({0x30, 0x08, 0x80, 0x01, 0x07, 0xA1, 0x03, 0x01, 0x01, 0xFF,
                           0x02, 0x01, 0x09});
  ber::reader rd{data};
  auto seq = rd.enter(ber::tags::sequence);
  REQUIRE(seq);
  CHECK(seq->depth() == 1);
  CHECK(*seq->read_unsigned(ber::context(0)) == 7);
  auto inner = seq->enter(ber::context(1));  // form is implied by enter()
  REQUIRE(inner);
  CHECK(inner->depth() == 2);
  CHECK(*inner->read_boolean());
  CHECK(inner->empty());
  CHECK(seq->expect_end());
  CHECK(*rd.read_integer() == 9);
  CHECK(rd.empty());
}

TEST_CASE("reader enter errors leave the reader unchanged", "[ber]") {
  const auto data = bytes({0x02, 0x01, 0x05, 0x30, 0x05, 0x02, 0x01});
  ber::reader rd{data};
  CHECK(rd.enter(ber::tags::sequence).error() == errc::malformed_encoding);
  auto e = rd.peek();
  REQUIRE(e);
  CHECK(rd.enter(*e).error() == errc::malformed_encoding);  // primitive
  REQUIRE(rd.skip());
  CHECK(rd.enter(ber::tags::sequence).error() == errc::length_overflow);
  CHECK(rd.remaining() == 4);

  const byte_buffer nothing;
  ber::reader empty{nothing};
  CHECK(empty.enter(ber::tags::sequence).error() == errc::truncated_input);
}

TEST_CASE("reader read_* helpers", "[ber]") {
  const auto data = bytes({
      0x01, 0x01, 0x00,                          // BOOLEAN FALSE
      0x02, 0x02, 0xFF, 0x7F,                    // INTEGER -129
      0x02, 0x02, 0x00, 0x80,                    // INTEGER 128
      0x0A, 0x01, 0x03,                          // ENUMERATED 3
      0x05, 0x00,                                // NULL
      0x03, 0x02, 0x07, 0x80,                    // BIT STRING '1'B
      0x04, 0x01, 0xAB,                          // OCTET STRING
      0x06, 0x03, 0x2A, 0x86, 0x48,              // OID 1.2.840
      0x1A, 0x02, 'L', 'D',                      // VisibleString
      0x0C, 0x02, 0xC3, 0xA9,                    // UTF8String
      0x18, 0x03, '2', '0', 'Z',                 // GeneralizedTime
      0x89, 0x01, 0x2A,                          // [9] IMPLICIT INTEGER
  });
  ber::reader rd{data};
  CHECK(*rd.read_boolean() == false);
  CHECK(*rd.read_integer() == -129);
  CHECK(*rd.read_unsigned() == 128);
  CHECK(*rd.read_enumerated() == 3);
  CHECK(rd.read_null());
  auto bits = rd.read_bit_string();
  REQUIRE(bits);
  CHECK(bits->bit_count == 1);
  CHECK(bits->test(0));
  CHECK(copy(*rd.read_octet_string()) == bytes({0xAB}));
  CHECK(*rd.read_oid() == ber::oid{1, 2, 840});
  CHECK(*rd.read_visible_string() == "LD");
  CHECK(*rd.read_utf8_string() == "\xC3\xA9");
  CHECK(*rd.read_generalized_time() == "20Z");
  CHECK(rd.read_integer().error() == errc::malformed_encoding);  // tag mismatch
  CHECK(*rd.read_integer(ber::context(9)) == 42);
  CHECK(rd.empty());
}

TEST_CASE("reader read_* failures do not advance", "[ber]") {
  // Non-minimal INTEGER, then a segmented OCTET STRING, then a constructed BOOLEAN.
  const auto data = bytes({0x02, 0x02, 0x00, 0x01, 0x24, 0x03, 0x04, 0x01, 0xAA,
                           0x21, 0x03, 0x01, 0x01, 0xFF});
  ber::reader rd{data};
  CHECK(rd.read_integer().error() == errc::malformed_encoding);
  CHECK(rd.remaining() == data.size());
  REQUIRE(rd.skip());
  CHECK(rd.read_octet_string().error() == errc::unsupported);
  CHECK(rd.remaining() == data.size() - 4);
  REQUIRE(rd.skip());
  CHECK(rd.read_boolean().error() == errc::malformed_encoding);
  REQUIRE(rd.skip());
  CHECK(rd.empty());
}

TEST_CASE("reader handles indefinite-length elements", "[ber]") {
  // SEQUENCE (indefinite) { INTEGER 1, [0] (indefinite) { NULL } } followed by INTEGER 2
  const auto data = bytes({0x30, 0x80, 0x02, 0x01, 0x01, 0xA0, 0x80, 0x05, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x02, 0x01, 0x02});
  ber::reader rd{data};
  auto seq = rd.enter(ber::tags::sequence);
  REQUIRE(seq);
  CHECK(*seq->read_integer() == 1);
  auto inner = seq->enter(ber::context(0));
  REQUIRE(inner);
  CHECK(inner->read_null());
  CHECK(inner->empty());
  CHECK(seq->empty());
  CHECK(*rd.read_integer() == 2);
  CHECK(rd.empty());
}

TEST_CASE("reader rejects end-of-contents outside indefinite contents", "[ber]") {
  const auto data = bytes({0x00, 0x00});
  ber::reader rd{data};
  CHECK(rd.next().error() == errc::malformed_encoding);
}

namespace {

byte_buffer nested_sequences(int levels) {
  byte_buffer data{0x05, 0x00};
  for (int i = 0; i < levels; ++i) {
    byte_buffer outer{0x30};
    if (data.size() < 0x80) {
      outer.push_back(static_cast<std::uint8_t>(data.size()));
    } else {
      outer.push_back(0x82);
      outer.push_back(static_cast<std::uint8_t>(data.size() >> 8));
      outer.push_back(static_cast<std::uint8_t>(data.size()));
    }
    outer.insert(outer.end(), data.begin(), data.end());
    data = std::move(outer);
  }
  return data;
}

// Descends until a primitive element is reached; returns the error, if any.
std::error_code descend(ber::reader rd) {
  for (;;) {
    auto e = rd.next();
    if (!e) return e.error();
    if (!e->constructed()) return {};
    auto child = rd.enter(*e);
    if (!child) return child.error();
    rd = *child;
  }
}

}  // namespace

TEST_CASE("reader nesting is bounded by max_depth", "[ber]") {
  const auto data = nested_sequences(70);
  CHECK(descend(ber::reader{data}) == errc::nesting_too_deep);
  CHECK_FALSE(descend(ber::reader{data, {.max_depth = 70}}));
  CHECK(descend(ber::reader{data, {.max_depth = 69}}) == errc::nesting_too_deep);

  const auto shallow = nested_sequences(2);
  CHECK_FALSE(descend(ber::reader{shallow, {.max_depth = 2}}));
  CHECK(descend(ber::reader{shallow, {.max_depth = 1}}) == errc::nesting_too_deep);
}

TEST_CASE("reader with zero-length constructed elements", "[ber]") {
  const auto data = bytes({0x30, 0x00, 0xA2, 0x00});
  ber::reader rd{data};
  auto a = rd.enter(ber::tags::sequence);
  REQUIRE(a);
  CHECK(a->empty());
  auto b = rd.enter(ber::context(2));
  REQUIRE(b);
  CHECK(b->empty());
  CHECK(rd.empty());
}
