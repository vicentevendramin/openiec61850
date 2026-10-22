#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <limits>
#include <string>
#include <vector>

#include "ber_test_util.hpp"
#include "openiec61850/ber/reader.hpp"
#include "openiec61850/ber/writer.hpp"

namespace ber = openiec61850::ber;
using ber_test::bytes;
using ber_test::copy;
using openiec61850::byte_buffer;
using openiec61850::errc;

namespace {

byte_buffer encode_integer(std::int64_t v) {
  byte_buffer out;
  ber::writer{out}.write_integer(v);
  return out;
}

byte_buffer encode_unsigned(std::uint64_t v) {
  byte_buffer out;
  ber::writer{out}.write_unsigned(v);
  return out;
}

}  // namespace

TEST_CASE("INTEGER encoding known answers", "[ber]") {
  CHECK(encode_integer(0) == bytes({0x02, 0x01, 0x00}));
  CHECK(encode_integer(127) == bytes({0x02, 0x01, 0x7F}));
  CHECK(encode_integer(128) == bytes({0x02, 0x02, 0x00, 0x80}));
  CHECK(encode_integer(-128) == bytes({0x02, 0x01, 0x80}));
  CHECK(encode_integer(-129) == bytes({0x02, 0x02, 0xFF, 0x7F}));
  CHECK(encode_integer(256) == bytes({0x02, 0x02, 0x01, 0x00}));
  CHECK(encode_integer(-1) == bytes({0x02, 0x01, 0xFF}));
  CHECK(encode_integer(std::numeric_limits<std::int64_t>::max()) ==
        bytes({0x02, 0x08, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}));
  CHECK(encode_integer(std::numeric_limits<std::int64_t>::min()) ==
        bytes({0x02, 0x08, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}));

  CHECK(encode_unsigned(0) == bytes({0x02, 0x01, 0x00}));
  CHECK(encode_unsigned(127) == bytes({0x02, 0x01, 0x7F}));
  CHECK(encode_unsigned(128) == bytes({0x02, 0x02, 0x00, 0x80}));
  CHECK(encode_unsigned(256) == bytes({0x02, 0x02, 0x01, 0x00}));
  CHECK(encode_unsigned(std::numeric_limits<std::uint64_t>::max()) ==
        bytes({0x02, 0x09, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}));
}

TEST_CASE("INTEGER round-trips at every width boundary", "[ber]") {
  std::vector<std::int64_t> values{std::numeric_limits<std::int64_t>::min(),
                                   std::numeric_limits<std::int64_t>::max()};
  for (int bits = 0; bits < 63; ++bits) {
    const std::int64_t p = std::int64_t{1} << bits;
    values.insert(values.end(), {p, p - 1, p + 1, -p, -p - 1, -p + 1});
  }
  for (const auto v : values) {
    CAPTURE(v);
    const auto enc = encode_integer(v);
    ber::reader rd{enc};
    CHECK(*rd.read_integer() == v);
    CHECK(rd.empty());
    if (v >= 0) {
      CHECK(encode_unsigned(static_cast<std::uint64_t>(v)) == enc);
    }
  }
  for (int bits = 0; bits < 64; ++bits) {
    const std::uint64_t p = std::uint64_t{1} << bits;
    for (const auto u : {p, p - 1, p + 1}) {
      CAPTURE(u);
      const auto enc = encode_unsigned(u);
      ber::reader rd{enc};
      CHECK(*rd.read_unsigned() == u);
    }
  }
}

TEST_CASE("primitive encoders", "[ber]") {
  byte_buffer out;
  ber::writer w{out};
  w.write_boolean(true);
  w.write_boolean(false);
  w.write_enumerated(3);
  w.write_null();
  w.write_octet_string(bytes({0xDE, 0xAD}));
  w.write_visible_string("LD0");
  w.write_utf8_string("\xC3\xA9");
  w.write_generalized_time("20261022Z");
  CHECK(out == bytes({0x01, 0x01, 0xFF, 0x01, 0x01, 0x00, 0x0A, 0x01, 0x03, 0x05, 0x00, 0x04,
                      0x02, 0xDE, 0xAD, 0x1A, 0x03, 'L', 'D', '0', 0x0C, 0x02, 0xC3, 0xA9,
                      0x18, 0x09, '2', '0', '2', '6', '1', '0', '2', '2', 'Z'}));
}

TEST_CASE("BIT STRING encoding", "[ber]") {
  byte_buffer out;
  ber::writer w{out};
  // X.690 §8.6.4.2 example with garbage in the padding bits, which are cleared.
  REQUIRE(w.write_bit_string(bytes({0x0A, 0x3B, 0x5F, 0x29, 0x1C, 0xDF}), 44));
  CHECK(out == bytes({0x03, 0x07, 0x04, 0x0A, 0x3B, 0x5F, 0x29, 0x1C, 0xD0}));

  out.clear();
  REQUIRE(w.write_bit_string({}, 0));
  CHECK(out == bytes({0x03, 0x01, 0x00}));

  out.clear();
  REQUIRE(w.write_bit_string(bytes({0xFF}), 8));
  CHECK(out == bytes({0x03, 0x02, 0x00, 0xFF}));

  out.clear();
  CHECK(w.write_bit_string(bytes({0xFF}), 9).error() == errc::malformed_encoding);
  CHECK(w.write_bit_string(bytes({0xFF, 0x00}), 8).error() == errc::malformed_encoding);
  CHECK(out.empty());

  // Round trip through the decoder.
  REQUIRE(w.write_bit_string(bytes({0xA0}), 3));
  ber::reader rd{out};
  auto bs = rd.read_bit_string();
  REQUIRE(bs);
  CHECK(bs->bit_count == 3);
  CHECK(bs->test(0));
  CHECK_FALSE(bs->test(1));
  CHECK(bs->test(2));
}

TEST_CASE("tag encoding", "[ber]") {
  const auto encode = [](ber::tag t) {
    byte_buffer out;
    ber::encode_tag(out, t);
    return out;
  };
  CHECK(encode(ber::tags::integer) == bytes({0x02}));
  CHECK(encode(ber::tags::sequence) == bytes({0x30}));
  CHECK(encode(ber::context(0, true)) == bytes({0xA0}));
  CHECK(encode(ber::application(30)) == bytes({0x5E}));
  CHECK(encode(ber::application(31)) == bytes({0x5F, 0x1F}));
  CHECK(encode(ber::context(127)) == bytes({0x9F, 0x7F}));
  CHECK(encode(ber::context(128)) == bytes({0x9F, 0x81, 0x00}));
  CHECK(encode(ber::private_tag(0x3FFF, true)) == bytes({0xFF, 0xFF, 0x7F}));
  CHECK(encode(ber::context(std::numeric_limits<std::uint32_t>::max())) ==
        bytes({0x9F, 0x8F, 0xFF, 0xFF, 0xFF, 0x7F}));

  for (const std::uint32_t n : {0U, 1U, 30U, 31U, 127U, 128U, 16383U, 16384U, 0xFFFFFFFFU}) {
    for (const auto cls : {ber::tag_class::universal, ber::tag_class::application,
                           ber::tag_class::context, ber::tag_class::private_}) {
      const ber::tag t{cls, true, n};
      const auto enc = encode(t);
      CHECK(*ber::decode_tag(enc) == t);
    }
  }
}

TEST_CASE("length encoding", "[ber]") {
  const auto encode = [](std::size_t n) {
    byte_buffer out;
    ber::encode_length(out, n);
    CHECK(out.size() == ber::encoded_length_size(n));
    return out;
  };
  CHECK(encode(0) == bytes({0x00}));
  CHECK(encode(127) == bytes({0x7F}));
  CHECK(encode(128) == bytes({0x81, 0x80}));
  CHECK(encode(255) == bytes({0x81, 0xFF}));
  CHECK(encode(256) == bytes({0x82, 0x01, 0x00}));
  CHECK(encode(65535) == bytes({0x82, 0xFF, 0xFF}));
  CHECK(encode(65536) == bytes({0x83, 0x01, 0x00, 0x00}));
  CHECK(encode(0x01020304) == bytes({0x84, 0x01, 0x02, 0x03, 0x04}));
}

TEST_CASE("nested constructed encoding", "[ber]") {
  byte_buffer out;
  ber::writer w{out};
  w.constructed(ber::tags::sequence, [&] {
    w.write_integer(1);
    w.constructed(ber::context(2), [&] { w.write_null(); });
  });
  CHECK(w.depth() == 0);
  CHECK(out == bytes({0x30, 0x07, 0x02, 0x01, 0x01, 0xA2, 0x02, 0x05, 0x00}));

  out.clear();
  const auto m = w.begin(ber::tags::sequence);
  CHECK(w.depth() == 1);
  w.end(m);
  CHECK(out == bytes({0x30, 0x00}));
}

TEST_CASE("constructed encoding with long-form lengths", "[ber]") {
  for (const std::size_t payload : {125U, 126U, 127U, 200U, 253U, 254U, 300U, 65533U, 70000U}) {
    CAPTURE(payload);
    const byte_buffer data(payload, 0x5A);
    byte_buffer out{0xEE};  // pre-existing content is preserved
    ber::writer w{out};
    w.constructed(ber::application(1), [&] {
      w.constructed(ber::tags::sequence, [&] { w.write_octet_string(data); });
      w.write_boolean(true);
    });
    REQUIRE(out.front() == 0xEE);

    ber::reader rd{openiec61850::byte_view{out}.subspan(1)};
    auto app = rd.enter(ber::application(1));
    REQUIRE(app);
    CHECK(rd.empty());
    auto seq = app->enter(ber::tags::sequence);
    REQUIRE(seq);
    const auto e = seq->peek();
    REQUIRE(e);
    CHECK(e->header_size() == 1 + ber::encoded_length_size(payload));
    CHECK(copy(*seq->read_octet_string()) == data);
    CHECK(seq->empty());
    CHECK(*app->read_boolean());
    CHECK(app->empty());

    // Minimal lengths: total size is fully determined.
    const std::size_t octets = 1 + ber::encoded_length_size(payload) + payload;
    const std::size_t seq_size = 1 + ber::encoded_length_size(octets) + octets;
    const std::size_t app_size = 1 + ber::encoded_length_size(seq_size + 3) + seq_size + 3;
    CHECK(out.size() == 1 + app_size);
  }
}

TEST_CASE("write_tlv and write_raw", "[ber]") {
  byte_buffer inner;
  ber::writer{inner}.write_integer(5);

  byte_buffer out;
  ber::writer w{out};
  w.write_tlv(ber::context(1, true), inner);
  w.write_raw(inner);
  w.write_tlv(ber::context(200), bytes({0x01}));
  CHECK(out == bytes({0xA1, 0x03, 0x02, 0x01, 0x05, 0x02, 0x01, 0x05, 0x9F, 0x81, 0x48, 0x01,
                      0x01}));
}

TEST_CASE("implicit tags on primitive encoders", "[ber]") {
  byte_buffer out;
  ber::writer w{out};
  w.write_unsigned(42, ber::context(0));
  w.write_boolean(true, ber::context(1));
  w.write_visible_string("x", ber::context(2));
  REQUIRE(w.write_oid(ber::oid{2, 2, 1, 0, 1}, ber::context(3)));
  CHECK(out == bytes({0x80, 0x01, 0x2A, 0x81, 0x01, 0xFF, 0x82, 0x01, 'x', 0x83, 0x04, 0x52,
                      0x01, 0x00, 0x01}));

  ber::reader rd{out};
  CHECK(*rd.read_unsigned(ber::context(0)) == 42);
  CHECK(*rd.read_boolean(ber::context(1)));
  CHECK(*rd.read_visible_string(ber::context(2)) == "x");
  CHECK(*rd.read_oid(ber::context(3)) == ber::oid{2, 2, 1, 0, 1});
  CHECK(rd.empty());
}
