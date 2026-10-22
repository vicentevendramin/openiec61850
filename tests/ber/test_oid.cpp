#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <limits>
#include <string>

#include "ber_test_util.hpp"
#include "openiec61850/ber/decode.hpp"
#include "openiec61850/ber/oid.hpp"
#include "openiec61850/ber/writer.hpp"

namespace ber = openiec61850::ber;
using ber_test::bytes;
using openiec61850::byte_buffer;
using openiec61850::errc;

namespace {

byte_buffer encode_oid(const ber::oid& v) {
  byte_buffer out;
  ber::writer w{out};
  REQUIRE(w.write_oid(v));
  return out;
}

}  // namespace

TEST_CASE("OBJECT IDENTIFIER known answers", "[ber]") {
  struct kat {
    ber::oid value;
    byte_buffer encoding;
  };
  const kat vectors[] = {
      // MMS abstract syntax (ISO 9506-2)
      {{1, 0, 9506, 2, 1}, bytes({0x06, 0x05, 0x28, 0xCA, 0x22, 0x02, 0x01})},
      // ACSE abstract syntax (ISO 8650)
      {{2, 2, 1, 0, 1}, bytes({0x06, 0x04, 0x52, 0x01, 0x00, 0x01})},
      // Basic encoding of a single ASN.1 type
      {{2, 1, 1}, bytes({0x06, 0x02, 0x51, 0x01})},
      {{1, 2, 840, 113549}, bytes({0x06, 0x06, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D})},
      // X.690 §8.19.5 example
      {{2, 999, 3}, bytes({0x06, 0x03, 0x88, 0x37, 0x03})},
      {{0, 0}, bytes({0x06, 0x01, 0x00})},
      {{1, 39}, bytes({0x06, 0x01, 0x4F})},
      {{0, 1, 4294967295U},
       bytes({0x06, 0x06, 0x01, 0x8F, 0xFF, 0xFF, 0xFF, 0x7F})},
  };
  for (const auto& v : vectors) {
    CHECK(encode_oid(v.value) == v.encoding);
    const auto decoded = ber::decode_oid(openiec61850::byte_view{v.encoding}.subspan(2));
    REQUIRE(decoded);
    CHECK(*decoded == v.value);
  }
}

TEST_CASE("OBJECT IDENTIFIER first subidentifier near the limit", "[ber]") {
  const ber::oid big{2, 4294967295U};
  const auto enc = encode_oid(big);
  const auto decoded = ber::decode_oid(openiec61850::byte_view{enc}.subspan(2));
  REQUIRE(decoded);
  CHECK(*decoded == big);
  // 2^32 + 80 as the first subidentifier: arc 2 would be 2^32.
  CHECK(ber::decode_oid(bytes({0x90, 0x80, 0x80, 0x80, 0x50})).error() == errc::unsupported);
}

TEST_CASE("malformed OBJECT IDENTIFIER", "[ber]") {
  CHECK(ber::decode_oid(byte_buffer{}).error() == errc::malformed_encoding);
  // §8.19.2: no leading 0x80 octet in a subidentifier.
  CHECK(ber::decode_oid(bytes({0x80, 0x01})).error() == errc::malformed_encoding);
  CHECK(ber::decode_oid(bytes({0x28, 0x80, 0x01})).error() == errc::malformed_encoding);
  // Last octet with bit 8 set.
  CHECK(ber::decode_oid(bytes({0x28, 0xCA})).error() == errc::malformed_encoding);
  // Arc above 2^32-1.
  CHECK(ber::decode_oid(bytes({0x28, 0x90, 0x80, 0x80, 0x80, 0x00})).error() ==
        errc::unsupported);
  // More arcs than oid::max_arcs.
  byte_buffer many(ber::oid::max_arcs, 0x01);
  CHECK(ber::decode_oid(many).error() == errc::unsupported);
  CHECK(ber::decode_oid(byte_buffer(ber::oid::max_arcs - 1, 0x01)));
}

TEST_CASE("OBJECT IDENTIFIER dotted notation", "[ber]") {
  auto v = ber::oid::from_string("1.0.9506.2.1");
  REQUIRE(v);
  CHECK(*v == ber::oid{1, 0, 9506, 2, 1});
  CHECK(v->to_string() == "1.0.9506.2.1");
  CHECK(v->size() == 5);
  CHECK((*v)[2] == 9506);

  CHECK(ber::oid{2, 2, 1, 0, 1}.to_string() == "2.2.1.0.1");
  CHECK(ber::oid{0, 0}.to_string() == "0.0");
  CHECK(ber::oid::from_string("2.999.4294967295")->to_string() == "2.999.4294967295");

  for (const char* bad : {"", "1", "1.", ".1", "1..2", "3.1", "1.40", "0.40.1", "01.2", "1.02",
                          "1.2.a", "1.2 ", "-1.2", "+1.2", "1.2.4294967296"}) {
    CAPTURE(bad);
    CHECK(ber::oid::from_string(bad).error() == errc::malformed_encoding);
  }

  std::string many = "1.2";
  for (std::size_t i = 2; i < ber::oid::max_arcs; ++i) many += ".7";
  CHECK(ber::oid::from_string(many));
  many += ".7";
  CHECK(ber::oid::from_string(many).error() == errc::unsupported);
}

TEST_CASE("oid value semantics", "[ber]") {
  constexpr ber::oid mms{1, 0, 9506, 2, 1};
  static_assert(mms.valid());
  static_assert(mms.size() == 5);
  CHECK(mms != ber::oid{1, 0, 9506, 2});
  CHECK(mms != ber::oid{1, 0, 9506, 2, 3});
  CHECK_FALSE(ber::oid{}.valid());
  CHECK_FALSE(ber::oid{1}.valid());
  CHECK_FALSE(ber::oid{3, 1}.valid());
  CHECK_FALSE(ber::oid{1, 40}.valid());
  CHECK(ber::oid{2, 40}.valid());

  std::uint32_t sum = 0;
  for (auto arc : mms) sum += arc;
  CHECK(sum == 9510);
  CHECK(mms.arcs().size() == 5);

  byte_buffer out;
  ber::writer w{out};
  CHECK(w.write_oid(ber::oid{3, 1}).error() == errc::malformed_encoding);
  CHECK(out.empty());
}
