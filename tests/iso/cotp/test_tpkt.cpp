#include <catch2/catch_test_macros.hpp>

#include <vector>

#include "openiec61850/iso/cotp/tpkt.hpp"

using openiec61850::byte_buffer;
using openiec61850::byte_view;
using openiec61850::errc;
using namespace openiec61850::iso::cotp;

namespace {

// A TPKT carrying a class 0 DT with EOT and the given user data.
byte_buffer dt_packet(std::vector<std::uint8_t> data) {
  byte_buffer out;
  REQUIRE(encode_tpkt_header(3 + data.size(), out));
  out.insert(out.end(), {0x02, 0xF0, 0x80});
  out.insert(out.end(), data.begin(), data.end());
  return out;
}

byte_buffer to_buffer(byte_view v) { return {v.begin(), v.end()}; }

}  // namespace

TEST_CASE("TPKT header encoding", "[cotp]") {
  byte_buffer out;
  REQUIRE(encode_tpkt_header(7, out));
  CHECK(out == byte_buffer{0x03, 0x00, 0x00, 0x0B});
  CHECK(encode_tpkt_header(65532, out).error() == errc::length_overflow);
  CHECK(out.size() == 4);
}

TEST_CASE("TPKT header validation", "[cotp]") {
  const byte_buffer ok{0x03, 0x00, 0x00, 0x16};
  auto len = decode_tpkt_header(ok);
  REQUIRE(len);
  CHECK(*len == 22);
  CHECK(decode_tpkt_header(byte_buffer{0x03, 0x00, 0x00}).error() == errc::truncated_input);
  CHECK(decode_tpkt_header(byte_buffer{0x02, 0x00, 0x00, 0x16}).error() == errc::malformed_encoding);
  CHECK(decode_tpkt_header(byte_buffer{0x03, 0x00, 0x00, 0x06}).error() == errc::malformed_encoding);
  CHECK(decode_tpkt_header(byte_buffer{0x03, 0x00, 0x00, 0x07}));
  CHECK(decode_tpkt_header(byte_buffer{0x03, 0x00, 0x01, 0x00}, 255).error() == errc::length_overflow);
}

TEST_CASE("TPKT framer yields a packet fed byte by byte", "[cotp]") {
  const auto packet = dt_packet({0xA1, 0xA2, 0xA3});
  tpkt_framer framer;
  for (std::size_t i = 0; i + 1 < packet.size(); ++i) {
    framer.feed(byte_view{packet}.subspan(i, 1));
    auto r = framer.next();
    REQUIRE(r);
    CHECK_FALSE(r->has_value());
  }
  framer.feed(byte_view{packet}.last(1));
  auto r = framer.next();
  REQUIRE(r);
  REQUIRE(r->has_value());
  CHECK(to_buffer(**r) == byte_buffer{0x02, 0xF0, 0x80, 0xA1, 0xA2, 0xA3});
  auto end = framer.next();
  REQUIRE(end);
  CHECK_FALSE(end->has_value());
  CHECK(framer.buffered() == 0);
}

TEST_CASE("TPKT framer yields several packets from one chunk", "[cotp]") {
  byte_buffer stream = dt_packet({0x01});
  const auto second = dt_packet({0x02, 0x03});
  stream.insert(stream.end(), second.begin(), second.end());
  const auto third = dt_packet({0x04});
  stream.insert(stream.end(), third.begin(), third.begin() + 5);  // partial

  tpkt_framer framer;
  framer.feed(stream);
  auto a = framer.next();
  REQUIRE(a);
  REQUIRE(a->has_value());
  CHECK(to_buffer(**a) == byte_buffer{0x02, 0xF0, 0x80, 0x01});
  auto b = framer.next();
  REQUIRE(b);
  REQUIRE(b->has_value());
  CHECK(to_buffer(**b) == byte_buffer{0x02, 0xF0, 0x80, 0x02, 0x03});
  auto c = framer.next();
  REQUIRE(c);
  CHECK_FALSE(c->has_value());
  CHECK(framer.buffered() == 5);

  framer.feed(byte_view{third}.subspan(5));
  auto d = framer.next();
  REQUIRE(d);
  REQUIRE(d->has_value());
  CHECK(to_buffer(**d) == byte_buffer{0x02, 0xF0, 0x80, 0x04});
}

TEST_CASE("TPKT framer errors are sticky", "[cotp]") {
  tpkt_framer framer;
  framer.feed(byte_buffer{0x04, 0x00, 0x00, 0x07, 0x02, 0xF0, 0x80});
  CHECK(framer.next().error() == errc::malformed_encoding);
  framer.feed(dt_packet({0x01}));
  CHECK(framer.next().error() == errc::malformed_encoding);
}

TEST_CASE("TPKT framer enforces the maximum length", "[cotp]") {
  tpkt_framer framer{100};
  framer.feed(byte_buffer{0x03, 0x00, 0x00, 0x65});  // 101
  CHECK(framer.next().error() == errc::length_overflow);

  tpkt_framer short_framer;
  short_framer.feed(byte_buffer{0x03, 0x00, 0x00, 0x05, 0x02});
  CHECK(short_framer.next().error() == errc::malformed_encoding);
}
