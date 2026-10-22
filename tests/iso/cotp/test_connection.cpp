#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <vector>

#include "openiec61850/iso/cotp/connection.hpp"

using openiec61850::byte_buffer;
using openiec61850::byte_view;
using openiec61850::errc;
using namespace openiec61850::iso::cotp;

namespace {

const byte_buffer mms_cr_tpkt{0x03, 0x00, 0x00, 0x16, 0x11, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00,
                              0xC1, 0x02, 0x00, 0x01, 0xC2, 0x02, 0x00, 0x01, 0xC0, 0x01, 0x0A};
const byte_buffer mms_cc_tpkt{0x03, 0x00, 0x00, 0x16, 0x11, 0xD0, 0x00, 0x01, 0x00, 0x02, 0x00,
                              0xC1, 0x02, 0x00, 0x01, 0xC2, 0x02, 0x00, 0x01, 0xC0, 0x01, 0x0A};

connection_config initiator_config(std::size_t max_tpdu = 1024) {
  connection_config c;
  c.local_reference = 1;
  c.calling_tsap = byte_buffer{0x00, 0x01};
  c.called_tsap = byte_buffer{0x00, 0x01};
  c.max_tpdu_size = max_tpdu;
  return c;
}

connection_config responder_config(std::size_t max_tpdu = 2048) {
  connection_config c;
  c.local_reference = 2;
  c.max_tpdu_size = max_tpdu;
  return c;
}

connection make(role r, connection_config c) {
  auto conn = connection::create(r, std::move(c));
  REQUIRE(conn);
  return std::move(*conn);
}

std::vector<event> pump(connection& from, connection& to) {
  std::vector<event> events;
  to.feed(from.take_output(), events);
  return events;
}

const disconnect_indication& single_disconnect(const std::vector<event>& events) {
  REQUIRE(events.size() == 1);
  const auto* d = std::get_if<disconnect_indication>(&events[0]);
  REQUIRE(d);
  return *d;
}

// Connects an initiator and a responder; returns the negotiated size seen by both.
std::size_t establish(connection& initiator, connection& responder) {
  REQUIRE(initiator.connect());
  auto at_responder = pump(initiator, responder);
  REQUIRE(at_responder.size() == 1);
  REQUIRE(std::holds_alternative<connected_indication>(at_responder[0]));
  auto at_initiator = pump(responder, initiator);
  REQUIRE(at_initiator.size() == 1);
  const auto& ci = std::get<connected_indication>(at_initiator[0]);
  CHECK(ci.tpdu_size == std::get<connected_indication>(at_responder[0]).tpdu_size);
  CHECK(initiator.state() == connection_state::open);
  CHECK(responder.state() == connection_state::open);
  return ci.tpdu_size;
}

// The parsed TPKT payloads in a byte stream.
std::vector<byte_buffer> packets(const byte_buffer& stream) {
  std::vector<byte_buffer> out;
  tpkt_framer framer;
  framer.feed(stream);
  while (true) {
    auto p = framer.next();
    REQUIRE(p);
    if (!*p) break;
    out.emplace_back((*p)->begin(), (*p)->end());
  }
  REQUIRE(framer.buffered() == 0);
  return out;
}

byte_buffer pattern(std::size_t n) {
  byte_buffer b(n);
  for (std::size_t i = 0; i < n; ++i) b[i] = static_cast<std::uint8_t>(i * 31 + 7);
  return b;
}

}  // namespace

TEST_CASE("Config validation", "[cotp]") {
  auto c = responder_config(4096);
  CHECK(connection::create(role::responder, c).error() == errc::unsupported);
  c.max_tpdu_size = 1000;
  CHECK(connection::create(role::responder, c).error() == errc::unsupported);
  c = initiator_config();
  c.called_tsap = byte_buffer(256, 0);
  CHECK(connection::create(role::initiator, c).error() == errc::length_overflow);
}

TEST_CASE("Initiator sends the MMS-style CR", "[cotp]") {
  auto conn = make(role::initiator, initiator_config());
  CHECK(conn.state() == connection_state::idle);
  REQUIRE(conn.connect());
  CHECK(conn.state() == connection_state::awaiting_cc);
  CHECK(conn.take_output() == mms_cr_tpkt);
  CHECK(conn.connect().error() == errc::invalid_state);

  std::vector<event> events;
  conn.feed(mms_cc_tpkt, events);
  REQUIRE(events.size() == 1);
  const auto& ci = std::get<connected_indication>(events[0]);
  CHECK(ci.tpdu_size == 1024);
  CHECK(ci.remote_reference == 2);
  CHECK(conn.state() == connection_state::open);
  CHECK(conn.tpdu_size() == 1024);
}

TEST_CASE("Responder answers a CR fed byte by byte with a CC", "[cotp]") {
  auto conn = make(role::responder, responder_config());
  CHECK(conn.state() == connection_state::awaiting_cr);
  std::vector<event> events;
  for (const auto b : mms_cr_tpkt) conn.feed(byte_view{&b, 1}, events);
  REQUIRE(events.size() == 1);
  const auto& ci = std::get<connected_indication>(events[0]);
  CHECK(ci.tpdu_size == 1024);
  CHECK(ci.remote_reference == 1);
  CHECK(ci.calling_tsap == byte_buffer{0x00, 0x01});
  CHECK(ci.called_tsap == byte_buffer{0x00, 0x01});
  CHECK(conn.take_output() == mms_cc_tpkt);
  CHECK_FALSE(conn.has_output());
}

TEST_CASE("TPDU size negotiation", "[cotp]") {
  SECTION("responder lowers the proposal") {
    auto i = make(role::initiator, initiator_config(2048));
    auto r = make(role::responder, responder_config(512));
    CHECK(establish(i, r) == 512);
  }
  SECTION("responder keeps a smaller proposal") {
    auto i = make(role::initiator, initiator_config(256));
    auto r = make(role::responder, responder_config(2048));
    CHECK(establish(i, r) == 256);
  }
  SECTION("a proposal above the class 0 limit is lowered") {
    auto r = make(role::responder, responder_config());
    std::vector<event> events;
    r.feed(byte_buffer{0x03, 0x00, 0x00, 0x0E, 0x09, 0xE0, 0x00, 0x00, 0x00, 0x07, 0x00, 0xC0, 0x01,
                       0x0D},
           events);
    REQUIRE(events.size() == 1);
    CHECK(std::get<connected_indication>(events[0]).tpdu_size == 2048);
    CHECK(r.take_output() == byte_buffer{0x03, 0x00, 0x00, 0x0E, 0x09, 0xD0, 0x00, 0x07, 0x00, 0x02,
                                         0x00, 0xC0, 0x01, 0x0B});
  }
  SECTION("an absent TPDU size means 128") {
    auto r = make(role::responder, responder_config());
    std::vector<event> events;
    r.feed(byte_buffer{0x03, 0x00, 0x00, 0x0B, 0x06, 0xE0, 0x00, 0x00, 0x00, 0x07, 0x00}, events);
    REQUIRE(events.size() == 1);
    CHECK(std::get<connected_indication>(events[0]).tpdu_size == 128);
  }
  SECTION("initiator rejects a CC that raises the size") {
    auto i = make(role::initiator, initiator_config(512));
    REQUIRE(i.connect());
    (void)i.take_output();
    std::vector<event> events;
    i.feed(mms_cc_tpkt, events);  // 1024
    const auto& d = single_disconnect(events);
    CHECK(d.origin == disconnect_origin::protocol_error);
    CHECK(d.error == errc::protocol_violation);
    CHECK(d.reason == reject_cause::invalid_parameter_value);
    auto out = packets(i.take_output());
    REQUIRE(out.size() == 1);
    CHECK(out[0][1] == 0x70);  // ER
    CHECK(i.state() == connection_state::closed);
  }
  SECTION("initiator rejects a CC with mismatched references") {
    auto i = make(role::initiator, initiator_config());
    REQUIRE(i.connect());
    auto cc = mms_cc_tpkt;
    cc[7] = 0x09;  // DST-REF 0x0009
    std::vector<event> events;
    i.feed(cc, events);
    CHECK(single_disconnect(events).origin == disconnect_origin::protocol_error);
  }
}

TEST_CASE("Segmentation and reassembly round trip", "[cotp]") {
  const std::size_t tpdu = GENERATE(128u, 256u, 1024u, 2048u);
  auto i = make(role::initiator, initiator_config(tpdu));
  auto r = make(role::responder, responder_config());
  REQUIRE(establish(i, r) == tpdu);
  const std::size_t max_segment = tpdu - 3;

  for (const std::size_t n : {std::size_t{0}, std::size_t{1}, max_segment, max_segment + 1,
                              3 * max_segment, std::size_t{10000}}) {
    const auto tsdu = pattern(n);
    REQUIRE(i.send(tsdu));
    const auto stream = i.take_output();
    const auto dts = packets(stream);
    REQUIRE(dts.size() == (n == 0 ? 1 : (n + max_segment - 1) / max_segment));
    for (std::size_t k = 0; k < dts.size(); ++k) {
      CHECK(dts[k].size() <= tpdu);
      CHECK(dts[k][0] == 0x02);
      CHECK(dts[k][1] == 0xF0);
      CHECK(dts[k][2] == (k + 1 == dts.size() ? 0x80 : 0x00));
    }

    // Deliver in uneven chunks.
    std::vector<event> events;
    for (std::size_t off = 0; off < stream.size(); off += 97) {
      r.feed(byte_view{stream}.subspan(off, std::min<std::size_t>(97, stream.size() - off)), events);
    }
    REQUIRE(events.size() == 1);
    CHECK(std::get<data_indication>(events[0]).tsdu == tsdu);
  }

  // And in the other direction, several TSDUs in one chunk.
  REQUIRE(r.send(pattern(5000)));
  REQUIRE(r.send(pattern(3)));
  auto events = pump(r, i);
  REQUIRE(events.size() == 2);
  CHECK(std::get<data_indication>(events[0]).tsdu == pattern(5000));
  CHECK(std::get<data_indication>(events[1]).tsdu == pattern(3));
}

TEST_CASE("TSAP hook refuses a connection with a DR", "[cotp]") {
  auto cfg = responder_config();
  cfg.accept_connection = [](const connection_request& cr) -> std::optional<std::uint8_t> {
    if (cr.called_tsap == byte_buffer{0x00, 0x01}) return disconnect_reason::address_unknown;
    return std::nullopt;
  };
  auto r = make(role::responder, cfg);
  auto i = make(role::initiator, initiator_config());
  REQUIRE(i.connect());
  auto at_r = pump(i, r);
  const auto& local = single_disconnect(at_r);
  CHECK(local.origin == disconnect_origin::local_refusal);
  CHECK(local.reason == disconnect_reason::address_unknown);
  CHECK(r.state() == connection_state::closed);

  const auto dr = r.take_output();
  CHECK(dr == byte_buffer{0x03, 0x00, 0x00, 0x0B, 0x06, 0x80, 0x00, 0x01, 0x00, 0x00, 0x03});
  std::vector<event> at_i;
  i.feed(dr, at_i);
  const auto& remote = single_disconnect(at_i);
  CHECK(remote.origin == disconnect_origin::refused);
  CHECK(remote.reason == disconnect_reason::address_unknown);
  CHECK(i.state() == connection_state::closed);
}

TEST_CASE("Class negotiation", "[cotp]") {
  auto r = make(role::responder, responder_config());
  std::vector<event> events;
  SECTION("class 2 without alternatives is refused") {
    r.feed(byte_buffer{0x03, 0x00, 0x00, 0x0B, 0x06, 0xE0, 0x00, 0x00, 0x00, 0x07, 0x20}, events);
    CHECK(single_disconnect(events).reason == disconnect_reason::negotiation_failed);
    CHECK(r.take_output() ==
          byte_buffer{0x03, 0x00, 0x00, 0x0B, 0x06, 0x80, 0x00, 0x07, 0x00, 0x00, 0x82});
  }
  SECTION("class 2 with class 0 as alternative is accepted as class 0") {
    r.feed(byte_buffer{0x03, 0x00, 0x00, 0x0E, 0x09, 0xE0, 0x00, 0x00, 0x00, 0x07, 0x20, 0xC7,
                       0x01, 0x00},
           events);
    REQUIRE(events.size() == 1);
    CHECK(std::holds_alternative<connected_indication>(events[0]));
    const auto out = packets(r.take_output());
    REQUIRE(out.size() == 1);
    CHECK(out[0][6] == 0x00);  // class 0
  }
}

TEST_CASE("Protocol errors", "[cotp]") {
  std::vector<event> events;

  SECTION("DT before the connection is open is answered with ER") {
    auto r = make(role::responder, responder_config());
    r.feed(byte_buffer{0x03, 0x00, 0x00, 0x08, 0x02, 0xF0, 0x80, 0x01}, events);
    const auto& d = single_disconnect(events);
    CHECK(d.origin == disconnect_origin::protocol_error);
    CHECK(d.error == errc::protocol_violation);
    CHECK(r.take_output() == byte_buffer{0x03, 0x00, 0x00, 0x0E, 0x09, 0x70, 0x00, 0x00, 0x00, 0xC1,
                                         0x03, 0x02, 0xF0, 0x80});
  }
  SECTION("unknown TPDU code is answered with ER invalid TPDU type") {
    auto r = make(role::responder, responder_config());
    r.feed(byte_buffer{0x03, 0x00, 0x00, 0x07, 0x02, 0x30, 0x00}, events);
    const auto& d = single_disconnect(events);
    CHECK(d.reason == reject_cause::invalid_tpdu_type);
    CHECK(d.error == errc::malformed_encoding);
    const auto out = packets(r.take_output());
    REQUIRE(out.size() == 1);
    CHECK(out[0][4] == reject_cause::invalid_tpdu_type);
  }
  SECTION("bad TPKT version closes without ER") {
    auto r = make(role::responder, responder_config());
    r.feed(byte_buffer{0x02, 0x00, 0x00, 0x16}, events);
    const auto& d = single_disconnect(events);
    CHECK(d.error == errc::malformed_encoding);
    CHECK_FALSE(r.has_output());
    CHECK(r.state() == connection_state::closed);
    events.clear();
    r.feed(mms_cr_tpkt, events);
    CHECK(events.empty());
  }
  SECTION("TPKT shorter than a TPDU closes without ER") {
    auto r = make(role::responder, responder_config());
    r.feed(byte_buffer{0x03, 0x00, 0x00, 0x04}, events);
    CHECK(single_disconnect(events).error == errc::malformed_encoding);
    CHECK_FALSE(r.has_output());
  }

  auto i = make(role::initiator, initiator_config(128));
  auto r = make(role::responder, responder_config());
  REQUIRE(establish(i, r) == 128);

  SECTION("DT above the negotiated TPDU size") {
    byte_buffer big{0x03, 0x00, 0x00, 0x88, 0x02, 0xF0, 0x80};  // TPDU of 132 octets
    big.resize(0x88, 0x55);
    r.feed(big, events);
    CHECK(single_disconnect(events).error == errc::length_overflow);
    const auto out = packets(r.take_output());
    REQUIRE(out.size() == 1);
    CHECK(out[0][1] == 0x70);
  }
  SECTION("oversize TSDU closes without ER") {
    auto cfg = responder_config();
    cfg.max_tsdu_size = 300;
    auto small = make(role::responder, cfg);
    auto i2 = make(role::initiator, initiator_config(128));
    REQUIRE(establish(i2, small) == 128);
    REQUIRE(i2.send(pattern(300)));
    auto ok = pump(i2, small);
    REQUIRE(ok.size() == 1);
    REQUIRE(i2.send(pattern(301)));
    const auto failed = pump(i2, small);
    const auto& d = single_disconnect(failed);
    CHECK(d.error == errc::length_overflow);
    CHECK_FALSE(small.has_output());
  }
  SECTION("CR on an open connection") {
    r.feed(mms_cr_tpkt, events);
    CHECK(single_disconnect(events).error == errc::protocol_violation);
    CHECK(r.has_output());
  }
  SECTION("ER from the peer") {
    i.feed(byte_buffer{0x03, 0x00, 0x00, 0x09, 0x04, 0x70, 0x00, 0x01, 0x02}, events);
    const auto& d = single_disconnect(events);
    CHECK(d.origin == disconnect_origin::remote_error);
    CHECK(d.reason == reject_cause::invalid_tpdu_type);
    CHECK_FALSE(i.has_output());
  }
  SECTION("network closed") {
    i.network_closed(events);
    CHECK(single_disconnect(events).origin == disconnect_origin::network_closed);
    CHECK(i.send(pattern(1)).error() == errc::invalid_state);
    events.clear();
    i.network_closed(events);
    CHECK(events.empty());
  }
  SECTION("local close") {
    i.close();
    CHECK(i.state() == connection_state::closed);
    CHECK(i.send(pattern(1)).error() == errc::invalid_state);
  }
}

TEST_CASE("Send requires an open connection", "[cotp]") {
  auto i = make(role::initiator, initiator_config());
  CHECK(i.send(pattern(1)).error() == errc::invalid_state);
  REQUIRE(i.connect());
  CHECK(i.send(pattern(1)).error() == errc::invalid_state);
}
