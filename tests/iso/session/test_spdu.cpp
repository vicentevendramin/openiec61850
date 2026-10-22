#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <vector>

#include "openiec61850/iso/session/spdu.hpp"

using openiec61850::byte_buffer;
using openiec61850::byte_view;
using openiec61850::errc;
namespace ss = openiec61850::iso::session;

namespace {

bool same(byte_view a, byte_view b) { return std::equal(a.begin(), a.end(), b.begin(), b.end()); }

byte_buffer filled(std::size_t n) {
  byte_buffer b(n);
  for (std::size_t i = 0; i < n; ++i) b[i] = static_cast<std::uint8_t>(i);
  return b;
}

template <typename T>
T decode_as(byte_view tsdu) {
  auto r = ss::decode_tsdu(tsdu);
  REQUIRE(r);
  REQUIRE(std::holds_alternative<T>(*r));
  return std::get<T>(*r);
}

const byte_buffer selector{0x00, 0x01};

// CN: Connect/Accept Item {protocol options 0, version 2}, requirements = duplex, calling and called
// selectors 0x0001, user data AA BB CC.
const byte_buffer connect_vector{0x0D, 0x19, 0x05, 0x06, 0x13, 0x01, 0x00, 0x16, 0x01, 0x02,
                                 0x14, 0x02, 0x00, 0x02, 0x33, 0x02, 0x00, 0x01, 0x34, 0x02,
                                 0x00, 0x01, 0xC1, 0x03, 0xAA, 0xBB, 0xCC};

}  // namespace

TEST_CASE("CN encodes to the known-answer vector", "[session]") {
  const byte_buffer user_data{0xAA, 0xBB, 0xCC};
  ss::connect_spdu cn;
  cn.version_number = ss::version_2;
  cn.session_requirements = ss::fu::duplex;
  cn.calling_selector = selector;
  cn.called_selector = selector;
  cn.user_data = user_data;
  byte_buffer out;
  REQUIRE(ss::encode(cn, out));
  CHECK(out == connect_vector);
}

TEST_CASE("CN decodes from the known-answer vector", "[session]") {
  const auto cn = decode_as<ss::connect_spdu>(connect_vector);
  CHECK_FALSE(cn.connection_id);
  CHECK(cn.protocol_options == 0);
  CHECK(cn.version_number == ss::version_2);
  CHECK(cn.session_requirements == ss::fu::duplex);
  CHECK(same(cn.calling_selector, selector));
  CHECK(same(cn.called_selector, selector));
  CHECK(same(cn.user_data, byte_buffer{0xAA, 0xBB, 0xCC}));
  // Zero-copy: the user data points into the TSDU.
  CHECK(cn.user_data.data() == connect_vector.data() + 24);
}

TEST_CASE("CN without Connect/Accept Item and requirements gets the defaults", "[session]") {
  const byte_buffer tsdu{0x0D, 0x00};
  const auto cn = decode_as<ss::connect_spdu>(tsdu);
  CHECK(cn.version_number == ss::version_1);
  CHECK(cn.session_requirements == ss::fu::default_requirements);
  CHECK(cn.user_data.empty());
}

TEST_CASE("CN with connection identifier and TSDU maximum size round-trips", "[session]") {
  const byte_buffer ref{'r', 'e', 'f'}, common{'c'}, extra{1, 2};
  ss::connect_spdu cn;
  cn.connection_id = ss::connection_identifier{ref, common, extra};
  cn.tsdu_max_size = ss::tsdu_maximum_size{0x1234, 0};
  cn.version_number = ss::version_1 | ss::version_2;
  cn.token_setting = 0x00;
  byte_buffer out;
  REQUIRE(ss::encode(cn, out));
  const auto back = decode_as<ss::connect_spdu>(out);
  REQUIRE(back.connection_id);
  CHECK(same(back.connection_id->ss_user_reference, ref));
  CHECK(same(back.connection_id->common_reference, common));
  CHECK(same(back.connection_id->additional_reference, extra));
  REQUIRE(back.tsdu_max_size);
  CHECK(back.tsdu_max_size->initiator_to_responder == 0x1234);
  CHECK(back.tsdu_max_size->responder_to_initiator == 0);
  CHECK(back.version_number == (ss::version_1 | ss::version_2));
  CHECK(back.token_setting == std::uint8_t{0});
}

TEST_CASE("CN user data above 512 octets uses Extended User Data", "[session]") {
  const auto user_data = filled(600);
  ss::connect_spdu cn;
  cn.user_data = user_data;
  byte_buffer out;
  REQUIRE(ss::encode(cn, out));
  // SI, LI (3 octets), Connect/Accept Item (8), requirements (4), PGI 194 header.
  REQUIRE(out.size() == 4 + 8 + 4 + 4 + 600);
  CHECK(out[0] == 0x0D);
  CHECK(out[1] == 0xFF);
  CHECK(out[16] == 0xC2);
  CHECK(out[17] == 0xFF);
  CHECK(out[18] == 0x02);
  CHECK(out[19] == 0x58);
  CHECK(same(decode_as<ss::connect_spdu>(out).user_data, user_data));

  SECTION("not allowed in version 1") {
    cn.version_number = ss::version_1;
    byte_buffer v1;
    CHECK(ss::encode(cn, v1).error() == errc::length_overflow);
    CHECK(v1.empty());
  }
  SECTION("above 10240 octets needs CDO") {
    const auto big = filled(10241);
    cn.user_data = big;
    byte_buffer v2;
    CHECK(ss::encode(cn, v2).error() == errc::unsupported);
  }
}

TEST_CASE("AC encodes to the known-answer vector", "[session]") {
  const byte_buffer user_data{0xDE, 0xAD};
  ss::accept_spdu ac;
  ac.responding_selector = selector;
  ac.user_data = user_data;
  byte_buffer out;
  REQUIRE(ss::encode(ac, out));
  const byte_buffer expected{0x0E, 0x14, 0x05, 0x06, 0x13, 0x01, 0x00, 0x16, 0x01, 0x02, 0x14,
                             0x02, 0x00, 0x02, 0x34, 0x02, 0x00, 0x01, 0xC1, 0x02, 0xDE, 0xAD};
  CHECK(out == expected);
  const auto back = decode_as<ss::accept_spdu>(out);
  CHECK(back.version_number == ss::version_2);
  CHECK(back.session_requirements == ss::fu::duplex);
  CHECK(same(back.responding_selector, selector));
  CHECK(back.calling_selector.empty());
  CHECK(same(back.user_data, user_data));
}

TEST_CASE("AC with user data above 254 octets uses the extended LI form", "[session]") {
  const auto user_data = filled(300);
  ss::accept_spdu ac;
  ac.responding_selector = selector;
  ac.user_data = user_data;
  byte_buffer out;
  REQUIRE(ss::encode(ac, out));
  // Parameter field: 8 + 4 + 4 + (4 + 300) = 320 = 0x0140.
  REQUIRE(out.size() == 4 + 320);
  CHECK(out[0] == 0x0E);
  CHECK(out[1] == 0xFF);
  CHECK(out[2] == 0x01);
  CHECK(out[3] == 0x40);
  CHECK(out[20] == 0xC1);
  CHECK(out[21] == 0xFF);
  CHECK(out[22] == 0x01);
  CHECK(out[23] == 0x2C);
  CHECK(same(decode_as<ss::accept_spdu>(out).user_data, user_data));
}

TEST_CASE("LI extended form is accepted for short lengths", "[session]") {
  const byte_buffer tsdu{0x1A, 0xFF, 0x00, 0x00};
  CHECK(std::holds_alternative<ss::abort_accept_spdu>(*ss::decode_tsdu(tsdu)));
}

TEST_CASE("data TSDU is GT followed by DT", "[session]") {
  const byte_buffer payload{0x01, 0x02, 0x03};
  byte_buffer out;
  ss::encode_data_tsdu(payload, out);
  CHECK(out == byte_buffer{0x01, 0x00, 0x01, 0x00, 0x01, 0x02, 0x03});

  byte_buffer via_struct;
  REQUIRE(ss::encode(ss::spdu{ss::data_transfer_spdu{std::nullopt, payload}}, via_struct));
  CHECK(via_struct == out);

  const auto dt = decode_as<ss::data_transfer_spdu>(out);
  CHECK_FALSE(dt.enclosure);
  CHECK(same(dt.user_information, payload));
  CHECK(dt.user_information.data() == out.data() + 4);
}

TEST_CASE("data TSDU with enclosure item and large payload", "[session]") {
  const auto payload = filled(70000);
  byte_buffer out;
  REQUIRE(ss::encode(ss::data_transfer_spdu{ss::enclosure::complete, payload}, out));
  CHECK(out.size() == 4 + 3 + 70000);
  const auto dt = decode_as<ss::data_transfer_spdu>(out);
  CHECK(dt.enclosure == ss::enclosure::complete);
  CHECK(same(dt.user_information, payload));
}

TEST_CASE("GT alone decodes as give tokens", "[session]") {
  CHECK_FALSE(decode_as<ss::give_tokens_spdu>(byte_buffer{0x01, 0x00}).token_item);
  CHECK(decode_as<ss::give_tokens_spdu>(byte_buffer{0x01, 0x03, 0x10, 0x01, 0x01}).token_item ==
        std::uint8_t{1});
}

TEST_CASE("FN, DN, AB, AA and RF known-answer vectors", "[session]") {
  const byte_buffer fn_data{0x61, 0x00};
  const byte_buffer dn_data{0x62, 0x00};
  byte_buffer out;

  SECTION("FN") {
    REQUIRE(ss::encode(ss::finish_spdu{ss::transport_disconnect::released, std::nullopt, fn_data},
                       out));
    CHECK(out == byte_buffer{0x09, 0x07, 0x11, 0x01, 0x01, 0xC1, 0x02, 0x61, 0x00});
    const auto fn = decode_as<ss::finish_spdu>(out);
    CHECK(fn.transport_disconnect == ss::transport_disconnect::released);
    CHECK(same(fn.user_data, fn_data));
  }
  SECTION("DN") {
    REQUIRE(ss::encode(ss::disconnect_spdu{std::nullopt, dn_data}, out));
    CHECK(out == byte_buffer{0x0A, 0x04, 0xC1, 0x02, 0x62, 0x00});
    CHECK(same(decode_as<ss::disconnect_spdu>(out).user_data, dn_data));
  }
  SECTION("AB") {
    ss::abort_spdu ab;
    ab.transport_disconnect = ss::transport_disconnect::released | ss::transport_disconnect::user_abort;
    REQUIRE(ss::encode(ab, out));
    CHECK(out == byte_buffer{0x19, 0x03, 0x11, 0x01, 0x03});
    CHECK(decode_as<ss::abort_spdu>(out).transport_disconnect == std::uint8_t{3});
  }
  SECTION("AA") {
    REQUIRE(ss::encode(ss::abort_accept_spdu{}, out));
    CHECK(out == byte_buffer{0x1A, 0x00});
  }
  SECTION("RF") {
    ss::refuse_spdu rf;
    rf.transport_disconnect = ss::transport_disconnect::released;
    rf.reason = ss::refuse_reason::selector_unknown;
    REQUIRE(ss::encode(rf, out));
    CHECK(out == byte_buffer{0x0C, 0x06, 0x11, 0x01, 0x01, 0x32, 0x01, 0x81});
    const auto back = decode_as<ss::refuse_spdu>(out);
    CHECK(back.reason == ss::refuse_reason::selector_unknown);
    CHECK(back.user_data.empty());
  }
}

TEST_CASE("RF, AB, NF and GT round-trip through the variant encoder", "[session]") {
  const byte_buffer data{1, 2, 3, 4};
  const byte_buffer reflect{9, 9};

  ss::refuse_spdu rf;
  rf.session_requirements = ss::fu::duplex;
  rf.version_number = ss::version_2;
  rf.reason = ss::refuse_reason::rejected_by_user;
  rf.user_data = data;
  byte_buffer out;
  REQUIRE(ss::encode(ss::spdu{rf}, out));
  const auto rf2 = decode_as<ss::refuse_spdu>(out);
  CHECK(rf2.session_requirements == ss::fu::duplex);
  CHECK(rf2.version_number == ss::version_2);
  CHECK(rf2.reason == ss::refuse_reason::rejected_by_user);
  CHECK(same(rf2.user_data, data));

  ss::abort_spdu ab;
  ab.transport_disconnect = ss::transport_disconnect::protocol_error;
  ab.reflect_parameter = reflect;
  ab.user_data = data;
  out.clear();
  REQUIRE(ss::encode(ss::spdu{ab}, out));
  const auto ab2 = decode_as<ss::abort_spdu>(out);
  CHECK(ab2.transport_disconnect == ss::transport_disconnect::protocol_error);
  CHECK(same(ab2.reflect_parameter, reflect));
  CHECK(same(ab2.user_data, data));

  out.clear();
  REQUIRE(ss::encode(ss::spdu{ss::not_finished_spdu{std::nullopt, data}}, out));
  CHECK(out[0] == ss::si::not_finished);
  CHECK(same(decode_as<ss::not_finished_spdu>(out).user_data, data));

  out.clear();
  REQUIRE(ss::encode(ss::spdu{ss::give_tokens_spdu{std::uint8_t{0x01}}}, out));
  CHECK(out == byte_buffer{0x01, 0x03, 0x10, 0x01, 0x01});
}

TEST_CASE("encoders append to the output buffer", "[session]") {
  byte_buffer out{0xEE};
  REQUIRE(ss::encode(ss::abort_accept_spdu{}, out));
  CHECK(out == byte_buffer{0xEE, 0x1A, 0x00});
}

TEST_CASE("encoders reject oversized fields", "[session]") {
  const auto long_selector = filled(17);
  ss::connect_spdu cn;
  cn.called_selector = long_selector;
  byte_buffer out;
  CHECK(ss::encode(cn, out).error() == errc::length_overflow);

  const auto huge = filled(70000);
  ss::accept_spdu ac;
  ac.user_data = huge;
  CHECK(ss::encode(ac, out).error() == errc::length_overflow);
  CHECK(out.empty());
}

TEST_CASE("unknown parameters are skipped", "[session]") {
  // CN with an unknown PI inside the Connect/Accept Item and an unknown PI at the top level.
  const byte_buffer tsdu{0x0D, 0x0D, 0x05, 0x07, 0x7F, 0x00, 0x16, 0x01, 0x02,
                         0x13, 0x00, 0x99, 0x02, 0xAB, 0xCD};
  // As is, the zero-length Protocol Options (0x13) is a known PI with a wrong size; renaming it to an
  // unknown code makes the TSDU valid.
  byte_buffer ok = tsdu;
  ok[9] = 0x7E;
  const auto cn = decode_as<ss::connect_spdu>(ok);
  CHECK(cn.version_number == ss::version_2);
  CHECK(cn.protocol_options == 0);
  CHECK(ss::decode_tsdu(tsdu).error() == errc::malformed_encoding);
}

TEST_CASE("malformed TSDUs are rejected", "[session]") {
  auto error_of = [](const byte_buffer& b) { return ss::decode_tsdu(b).error(); };

  CHECK(error_of({}) == errc::truncated_input);
  CHECK(error_of({0x0D}) == errc::truncated_input);
  CHECK(error_of({0x0D, 0xFF, 0x01}) == errc::truncated_input);
  // LI beyond the buffer.
  CHECK(error_of({0x0D, 0x05, 0x14, 0x02}) == errc::length_overflow);
  CHECK(error_of({0x0D, 0xFF, 0x01, 0x00, 0x00}) == errc::length_overflow);
  // PGI length overflowing the SPDU parameter field.
  CHECK(error_of({0x0D, 0x04, 0x05, 0x06, 0x13, 0x01}) == errc::length_overflow);
  // ... and with the SPDU LI covering the whole buffer, the PGI overflow leaves trailing octets.
  CHECK(error_of({0x0D, 0x04, 0x05, 0x06, 0x13, 0x01, 0x00, 0x16, 0x01, 0x02}) ==
        errc::malformed_encoding);
  // PI length overflowing its PGI.
  CHECK(error_of({0x0D, 0x05, 0x05, 0x03, 0x13, 0x05, 0x00}) == errc::length_overflow);
  // Parameter header cut inside the field.
  CHECK(error_of({0x0D, 0x01, 0x14}) == errc::truncated_input);
  // Unknown SI.
  CHECK(error_of({0x63, 0x00}) == errc::malformed_encoding);
  // Known but unsupported SI (CDO).
  CHECK(error_of({0x0F, 0x00}) == errc::unsupported);
  // Trailing octets after a category 1 SPDU.
  CHECK(error_of({0x1A, 0x00, 0x00}) == errc::malformed_encoding);
  // Duplicate parameter.
  CHECK(error_of({0x0D, 0x08, 0x14, 0x02, 0x00, 0x02, 0x14, 0x02, 0x00, 0x02}) ==
        errc::malformed_encoding);
  // Wrong parameter size.
  CHECK(error_of({0x0D, 0x03, 0x14, 0x01, 0x02}) == errc::malformed_encoding);
  CHECK(error_of({0x0D, 0x13, 0x34, 0x11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}) ==
        errc::malformed_encoding);
  // Both User Data and Extended User Data.
  CHECK(error_of({0x0D, 0x06, 0xC1, 0x01, 0x00, 0xC2, 0x01, 0x00}) == errc::malformed_encoding);
  // RF without Reason Code.
  CHECK(error_of({0x0C, 0x03, 0x11, 0x01, 0x01}) == errc::malformed_encoding);
  CHECK(error_of({0x0C, 0x02, 0x32, 0x00}) == errc::malformed_encoding);
  // GT followed by a truncated or non-DT category 2 SPDU.
  CHECK(error_of({0x01, 0x00, 0x01}) == errc::truncated_input);
  CHECK(error_of({0x01, 0x00, 0x01, 0x05, 0x19}) == errc::length_overflow);
  CHECK(error_of({0x01, 0x00, 0x21, 0x00}) == errc::unsupported);
  // PT is outside the profile.
  CHECK(error_of({0x02, 0x00}) == errc::unsupported);
}

TEST_CASE("every strict prefix of a CN is rejected", "[session]") {
  for (std::size_t n = 0; n < connect_vector.size(); ++n) {
    const byte_view prefix{connect_vector.data(), n};
    CHECK_FALSE(ss::decode_tsdu(prefix));
  }
}
