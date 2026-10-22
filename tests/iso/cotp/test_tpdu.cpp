#include <catch2/catch_test_macros.hpp>

#include "openiec61850/iso/cotp/tpdu.hpp"

using openiec61850::byte_buffer;
using openiec61850::byte_view;
using openiec61850::errc;
using namespace openiec61850::iso::cotp;

namespace {

// Typical MMS association CR: SRC-REF 1, class 0, TSAPs 0x0001/0x0001, TPDU size 1024.
const byte_buffer mms_cr_tpkt{0x03, 0x00, 0x00, 0x16,                    // TPKT, length 22
                              0x11, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00,  // LI 17, CR, DST, SRC, class
                              0xC1, 0x02, 0x00, 0x01,                    // calling TSAP
                              0xC2, 0x02, 0x00, 0x01,                    // called TSAP
                              0xC0, 0x01, 0x0A};                         // TPDU size 1024

const byte_buffer mms_cc{0x11, 0xD0, 0x00, 0x01, 0x00, 0x02, 0x00, 0xC1, 0x02, 0x00,
                         0x01, 0xC2, 0x02, 0x00, 0x01, 0xC0, 0x01, 0x0A};

connection_request mms_cr() {
  connection_request cr;
  cr.src_ref = 0x0001;
  cr.tpdu_size = 0x0A;
  cr.calling_tsap = byte_buffer{0x00, 0x01};
  cr.called_tsap = byte_buffer{0x00, 0x01};
  return cr;
}

}  // namespace

TEST_CASE("TPDU size codes", "[cotp]") {
  CHECK(tpdu_size_from_code(7) == 128u);
  CHECK(tpdu_size_from_code(0x0A) == 1024u);
  CHECK(tpdu_size_from_code(13) == 8192u);
  CHECK_FALSE(tpdu_size_from_code(6));
  CHECK_FALSE(tpdu_size_from_code(14));
  CHECK(tpdu_size_code(2048) == std::uint8_t{0x0B});
  CHECK_FALSE(tpdu_size_code(1000));
}

TEST_CASE("TPDU kind classification", "[cotp]") {
  CHECK(tpdu_kind_of(0xE0) == tpdu_kind::cr);
  CHECK(tpdu_kind_of(0xE3) == tpdu_kind::cr);
  CHECK(tpdu_kind_of(0xD0) == tpdu_kind::cc);
  CHECK(tpdu_kind_of(0x80) == tpdu_kind::dr);
  CHECK(tpdu_kind_of(0xF0) == tpdu_kind::dt);
  CHECK(tpdu_kind_of(0x70) == tpdu_kind::er);
  CHECK_FALSE(tpdu_kind_of(0x00));
  CHECK_FALSE(tpdu_kind_of(0x30));
  CHECK_FALSE(tpdu_kind_of(0x81));
}

TEST_CASE("CR known answer", "[cotp]") {
  byte_buffer out;
  REQUIRE(encode_tpkt(tpdu{mms_cr()}, out));
  CHECK(out == mms_cr_tpkt);

  auto decoded = decode_tpdu(byte_view{mms_cr_tpkt}.subspan(4));
  REQUIRE(decoded);
  const auto* cr = std::get_if<connection_request>(&*decoded);
  REQUIRE(cr);
  CHECK(*cr == mms_cr());
  CHECK(cr->protocol_class() == 0);
}

TEST_CASE("CC known answer", "[cotp]") {
  connection_confirm cc;
  cc.dst_ref = 0x0001;
  cc.src_ref = 0x0002;
  cc.tpdu_size = 0x0A;
  cc.calling_tsap = byte_buffer{0x00, 0x01};
  cc.called_tsap = byte_buffer{0x00, 0x01};
  byte_buffer out;
  REQUIRE(encode(cc, out));
  CHECK(out == mms_cc);

  auto decoded = decode_tpdu(mms_cc);
  REQUIRE(decoded);
  REQUIRE(std::holds_alternative<connection_confirm>(*decoded));
  CHECK(std::get<connection_confirm>(*decoded) == cc);
}

TEST_CASE("DT known answer", "[cotp]") {
  const byte_buffer payload{0x01, 0x00, 0x01, 0x00};
  byte_buffer out;
  REQUIRE(encode_tpkt(tpdu{data_tpdu{true, 0, payload}}, out));
  CHECK(out == byte_buffer{0x03, 0x00, 0x00, 0x0B, 0x02, 0xF0, 0x80, 0x01, 0x00, 0x01, 0x00});

  auto decoded = decode_tpdu(byte_view{out}.subspan(4));
  REQUIRE(decoded);
  const auto& dt = std::get<data_tpdu>(*decoded);
  CHECK(dt.eot);
  CHECK(dt.nr == 0);
  CHECK(byte_buffer(dt.user_data.begin(), dt.user_data.end()) == payload);

  auto middle = decode_tpdu(byte_buffer{0x02, 0xF0, 0x05, 0xAA});
  REQUIRE(middle);
  CHECK_FALSE(std::get<data_tpdu>(*middle).eot);
  CHECK(std::get<data_tpdu>(*middle).nr == 5);
}

TEST_CASE("DR known answer", "[cotp]") {
  disconnect_request dr;
  dr.dst_ref = 0x0001;
  dr.reason = disconnect_reason::address_unknown;
  byte_buffer out;
  REQUIRE(encode(dr, out));
  CHECK(out == byte_buffer{0x06, 0x80, 0x00, 0x01, 0x00, 0x00, 0x03});

  auto decoded = decode_tpdu(out);
  REQUIRE(decoded);
  CHECK(std::get<disconnect_request>(*decoded) == dr);

  // With an additional information parameter, preserved as-is.
  const byte_buffer with_info{0x09, 0x80, 0x00, 0x01, 0x00, 0x02, 0x80, 0xE0, 0x01, 0x42};
  auto info = decode_tpdu(with_info);
  REQUIRE(info);
  const auto& d = std::get<disconnect_request>(*info);
  CHECK(d.reason == disconnect_reason::normal);
  REQUIRE(d.parameters.size() == 1);
  CHECK(d.parameters[0] == tpdu_parameter{parameter_code::additional_information, {0x42}});
  byte_buffer again;
  REQUIRE(encode(d, again));
  CHECK(again == with_info);
}

TEST_CASE("ER known answer", "[cotp]") {
  error_tpdu er;
  er.dst_ref = 0x0001;
  er.cause = reject_cause::invalid_tpdu_type;
  er.invalid_tpdu = byte_buffer{0x02, 0x30};
  byte_buffer out;
  REQUIRE(encode(er, out));
  CHECK(out == byte_buffer{0x08, 0x70, 0x00, 0x01, 0x02, 0xC1, 0x02, 0x02, 0x30});

  auto decoded = decode_tpdu(out);
  REQUIRE(decoded);
  CHECK(std::get<error_tpdu>(*decoded) == er);
}

TEST_CASE("Unknown CR parameters are preserved", "[cotp]") {
  // CR without TPDU size, with version (0xC4) and alternative classes (0xC7).
  const byte_buffer in{0x0F, 0xE0, 0x00, 0x00, 0x12, 0x34, 0x20, 0xC4, 0x01,
                       0x01, 0xC7, 0x01, 0x00, 0xC0, 0x01, 0x07};
  auto decoded = decode_tpdu(in);
  REQUIRE(decoded);
  const auto& cr = std::get<connection_request>(*decoded);
  CHECK(cr.src_ref == 0x1234);
  CHECK(cr.protocol_class() == 2);
  CHECK(cr.tpdu_size == std::uint8_t{7});
  CHECK_FALSE(cr.calling_tsap);
  REQUIRE(cr.other_parameters.size() == 2);
  CHECK(cr.other_parameters[0] == tpdu_parameter{0xC4, {0x01}});
  CHECK(cr.other_parameters[1] == tpdu_parameter{0xC7, {0x00}});

  byte_buffer out;
  REQUIRE(encode(cr, out));
  auto again = decode_tpdu(out);
  REQUIRE(again);
  CHECK(std::get<connection_request>(*again) == cr);
}

TEST_CASE("Malformed TPDUs are rejected", "[cotp]") {
  CHECK(decode_tpdu(byte_buffer{0x02}).error() == errc::truncated_input);
  CHECK(decode_tpdu(byte_buffer{0x00, 0xF0}).error() == errc::malformed_encoding);
  CHECK(decode_tpdu(byte_buffer{0xFF, 0xF0, 0x80}).error() == errc::malformed_encoding);
  // LI beyond the buffer.
  CHECK(decode_tpdu(byte_buffer{0x11, 0xE0, 0x00, 0x00}).error() == errc::length_overflow);
  CHECK(decode_tpdu(byte_buffer{0x03, 0xF0, 0x80}).error() == errc::length_overflow);
  // Unassigned and non-class-0 codes.
  CHECK(decode_tpdu(byte_buffer{0x02, 0x30, 0x80}).error() == errc::malformed_encoding);
  CHECK(decode_tpdu(byte_buffer{0x02, 0x10, 0x80}).error() == errc::unsupported);
  CHECK(decode_tpdu(byte_buffer{0x06, 0xC0, 0x00, 0x01, 0x00, 0x02, 0x00}).error() ==
        errc::unsupported);
  // CR fixed part too short.
  CHECK(decode_tpdu(byte_buffer{0x05, 0xE0, 0x00, 0x00, 0x00, 0x01}).error() ==
        errc::malformed_encoding);
  // Parameter length past LI.
  CHECK(decode_tpdu(byte_buffer{0x09, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00, 0xC1, 0x05, 0x00})
            .error() == errc::length_overflow);
  // Lone parameter code octet.
  CHECK(decode_tpdu(byte_buffer{0x07, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00, 0xC1}).error() ==
        errc::length_overflow);
  // TPDU size out of range and with a bad length.
  CHECK(decode_tpdu(byte_buffer{0x09, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00, 0xC0, 0x01, 0x0E})
            .error() == errc::malformed_encoding);
  CHECK(decode_tpdu(byte_buffer{0x0A, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00, 0xC0, 0x02, 0x0A, 0x00})
            .error() == errc::malformed_encoding);
  // DT with a variable part (not class 0).
  CHECK(decode_tpdu(byte_buffer{0x03, 0xF0, 0x80, 0x00}).error() == errc::malformed_encoding);
  // ER with trailing data.
  CHECK(decode_tpdu(byte_buffer{0x04, 0x70, 0x00, 0x01, 0x00, 0xAA}).error() ==
        errc::malformed_encoding);
}

TEST_CASE("Encoding rejects oversize headers", "[cotp]") {
  connection_request cr;
  cr.calling_tsap = byte_buffer(200, 0x11);
  cr.called_tsap = byte_buffer(200, 0x22);
  byte_buffer out{0xAA};
  CHECK(encode(cr, out).error() == errc::length_overflow);
  CHECK(encode_tpkt(tpdu{cr}, out).error() == errc::length_overflow);
  CHECK(out == byte_buffer{0xAA});

  cr.called_tsap = byte_buffer(256, 0x22);
  cr.calling_tsap.reset();
  CHECK(encode(cr, out).error() == errc::length_overflow);
}
