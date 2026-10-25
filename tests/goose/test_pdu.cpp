#include <catch2/catch_test_macros.hpp>

#include <vector>

#include "goose_test_util.hpp"
#include "openiec61850/goose/pdu.hpp"

namespace goose = openiec61850::goose;
namespace mms = openiec61850::mms;
using goose_test::hex;
using openiec61850::byte_buffer;
using openiec61850::errc;

namespace {

// 8-1 Annex A IECGoosePdu with every field, built by hand from the ASN.1 definition.
const byte_buffer kat_pdu = hex(
    "61 47"
    " 80 0C 'LD/LLN0$GO$g'"
    " 81 02 07 D0"
    " 82 0A 'LD/LLN0$DS'"
    " 83 02 'G1'"
    " 84 08 5F 5E 10 00 80 00 00 0A"
    " 85 01 01"
    " 86 01 00"
    " 87 01 00"
    " 88 01 01"
    " 89 01 00"
    " 8A 01 02"
    " AB 07 83 01 FF 85 02 03 E8");

const byte_buffer kat_frame_header = hex(
    "01 0C CD 01 00 01 00 11 22 33 44 55 81 00 80 00 88 B8 00 01 00 51 00 00 00 00");

goose::pdu_fields kat_fields() {
  goose::pdu_fields f;
  f.gocb_ref = "LD/LLN0$GO$g";
  f.time_allowed_to_live = 2000;
  f.dat_set = "LD/LLN0$DS";
  f.go_id = "G1";
  f.t = {0x5F5E1000, 0x800000, 0x0A};
  f.st_num = 1;
  f.sq_num = 0;
  f.conf_rev = 1;
  return f;
}

const std::vector<mms::data> kat_values{mms::data::boolean(true), mms::data::integer(1000)};

goose::frame_header kat_header() {
  goose::frame_header h;
  h.destination = {0x01, 0x0C, 0xCD, 0x01, 0x00, 0x01};
  h.source = goose_test::mac_a;
  h.vlan = goose::vlan_tag{};
  h.app_id = 1;
  return h;
}

}  // namespace

TEST_CASE("GOOSE PDU known answer", "[goose]") {
  byte_buffer out;
  REQUIRE(goose::encode_pdu(kat_fields(), kat_values, out));
  CHECK(out == kat_pdu);

  byte_buffer frame;
  REQUIRE(goose::encode(kat_header(), kat_fields(), kat_values, frame));
  byte_buffer expected = kat_frame_header;
  expected.insert(expected.end(), kat_pdu.begin(), kat_pdu.end());
  CHECK(frame == expected);

  auto m = goose::decode(frame);
  REQUIRE(m);
  const auto& p = m->pdu;
  CHECK(p.gocb_ref == "LD/LLN0$GO$g");
  CHECK(p.time_allowed_to_live == 2000);
  CHECK(p.dat_set == "LD/LLN0$DS");
  REQUIRE(p.go_id);
  CHECK(*p.go_id == "G1");
  CHECK(p.t == mms::utc_time{0x5F5E1000, 0x800000, 0x0A});
  CHECK(p.st_num == 1);
  CHECK(p.sq_num == 0);
  CHECK_FALSE(p.simulation);
  CHECK(p.conf_rev == 1);
  CHECK_FALSE(p.nds_com);
  CHECK(p.num_dat_set_entries == 2);
  CHECK(p.all_data.size() == 2);
  auto it = p.all_data.begin();
  CHECK(*it->as_boolean());
  ++it;
  CHECK(*it->as_int64() == 1000);
  CHECK_FALSE(p.security);
}

TEST_CASE("GOOSE PDU without the DEFAULT and OPTIONAL fields", "[goose]") {
  const auto pdu = hex(
      "61 2A 80 01 'g' 81 01 0A 82 01 'd' 84 08 00 00 00 01 00 00 00 00 85 05 00 FF FF FF FF"
      " 86 01 05 88 01 03 8A 01 00 AB 00 AC 03 04 01 00");
  auto p = goose::decode_pdu(pdu);
  REQUIRE(p);
  CHECK_FALSE(p->go_id);
  CHECK(p->st_num == 0xFFFFFFFF);
  CHECK(p->sq_num == 5);
  CHECK(p->conf_rev == 3);
  CHECK(p->all_data.empty());
  REQUIRE(p->security);
  CHECK(p->security->size() == 3);
}

TEST_CASE("GOOSE round trip with simulation and ndsCom", "[goose]") {
  auto f = kat_fields();
  f.go_id = "";
  f.simulation = true;
  f.nds_com = true;
  f.st_num = 0xFFFFFFFF;
  f.sq_num = 70000;
  f.num_dat_set_entries = 5;  // deliberately inconsistent: carried as given
  const std::vector<mms::data> values{
      mms::data::structure({mms::data::boolean(false),
                            mms::data::bit_string(hex("00 00"), 13),
                            mms::data::utc_time({1, 2, 3})}),
      mms::data::floating_point(1.5F), mms::data::visible_string("abc")};
  byte_buffer out;
  REQUIRE(goose::encode_pdu(f, values, out));
  auto p = goose::decode_pdu(out);
  REQUIRE(p);
  CHECK_FALSE(p->go_id);
  CHECK(p->simulation);
  CHECK(p->nds_com);
  CHECK(p->st_num == 0xFFFFFFFF);
  CHECK(p->sq_num == 70000);
  CHECK(p->num_dat_set_entries == 5);
  std::vector<mms::data> back;
  for (const auto& v : p->all_data) back.push_back(*mms::data::from_view(v));
  CHECK(back == values);

  // Pre-encoded allData produces the same octets.
  byte_buffer all;
  openiec61850::ber::writer w{all};
  for (const auto& v : values) REQUIRE(v.encode(w));
  byte_buffer raw;
  REQUIRE(goose::encode_pdu_raw(f, all, 3, raw));
  CHECK(raw == out);
}

TEST_CASE("Malformed GOOSE PDUs", "[goose]") {
  // Wrong application tag (savPdu).
  CHECK_FALSE(goose::decode_pdu(hex("60 00")));
  // Trailing octets after the PDU.
  auto trailing = kat_pdu;
  trailing.push_back(0);
  CHECK(goose::decode_pdu(trailing).error() == errc::malformed_encoding);
  // Missing confRev.
  CHECK_FALSE(goose::decode_pdu(hex(
      "61 1E 80 01 'g' 81 01 0A 82 01 'd' 84 08 00 00 00 01 00 00 00 00 85 01 01 86 01 05"
      " 8A 01 00 AB 00")));
  // stNum above 2^32-1.
  CHECK(goose::decode_pdu(hex("61 25 80 01 'g' 81 01 0A 82 01 'd' 84 08 00 00 00 01 00 00 00 00"
                              " 85 05 01 00 00 00 00 86 01 05 88 01 03 8A 01 00 AB 00"))
            .error() == errc::value_out_of_range);
  // Negative TAL.
  CHECK_FALSE(goose::decode_pdu(hex("61 21 80 01 'g' 81 01 FF 82 01 'd' 84 08 00 00 00 01 00 00 00 00"
                                    " 85 01 01 86 01 05 88 01 03 8A 01 00 AB 00")));
  // t with 7 octets.
  CHECK(goose::decode_pdu(hex("61 20 80 01 'g' 81 01 0A 82 01 'd' 84 07 00 00 00 01 00 00 00"
                              " 85 01 01 86 01 05 88 01 03 8A 01 00 AB 00"))
            .error() == errc::malformed_encoding);
  // Invalid Data in allData (boolean of length 2).
  CHECK_FALSE(goose::decode_pdu(hex("61 25 80 01 'g' 81 01 0A 82 01 'd' 84 08 00 00 00 01 00 00 00 00"
                                    " 85 01 01 86 01 05 88 01 03 8A 01 01 AB 04 83 02 00 00")));
  // Fields out of order (datSet before TAL).
  CHECK_FALSE(goose::decode_pdu(hex("61 21 80 01 'g' 82 01 'd' 81 01 0A 84 08 00 00 00 01 00 00 00 00"
                                    " 85 01 01 86 01 05 88 01 03 8A 01 00 AB 00")));
  // Every truncation of a valid PDU fails cleanly.
  for (std::size_t n = 0; n < kat_pdu.size(); ++n) {
    CHECK_FALSE(goose::decode_pdu({kat_pdu.data(), n}));
  }
  // A GOOSE decode of an SV frame.
  CHECK(goose::decode(hex("01 0C CD 04 00 01 00 11 22 33 44 55 88 BA 40 00 00 0A 00 00 00 00 60 00"))
            .error() == errc::unsupported);
}

TEST_CASE("GOOSE encoder rejects invalid values", "[goose]") {
  const std::vector<mms::data> values{mms::data{}};
  byte_buffer out;
  CHECK(goose::encode(kat_header(), kat_fields(), values, out).error() == errc::invalid_state);
  CHECK(out.empty());
}
