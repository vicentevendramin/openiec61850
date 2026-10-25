#include <catch2/catch_approx.hpp>
#include <catch2/catch_test_macros.hpp>

#include <array>
#include <vector>

#include "goose_test_util.hpp"
#include "openiec61850/goose/sv.hpp"

namespace sv = openiec61850::sv;
namespace goose = openiec61850::goose;
namespace mms = openiec61850::mms;
namespace model = openiec61850::model;
using goose_test::hex;
using openiec61850::byte_buffer;
using openiec61850::errc;

namespace {

// 9-2 savPdu with one ASDU, built by hand from the ASN.1 definition; the frame is exactly the
// 60-octet Ethernet minimum.
const byte_buffer kat_frame = hex(
    "01 0C CD 04 00 01 00 11 22 33 44 55 88 BA 40 00 00 2E 00 00 00 00"
    " 60 24 80 01 01 A2 1F"
    " 30 1D 80 04 'MU01' 82 02 01 02 83 04 00 00 00 01 85 01 02"
    " 87 08 00 00 03 E8 00 00 20 01");

}  // namespace

TEST_CASE("SV frame known answer", "[sv]") {
  const auto seq = hex("00 00 03 E8 00 00 20 01");
  sv::asdu a;
  a.sv_id = "MU01";
  a.smp_cnt = 0x0102;
  a.conf_rev = 1;
  a.smp_synch = sv::smp_synch::global;
  a.seq_data = seq;
  goose::frame_header h;
  h.destination = {0x01, 0x0C, 0xCD, 0x04, 0x00, 0x01};
  h.source = goose_test::mac_a;
  h.app_id = 0x4000;
  byte_buffer out;
  REQUIRE(sv::encode(h, std::span<const sv::asdu>(&a, 1), out));
  CHECK(out == kat_frame);

  auto m = sv::decode(kat_frame);
  REQUIRE(m);
  CHECK(m->frame.app_id == 0x4000);
  CHECK(m->pdu.no_asdu == 1);
  CHECK_FALSE(m->pdu.security);
  REQUIRE(m->pdu.asdus.size() == 1);
  const auto d = *m->pdu.asdus.begin();
  CHECK(d.sv_id == "MU01");
  CHECK_FALSE(d.dat_set);
  CHECK(d.smp_cnt == 0x0102);
  CHECK(d.conf_rev == 1);
  CHECK_FALSE(d.refr_tm);
  CHECK(d.smp_synch == 2);
  CHECK_FALSE(d.smp_rate);
  CHECK_FALSE(d.smp_mod);
  std::array<sv::analog_sample, 1> s{};
  auto n = sv::decode_analog_samples(d.seq_data, s);
  REQUIRE(n);
  CHECK(*n == 1);
  CHECK(s[0].value == 1000);
  CHECK(s[0].q.raw == 0x2001);
  CHECK(s[0].q.is_derived());
  CHECK(s[0].q.validity() == model::validity::invalid);
}

TEST_CASE("SV round trip with every optional field and several ASDUs", "[sv]") {
  sv::le::samples ls;
  ls.set_current(0, 1.234);
  ls.set_current(3, -0.0004);
  ls.set_voltage(0, 63508.5, sv::quality32{0x800});
  const auto seq = sv::le::encode(ls);
  std::vector<sv::asdu> asdus(8);
  for (std::size_t i = 0; i < asdus.size(); ++i) {
    auto& a = asdus[i];
    a.sv_id = "IED1MU/LLN0$MS$smv";
    a.dat_set = "IED1MU/LLN0$PhsMeas1";
    a.smp_cnt = static_cast<std::uint16_t>(12790 + i);
    a.conf_rev = 0x01020304;
    a.refr_tm = mms::utc_time{100, 200, 0x18};
    a.smp_synch = sv::smp_synch::local;
    a.smp_rate = 256;
    a.seq_data = seq;
    a.smp_mod = static_cast<std::uint16_t>(sv::sample_mode::samples_per_period);
    a.gm_identity = std::array<std::uint8_t, 8>{1, 2, 3, 4, 5, 6, 7, 8};
  }
  goose::frame_header h;
  h.vlan = goose::vlan_tag{4, false, 10};
  h.reserved1 = goose::reserved1_simulation;
  byte_buffer out;
  REQUIRE(sv::encode(h, asdus, out));
  auto m = sv::decode(out);
  REQUIRE(m);
  CHECK(m->frame.simulation());
  CHECK(m->pdu.no_asdu == 8);
  std::size_t i = 0;
  for (const auto& a : m->pdu.asdus) {
    CHECK(a.sv_id == "IED1MU/LLN0$MS$smv");
    REQUIRE(a.dat_set);
    CHECK(*a.dat_set == "IED1MU/LLN0$PhsMeas1");
    CHECK(a.smp_cnt == 12790 + i);
    CHECK(a.conf_rev == 0x01020304);
    CHECK(a.refr_tm == mms::utc_time{100, 200, 0x18});
    CHECK(a.smp_rate == 256);
    CHECK(a.smp_mod == 0);
    CHECK(a.gm_identity == std::array<std::uint8_t, 8>{1, 2, 3, 4, 5, 6, 7, 8});
    auto back = sv::le::decode(a.seq_data);
    REQUIRE(back);
    CHECK(*back == ls);
    ++i;
  }
  CHECK(i == 8);
}

TEST_CASE("9-2 LE samples and quality", "[sv]") {
  sv::le::samples s;
  s.set_current(sv::le::ia, 1.0);
  s.set_current(sv::le::ib, -2.5);
  s.set_voltage(0, 100.0);
  s.set_voltage(3, 1e12);  // saturates
  CHECK(s.channels[sv::le::ia].value == 1000);
  CHECK(s.channels[sv::le::ib].value == -2500);
  CHECK(s.channels[sv::le::va].value == 10000);
  CHECK(s.channels[sv::le::vn].value == 2147483647);
  CHECK(s.current(0) == Catch::Approx(1.0));
  CHECK(s.voltage(0) == Catch::Approx(100.0));

  const auto bytes = sv::le::encode(s);
  CHECK(bytes.size() == 64);
  CHECK(bytes[0] == 0x00);
  CHECK(bytes[3] == 0xE8);
  CHECK(bytes[8] == 0xFF);  // -2500 = FF FF F6 3C
  CHECK(bytes[11] == 0x3C);
  CHECK_FALSE(sv::le::decode(byte_buffer(63, 0)));

  auto q = model::quality{};
  q.set_validity(model::validity::questionable).set(model::quality_flag::test);
  const auto q32 = sv::quality32::from_quality(q, true);
  CHECK(q32.raw == (0x3U | 0x800U | 0x2000U));
  CHECK(q32.to_quality() == q);
  CHECK(sv::quality32::from_quality(
            model::quality{}.set_validity(model::validity::invalid)).raw == 1);
  CHECK(sv::quality32{0x0402}.to_quality().validity() == model::validity::reserved);
  CHECK(sv::quality32{0x0402}.to_quality().source() == model::source::substituted);

  std::array<sv::analog_sample, 1> small{};
  CHECK(sv::decode_analog_samples(byte_buffer(16, 0), small).error() == errc::buffer_too_small);
  CHECK(sv::decode_analog_samples(byte_buffer(7, 0), small).error() == errc::malformed_encoding);

  byte_buffer fixed;
  sv::store_float32(fixed, 1.5F);
  sv::store_int32(fixed, -2);
  CHECK(fixed == hex("3F C0 00 00 FF FF FF FE"));
  CHECK(sv::load_float32(fixed, 0) == 1.5F);
  CHECK(sv::load_int32(fixed, 4) == -2);
  CHECK(sv::le::samples_per_second(80, 50) == 4000);
}

TEST_CASE("Malformed SV PDUs", "[sv]") {
  const openiec61850::byte_view pdu{kat_frame.data() + 22, kat_frame.size() - 22};
  REQUIRE(sv::decode_pdu(pdu));
  for (std::size_t n = 0; n < pdu.size(); ++n) CHECK_FALSE(sv::decode_pdu(pdu.first(n)));
  // noASDU 2 with one ASDU; noASDU 0.
  auto wrong = byte_buffer(pdu.begin(), pdu.end());
  wrong[4] = 2;
  CHECK(sv::decode_pdu(wrong).error() == errc::malformed_encoding);
  wrong[4] = 0;
  CHECK(sv::decode_pdu(wrong).error() == errc::malformed_encoding);
  // smpCnt of 3 octets.
  CHECK(sv::decode_pdu(hex("60 1A 80 01 01 A2 15 30 13 80 01 'M' 82 03 00 01 02 83 04 00 00 00 01"
                           " 85 01 00 87 00"))
            .error() == errc::malformed_encoding);
  // Missing smpSynch.
  CHECK_FALSE(sv::decode_pdu(hex("60 16 80 01 01 A2 11 30 0F 80 01 'M' 82 02 00 01 83 04 00 00 00 01"
                                 " 87 00")));
  // An ASDU that is not a SEQUENCE.
  CHECK_FALSE(sv::decode_pdu(hex("60 09 80 01 01 A2 04 31 02 80 00")));
  // Empty ASDU list in the encoder.
  byte_buffer out;
  CHECK(sv::encode_pdu({}, out).error() == errc::invalid_state);
}
