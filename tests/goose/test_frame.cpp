#include <catch2/catch_test_macros.hpp>

#include "goose_test_util.hpp"
#include "openiec61850/goose/frame.hpp"

namespace goose = openiec61850::goose;
using goose_test::hex;
using openiec61850::byte_buffer;
using openiec61850::errc;

TEST_CASE("802.1Q TCI packs priority, DEI and VLAN ID", "[goose]") {
  CHECK(goose::vlan_tag{}.tci() == 0x8000);
  CHECK(goose::vlan_tag{7, true, 0xABC}.tci() == 0xFABC);
  CHECK(goose::vlan_tag::from_tci(0x6005) == goose::vlan_tag{3, false, 5});
}

TEST_CASE("Frame header encoding pads to the Ethernet minimum", "[goose]") {
  goose::frame_header h;
  h.destination = goose::goose_multicast_base;
  h.destination[5] = 1;
  h.source = goose_test::mac_a;
  h.vlan = goose::vlan_tag{4, false, 5};
  h.ether_type = goose::ethertype_goose;
  h.app_id = 0x1234;
  h.reserved1 = goose::reserved1_simulation;
  byte_buffer out;
  const auto start = goose::begin_frame(out, h);
  out.push_back(0xAA);  // a one-octet "APDU"
  REQUIRE(goose::finish_frame(out, start));
  CHECK(out.size() == 60);
  const auto expected = hex("01 0C CD 01 00 01 00 11 22 33 44 55 81 00 80 05 88 B8 12 34 00 09 80 00 00 00 AA");
  CHECK(byte_buffer(out.begin(), out.begin() + 27) == expected);
  for (std::size_t i = 27; i < out.size(); ++i) CHECK(out[i] == 0);

  auto v = goose::decode_frame(out);
  REQUIRE(v);
  CHECK(v->destination == h.destination);
  CHECK(v->source == goose_test::mac_a);
  REQUIRE(v->vlan);
  CHECK(*v->vlan == goose::vlan_tag{4, false, 5});
  CHECK(v->ether_type == goose::ethertype_goose);
  CHECK(v->app_id == 0x1234);
  CHECK(v->length == 9);
  CHECK(v->simulation());
  CHECK(v->apdu.size() == 1);
  CHECK(v->apdu[0] == 0xAA);
  CHECK(goose::peek_ether_type(out) == goose::ethertype_goose);
}

TEST_CASE("Frame without VLAN tag", "[goose]") {
  const auto f = hex("01 0C CD 04 00 01 00 11 22 33 44 55 88 BA 40 00 00 0A 00 00 00 00 60 00");
  auto v = goose::decode_frame(f);
  REQUIRE(v);
  CHECK_FALSE(v->vlan);
  CHECK(v->ether_type == goose::ethertype_sv);
  CHECK(v->app_id == 0x4000);
  CHECK_FALSE(v->simulation());
  CHECK(v->apdu.size() == 2);
}

TEST_CASE("Malformed frame headers", "[goose]") {
  CHECK(goose::decode_frame(hex("01 0C CD")).error() == errc::truncated_input);
  // IPv4 EtherType.
  CHECK(goose::decode_frame(hex("01 0C CD 04 00 01 00 11 22 33 44 55 08 00 40 00 00 08 00 00 00 00"))
            .error() == errc::unsupported);
  // Stacked VLAN tags.
  CHECK(goose::decode_frame(
            hex("01 0C CD 04 00 01 00 11 22 33 44 55 81 00 00 01 81 00 00 02 88 BA 00 00"))
            .error() == errc::unsupported);
  // Truncated after the VLAN tag / inside the APPID header.
  CHECK(goose::decode_frame(hex("01 0C CD 04 00 01 00 11 22 33 44 55 81 00 00")).error() ==
        errc::truncated_input);
  CHECK(goose::decode_frame(hex("01 0C CD 04 00 01 00 11 22 33 44 55 88 B8 00 01 00")).error() ==
        errc::truncated_input);
  // Length below 8, and beyond the frame.
  CHECK(goose::decode_frame(hex("01 0C CD 04 00 01 00 11 22 33 44 55 88 B8 00 01 00 07 00 00 00 00"))
            .error() == errc::malformed_encoding);
  CHECK(goose::decode_frame(hex("01 0C CD 04 00 01 00 11 22 33 44 55 88 B8 00 01 00 0A 00 00 00 00 61"))
            .error() == errc::length_overflow);
  byte_buffer bad;
  CHECK(goose::finish_frame(bad, 0).error() == errc::invalid_state);
}

TEST_CASE("MAC address text form", "[goose]") {
  auto m = goose::parse_mac("01-0C-CD-01-00-1f");
  REQUIRE(m);
  CHECK(*m == goose::mac_address{0x01, 0x0C, 0xCD, 0x01, 0x00, 0x1F});
  CHECK(goose::to_string(*m) == "01-0C-CD-01-00-1F");
  CHECK(goose::parse_mac("01:0C:CD:01:00:1F"));
  CHECK(goose::parse_mac("010CCD01001F"));
  CHECK_FALSE(goose::parse_mac("01-0C-CD-01-00"));
  CHECK_FALSE(goose::parse_mac("01-0C-CD-01-00-1F-"));
  CHECK_FALSE(goose::parse_mac("01-0C-CD-01-00-1G"));
  CHECK(goose::is_multicast(*m));
  CHECK_FALSE(goose::is_multicast(goose_test::mac_a));
}
