#include <catch2/catch_test_macros.hpp>

#include "scl_test_util.hpp"

namespace scl = openiec61850::scl;
namespace ber = openiec61850::ber;
using openiec61850::byte_buffer;
using openiec61850::errc;
using scl_test::load_data;

namespace {

scl::address make(std::initializer_list<std::pair<const char*, const char*>> ps) {
  scl::address a;
  for (const auto& [t, v] : ps) a.p.push_back({t, v});
  return a;
}

}  // namespace

TEST_CASE("ConnectedAP address gives client connection parameters", "[scl]") {
  const auto doc = load_data("ed2_bay.cid");
  auto a = scl::connected_ap_address(doc, "BAY1", "P1");
  REQUIRE(a);
  CHECK(a->ip == "10.0.0.21");
  CHECK(a->ip_subnet == "255.255.0.0");
  CHECK(a->ip_gateway == "10.0.0.1");
  CHECK(a->t_selector == byte_buffer{0x00, 0x01});
  CHECK(a->s_selector == byte_buffer{0x00, 0x01});
  CHECK(a->p_selector == byte_buffer{0x00, 0x00, 0x00, 0x01});
  REQUIRE(a->ap_title);
  CHECK(*a->ap_title == ber::oid{1, 3, 9999, 23});
  CHECK(a->ae_qualifier == 23);
  CHECK_FALSE(a->ap_invoke);

  CHECK(scl::connected_ap_address(doc, "BAY1", "P2").error() == errc::invalid_state);

  const auto scd = load_data("station.scd");
  auto b = scl::connected_ap_address(scd, "IED1", "S1");
  REQUIRE(b);
  CHECK(*b->ap_title == ber::oid{1, 3, 9999, 1});
  auto c = scl::connected_ap_address(scd, "IED2", "S2");
  REQUIRE(c);
  CHECK(c->ip == "192.168.100.2");
  CHECK(c->t_selector.empty());
  CHECK_FALSE(c->ap_title);
}

TEST_CASE("Invalid OSI address parameters", "[scl]") {
  CHECK(scl::parse_ap_address(make({{"OSI-TSEL", "001"}})).error() == errc::malformed_encoding);
  CHECK(scl::parse_ap_address(make({{"OSI-PSEL", "0g"}})).error() == errc::malformed_encoding);
  CHECK(scl::parse_ap_address(make({{"OSI-AP-Title", "1,3,,4"}})).error() ==
        errc::malformed_encoding);
  CHECK(scl::parse_ap_address(make({{"OSI-AP-Title", "7,3"}})).error() ==
        errc::malformed_encoding);
  CHECK(scl::parse_ap_address(make({{"OSI-AE-Qualifier", "x"}})).error() ==
        errc::malformed_encoding);
  auto ok = scl::parse_ap_address(make({{"OSI-AP-Title", "1.3.9999.33"}, {"OSI-AP-Invoke", "2"}}));
  REQUIRE(ok);
  CHECK(*ok->ap_title == ber::oid{1, 3, 9999, 33});
  CHECK(ok->ap_invoke == 2);
  CHECK(scl::parse_hex_selector("00 01")->size() == 2);
}

TEST_CASE("GSE and SMV layer 2 addresses", "[scl]") {
  const auto icd = load_data("ed1_relay.icd");
  auto g = scl::parse_l2_address(icd.comm.find("TEMPLATE", "S1")->gse.at(0).addr);
  REQUIRE(g);
  CHECK(g->mac == std::array<std::uint8_t, 6>{0x01, 0x0C, 0xCD, 0x01, 0x00, 0x01});
  CHECK(g->app_id == 1);
  CHECK(g->vlan_id == 0);
  CHECK(g->vlan_priority == 4);

  const auto cid = load_data("ed2_bay.cid");
  auto s = scl::parse_l2_address(cid.comm.find("BAY1", "P1")->smv.at(0).addr);
  REQUIRE(s);
  CHECK(s->app_id == 0x4000);
  CHECK(s->vlan_id == 5);

  CHECK_FALSE(scl::parse_l2_address(make({{"APPID", "1"}})));
  CHECK_FALSE(scl::parse_l2_address(make({{"MAC-Address", "01-0C-CD-01-00"}, {"APPID", "1"}})));
  CHECK_FALSE(scl::parse_l2_address(make({{"MAC-Address", "01-0C-CD-01-00-001"}, {"APPID", "1"}})));
  CHECK_FALSE(scl::parse_l2_address(make({{"MAC-Address", "01-0C-CD-01-00-01"}, {"APPID", "10000"}})));
  CHECK_FALSE(scl::parse_l2_address(
      make({{"MAC-Address", "01-0C-CD-01-00-01"}, {"APPID", "1"}, {"VLAN-PRIORITY", "8"}})));
}
