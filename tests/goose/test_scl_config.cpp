#include <catch2/catch_test_macros.hpp>

#include "openiec61850/goose/scl_config.hpp"
#include "openiec61850/scl/load.hpp"

namespace goose = openiec61850::goose;
namespace sv = openiec61850::sv;
namespace scl = openiec61850::scl;
using namespace std::chrono_literals;
using openiec61850::errc;

namespace {

constexpr const char* scd = R"(<?xml version="1.0" encoding="UTF-8"?>
<SCL xmlns="http://www.iec.ch/61850/2003/SCL" version="2007" revision="B" release="4">
  <Header id="goose-test"/>
  <Communication>
    <SubNetwork name="ProcessBus" type="8-MMS">
      <ConnectedAP iedName="IED1" apName="P1">
        <GSE ldInst="LD0" cbName="gcb1">
          <Address>
            <P type="MAC-Address">01-0C-CD-01-00-10</P>
            <P type="APPID">0010</P>
            <P type="VLAN-ID">00A</P>
            <P type="VLAN-PRIORITY">6</P>
          </Address>
          <MinTime unit="s" multiplier="m">4</MinTime>
          <MaxTime unit="s" multiplier="m">2000</MaxTime>
        </GSE>
        <GSE ldInst="LD0" cbName="gcbNoAddr">
          <Address><P type="APPID">0011</P></Address>
        </GSE>
        <SMV ldInst="MU" cbName="msv1">
          <Address>
            <P type="MAC-Address">01-0C-CD-04-00-01</P>
            <P type="APPID">4001</P>
          </Address>
        </SMV>
      </ConnectedAP>
    </SubNetwork>
  </Communication>
  <IED name="IED1">
    <AccessPoint name="P1">
      <Server>
        <LDevice inst="LD0">
          <LN0 lnClass="LLN0" inst="" lnType="LLN0_T">
            <DataSet name="ds1">
              <FCDA ldInst="LD0" lnClass="GGIO" lnInst="1" doName="Ind1" daName="stVal" fc="ST"/>
              <FCDA ldInst="LD0" lnClass="GGIO" lnInst="1" doName="Ind1" daName="q" fc="ST"/>
            </DataSet>
            <GSEControl name="gcb1" datSet="ds1" appID="IED1_GOOSE" confRev="3"/>
            <GSEControl name="gcbNoId" datSet="ds1" confRev="1"/>
            <GSEControl name="gcbNoAddr" datSet="ds1" confRev="1"/>
          </LN0>
          <LN lnClass="GGIO" inst="1" lnType="GGIO_T"/>
        </LDevice>
        <LDevice inst="MU">
          <LN0 lnClass="LLN0" inst="" lnType="LLN0_T">
            <DataSet name="PhsMeas1">
              <FCDA ldInst="MU" lnClass="GGIO" lnInst="1" doName="Ind1" daName="stVal" fc="ST"/>
            </DataSet>
            <SampledValueControl name="msv1" datSet="PhsMeas1" smvID="IED1MU01" confRev="2"
                                 smpRate="80" nofASDU="1" smpMod="SmpPerPeriod">
              <SmvOpts refreshTime="true" sampleRate="true" dataSet="true"/>
            </SampledValueControl>
          </LN0>
          <LN lnClass="GGIO" inst="1" lnType="GGIO_T"/>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0"><DO name="Beh" type="ENS_T"/></LNodeType>
    <LNodeType id="GGIO_T" lnClass="GGIO">
      <DO name="Beh" type="ENS_T"/>
      <DO name="Ind1" type="SPS_T"/>
    </LNodeType>
    <DOType id="ENS_T" cdc="ENS">
      <DA name="stVal" bType="Enum" type="BehKind" fc="ST" dchg="true"/>
      <DA name="q" bType="Quality" fc="ST" qchg="true"/>
      <DA name="t" bType="Timestamp" fc="ST"/>
    </DOType>
    <DOType id="SPS_T" cdc="SPS">
      <DA name="stVal" bType="BOOLEAN" fc="ST" dchg="true"/>
      <DA name="q" bType="Quality" fc="ST" qchg="true"/>
      <DA name="t" bType="Timestamp" fc="ST"/>
    </DOType>
    <EnumType id="BehKind"><EnumVal ord="1">on</EnumVal></EnumType>
  </DataTypeTemplates>
</SCL>)";

}  // namespace

TEST_CASE("GOOSE configuration from SCL", "[goose]") {
  auto loaded = scl::load_string(scd);
  REQUIRE(loaded.ok());
  const auto& doc = *loaded.doc;

  auto pc = goose::publisher_config_from_scl(doc, "IED1", "LD0", "gcb1");
  REQUIRE(pc);
  CHECK(pc->destination == goose::mac_address{0x01, 0x0C, 0xCD, 0x01, 0x00, 0x10});
  CHECK(pc->app_id == 0x10);
  REQUIRE(pc->vlan);
  CHECK(pc->vlan->id == 10);
  CHECK(pc->vlan->priority == 6);
  CHECK(pc->gocb_ref == "IED1LD0/LLN0$GO$gcb1");
  CHECK(pc->dat_set == "IED1LD0/LLN0$ds1");
  CHECK(pc->go_id == "IED1_GOOSE");
  CHECK(pc->conf_rev == 3);
  CHECK(pc->min_time == 4ms);
  CHECK(pc->max_time == 2000ms);

  auto sc = goose::subscriber_config_from_scl(doc, "IED1", "LD0", "gcb1", "P1");
  REQUIRE(sc);
  CHECK(sc->app_id == 0x10);
  CHECK(sc->gocb_ref == "IED1LD0/LLN0$GO$gcb1");
  CHECK(sc->dat_set == "IED1LD0/LLN0$ds1");
  CHECK(sc->go_id == "IED1_GOOSE");
  CHECK(sc->conf_rev == 3);
  CHECK(sc->num_entries == 2);

  CHECK(goose::publisher_config_from_scl(doc, "IED2", "LD0", "gcb1").error() ==
        errc::invalid_state);
  CHECK(goose::publisher_config_from_scl(doc, "IED1", "LD0", "nope").error() ==
        errc::invalid_state);
  CHECK(goose::publisher_config_from_scl(doc, "IED1", "LD0", "gcb1", "P9").error() ==
        errc::invalid_state);
  // A control block without a GSE address, and a GSE without MAC-Address.
  CHECK(goose::publisher_config_from_scl(doc, "IED1", "LD0", "gcbNoId").error() ==
        errc::invalid_state);
  CHECK(goose::publisher_config_from_scl(doc, "IED1", "LD0", "gcbNoAddr").error() ==
        errc::malformed_encoding);
}

TEST_CASE("SV configuration from SCL", "[sv]") {
  auto loaded = scl::load_string(scd);
  REQUIRE(loaded.ok());
  const auto& doc = *loaded.doc;
  auto pc = sv::publisher_config_from_scl(doc, "IED1", "MU", "msv1");
  REQUIRE(pc);
  CHECK(pc->app_id == 0x4001);
  CHECK(pc->sv_id == "IED1MU01");
  CHECK(pc->dat_set == "IED1MU/LLN0$PhsMeas1");
  CHECK(pc->conf_rev == 2);
  CHECK(pc->smp_rate == 80);
  CHECK_FALSE(pc->smp_mod);
  CHECK(pc->refresh_time);
  CHECK(pc->asdus_per_frame == 1);
  CHECK(pc->smp_cnt_wrap == 4000);

  auto sc = sv::subscriber_config_from_scl(doc, "IED1", "MU", "msv1", {}, 60);
  REQUIRE(sc);
  CHECK(sc->sv_id == "IED1MU01");
  CHECK(sc->conf_rev == 2);
  CHECK(sc->smp_cnt_wrap == 4800);
  CHECK(sc->destination == goose::mac_address{0x01, 0x0C, 0xCD, 0x04, 0x00, 0x01});
}
