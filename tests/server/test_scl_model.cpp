#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdio>
#include <set>
#include <string>
#include <vector>

#include "openiec61850/client/control.hpp"
#include "openiec61850/scl/scl.hpp"
#include "openiec61850/server/scl_model.hpp"
#include "server_test_util.hpp"

using namespace server_test;
using asio::awaitable;
using model::fc;
namespace scl = openiec61850::scl;

namespace {

std::string data_path(std::string_view file) {
  return std::string{OPENIEC61850_SCL_TEST_DATA} + "/" + std::string{file};
}

scl::document load_doc(std::string_view file) {
  auto r = scl::load_file(data_path(file));
  REQUIRE(r.ok());
  return std::move(*r.doc);
}

std::vector<std::string> sorted(std::vector<std::string> v) {
  std::sort(v.begin(), v.end());
  return v;
}

bool has_fc(const scl::data_node& n, model::functional_constraint f) { return n.has_fc(f); }

// What the test compares against: the SCL file instantiated independently of the loader.
struct expectation {
  std::string file;
  std::string ied;
  std::string ap;
};

expectation& current() {
  static expectation e;
  return e;
}

std::vector<std::string> rcb_names(const scl::instantiated_ln& ln, bool buffered) {
  std::vector<std::string> out;
  for (const auto& rc : ln.report_controls) {
    if (rc.buffered != buffered) continue;
    if (!rc.indexed) {
      out.push_back(rc.name);
      continue;
    }
    for (std::uint32_t i = 1; i <= std::max<std::uint32_t>(rc.rpt_enabled_max, 1); ++i) {
      char suffix[4];
      std::snprintf(suffix, sizeof suffix, "%02u", static_cast<unsigned>(i));
      out.push_back(rc.name + suffix);
    }
  }
  return sorted(std::move(out));
}

// Starts a server on the SCL model of current() and compares what our client discovers with the
// instantiated SCL: LDs, LNs, DOs, every FC of every DO readable, data sets and their members,
// RCB instances and their attributes.
awaitable<void> compare_with_scl() {
  const auto& e = current();
  const auto doc = load_doc(e.file);
  scl::diagnostics diags;
  auto m = srv::load_model(doc, e.ied, e.ap, {}, &diags);
  for (const auto& d : diags) UNSCOPED_INFO(scl::to_string(d));
  REQUIRE(m);
  CHECK(diags.error_count() == 0);
  auto inst = scl::instantiate(doc, e.ied, e.ap);
  REQUIRE(inst);

  srv::server_options so;
  so.association.transport.handshake_timeout = 2s;
  auto s = srv::server::start(co_await asio::this_coro::executor, std::move(*m), loopback, so);
  REQUIRE(s);
  auto c = co_await connect(options_for(*s));

  std::vector<std::string> lds;
  for (const auto& ld : inst->lds) lds.push_back(ld.name);
  auto dir = co_await c.get_server_directory();
  REQUIRE(dir);
  CHECK(sorted(*dir) == sorted(lds));

  std::size_t reads = 0;
  for (const auto& ld : inst->lds) {
    std::vector<std::string> lns;
    for (const auto& ln : ld.lns) lns.push_back(ln.name);
    auto got_lns = co_await c.get_logical_device_directory(ld.name);
    REQUIRE(got_lns);
    CHECK(sorted(*got_lns) == sorted(lns));
    for (const auto& ln : ld.lns) {
      INFO(ld.name + "/" + ln.name);
      const auto ln_ref = oref(ld.name + "/" + ln.name);
      auto lnd = co_await c.get_logical_node_directory(ln_ref);
      REQUIRE(lnd);
      std::vector<std::string> dos;
      for (const auto& d : ln.data_objects) dos.push_back(d.name);
      CHECK(sorted(lnd->data_objects) == sorted(dos));
      std::vector<std::string> dss;
      for (const auto& ds : ln.data_sets) dss.push_back(ds.name);
      CHECK(sorted(lnd->data_sets) == sorted(dss));
      CHECK(sorted(lnd->brcbs) == rcb_names(ln, true));
      CHECK(sorted(lnd->urcbs) == rcb_names(ln, false));

      // Every DO is readable under each FC it has.
      for (const auto& d : ln.data_objects) {
        for (std::size_t i = 0; i < model::functional_constraint_count; ++i) {
          const auto f = static_cast<model::functional_constraint>(i);
          if (f == fc::XX || !has_fc(d, f)) continue;
          auto v = co_await c.read(oref(ld.name + "/" + ln.name + "." + d.name).with_fc(f));
          INFO(d.name + " " + std::string(model::to_string(f)));
          CHECK(v);
          ++reads;
        }
      }

      for (const auto& ds : ln.data_sets) {
        auto got = co_await c.get_data_set_directory(oref(ld.name + "/" + ln.name + "." + ds.name));
        REQUIRE(got);
        CHECK_FALSE(got->deletable);
        REQUIRE(got->members.size() == ds.members.size());
        for (std::size_t i = 0; i < ds.members.size(); ++i) {
          CHECK(got->members[i].text() == ds.members[i].text());
        }
        auto values = co_await c.get_data_set_values(oref(ld.name + "/" + ln.name + "." + ds.name));
        REQUIRE(values);
        CHECK(values->size() == ds.members.size());
      }

      for (const auto& rc : ln.report_controls) {
        const auto names = rcb_names(ln, rc.buffered);
        for (const auto& name : names) {
          if (!name.starts_with(rc.name)) continue;
          INFO(name);
          auto v = co_await c.get_rcb_values(
              oref(ld.name + "/" + ln.name + "." + name).with_fc(rc.buffered ? fc::BR : fc::RP));
          REQUIRE(v);
          CHECK(v->rpt_id == rc.rpt_id);
          CHECK(v->conf_rev == rc.conf_rev);
          CHECK(v->buf_tm == rc.buf_time);
          CHECK(v->intg_pd == rc.intg_pd);
          REQUIRE(v->trg_ops);
          CHECK(v->trg_ops->raw() == rc.trg_ops.raw());
          REQUIRE(v->opt_flds);
          CHECK(v->opt_flds->raw() == rc.opt_fields.raw());
          CHECK(v->dat_set == (rc.dat_set.empty() ? std::string{} : ld.name + "/" + ln.name + "$" + rc.dat_set));
          CHECK(v->rpt_ena == false);
        }
      }
    }
  }
  CHECK(reads > 0);
  s->stop();
}

awaitable<mms::data> read_ok(client::client& c, std::string_view ref) {
  auto v = co_await c.read(oref(ref));
  INFO(std::string(ref));
  REQUIRE(v);
  co_return std::move(*v);
}

}  // namespace

TEST_CASE("SCL model: Ed.1 ICD discovered by our client matches the SCL", "[server][scl]") {
  current() = {"ed1_relay.icd", "TEMPLATE", ""};
  run(&compare_with_scl);
}

TEST_CASE("SCL model: Ed.2 CID discovered by our client matches the SCL", "[server][scl]") {
  current() = {"ed2_bay.cid", "BAY1", "P1"};
  run(&compare_with_scl);
}

TEST_CASE("SCL model: SCD IEDs, including a ServerAt access point", "[server][scl]") {
  current() = {"station.scd", "IED1", ""};
  run(&compare_with_scl);
  current() = {"station.scd", "IED2", "S2"};
  run(&compare_with_scl);
}

TEST_CASE("SCL model: initial values", "[server][scl]") {
  run([]() -> awaitable<void> {
    scl::diagnostics diags;
    auto m = srv::load_model_file(data_path("ed1_relay.icd"), "TEMPLATE", {}, {}, &diags);
    REQUIRE(m);
    CHECK(m->edition() == model::edition::ed1);
    auto s = srv::server::start(co_await asio::this_coro::executor, std::move(*m), loopback);
    REQUIRE(s);
    auto c = co_await connect(options_for(*s));
    CHECK(co_await read_ok(c, "TEMPLATECTRL/GGIO1.Ind1.stVal[ST]") == mms::data::boolean(true));
    CHECK(co_await read_ok(c, "TEMPLATECTRL/GGIO1.Ind2.stVal[ST]") == mms::data::boolean(false));
    // Enum Val text -> ord; DAI overriding the DOType Val.
    CHECK(co_await read_ok(c, "TEMPLATECTRL/LLN0.Mod.ctlModel[CF]") == mms::data::integer(0));
    CHECK(co_await read_ok(c, "TEMPLATECTRL/XCBR1.BlkOpn.ctlModel[CF]") == mms::data::integer(0));
    CHECK(co_await read_ok(c, "TEMPLATECTRL/GGIO1.Mod.ctlModel[CF]") == mms::data::integer(1));
    CHECK(co_await read_ok(c, "TEMPLATECTRL/Q0CSWI1.Pos.ctlModel[CF]") == mms::data::integer(1));
    CHECK(co_await read_ok(c, "TEMPLATECTRL/Q0CSWI1.Pos.sboTimeout[CF]") ==
          mms::data::unsigned_integer(30000));
    CHECK(co_await read_ok(c, "TEMPLATECTRL/GGIO1.Health.stVal[ST]") == mms::data::integer(1));
    CHECK(co_await read_ok(c, "TEMPLATECTRL/LLN0.NamPlt.vendor[DC]") ==
          mms::data::visible_string("openiec61850"));
    CHECK(co_await read_ok(c, "TEMPLATECTRL/LLN0.NamPlt.ldNs[EX]") ==
          mms::data::visible_string("IEC 61850-7-4:2003"));
    CHECK(co_await read_ok(c, "TEMPLATECTRL/XCBR1.OpCnt.stVal[ST]") == mms::data::integer(0));
    CHECK(co_await read_ok(c, "TEMPLATEMEAS/MMXU1.TotW.units.SIUnit[CF]") == mms::data::integer(38));
    CHECK(co_await read_ok(c, "TEMPLATEMEAS/MMXU1.Hz.units.SIUnit[CF]") == mms::data::integer(0));
    CHECK(co_await read_ok(c, "TEMPLATEMEAS/MMXU1.TotW.db[CF]") == mms::data::unsigned_integer(500));
    const auto hist = co_await read_ok(c, "TEMPLATECTRL/GGIO1.Hist.hstVal[ST]");
    CHECK(hist == mms::data::array(std::vector<mms::data>(8, mms::data::unsigned_integer(0))));
    CHECK(co_await read_ok(c, "TEMPLATECTRL/GGIO1.Hist.numPts[CF]") == mms::data::unsigned_integer(8));
    // The empty <Val> of an enumeration is reported and the default kept.
    CHECK(co_await read_ok(c, "TEMPLATEMEAS/MMXU1.TotW.units.multiplier[CF]") == mms::data::integer(0));

    // Trigger options and a cross-LD data set member drive reports.
    auto rcb = oref("TEMPLATECTRL/LLN0.urcbPos02[RP]");
    client::report_settings rs;
    auto en = co_await c.enable_reporting(rcb, rs);
    REQUIRE(en);
    auto upd = s->update(oref("TEMPLATECTRL/XCBR1.Pos.stVal[ST]"), model::to_mms(model::dbpos::on));
    CHECK(upd);
    auto rpt = co_await next_report(c);
    CHECK(rpt.rpt_id == "TEMPLATECTRL/LLN0$RP$urcbPos");
    s->stop();
  });

  run([]() -> awaitable<void> {
    auto m = srv::load_model_file(data_path("ed2_bay.cid"), "BAY1");
    REQUIRE(m);
    srv::server_options so;
    so.on_control = [](const srv::control_request&) { return srv::control_result::ok(); };
    auto s = srv::server::start(co_await asio::this_coro::executor, std::move(*m), loopback, so);
    REQUIRE(s);
    auto c = co_await connect(options_for(*s));
    CHECK(co_await read_ok(c, "Bay1Prot/LLN0.Mod.stVal[ST]") == mms::data::integer(1));
    CHECK(co_await read_ok(c, "Bay1Prot/LLN0.Mod.ctlModel[CF]") == mms::data::integer(0));
    CHECK(co_await read_ok(c, "Bay1Prot/QA1CSWI1.Pos.ctlModel[CF]") == mms::data::integer(4));
    CHECK(co_await read_ok(c, "Bay1Prot/XCBR1.Pos.ctlModel[CF]") == mms::data::integer(0));
    CHECK(co_await read_ok(c, "Bay1Prot/MMXU1.Hz.db[CF]") == mms::data::unsigned_integer(200));
    // Array of structures with one element initialised (SDI ix).
    const auto an = co_await read_ok(c, "Bay1Prot/GGIO1.AnIn.mag[MX]");
    REQUIRE(an.elements().size() == 4);
    CHECK(an.elements()[0] == mms::data::structure({mms::data::floating_point(0.0F)}));
    CHECK(an.elements()[1] == mms::data::structure({mms::data::floating_point(1.5F)}));
    // Setting group 1 (actSG) of a SG attribute.
    CHECK(co_await read_ok(c, "Bay1Prot/PTOC1.StrVal.setMag.f[SG]") == mms::data::floating_point(100.0F));
    // RCB instances: indexed (max 2) and not indexed.
    auto lnd = co_await c.get_logical_node_directory(oref("Bay1Prot/LLN0"));
    REQUIRE(lnd);
    CHECK(lnd->brcbs == std::vector<std::string>{"brcbMeas01", "brcbMeas02"});
    CHECK(lnd->urcbs == std::vector<std::string>{"urcbStatus"});
    // The data set member with an array index.
    auto ds = co_await c.get_data_set_values(oref("Bay1Prot/LLN0.Meas"));
    REQUIRE(ds);
    REQUIRE(ds->size() == 3);
    REQUIRE((*ds)[2]);
    CHECK(*(*ds)[2] == mms::data::structure({mms::data::floating_point(0.0F)}));
    // The SCL ctlModel drives the control model: sbo-with-enhanced-security.
    auto ctl = co_await c.get_control(oref("Bay1Prot/QA1CSWI1.Pos"));
    REQUIRE(ctl);
    CHECK(ctl->ctl_model() == model::ctl_model::sbo_with_enhanced_security);
    auto sel = co_await ctl->select_with_value(mms::data::boolean(true));
    CHECK(sel);
    auto op = co_await ctl->operate(mms::data::boolean(true));
    CHECK(op);
    auto status_only = co_await c.get_control(oref("Bay1Prot/XCBR1.Pos"));
    REQUIRE(status_only);
    auto refused = co_await status_only->operate(mms::data::boolean(true));
    CHECK_FALSE(refused);
    s->stop();
  });
}

TEST_CASE("SCL model: setting group selection", "[server][scl]") {
  srv::scl_load_options o;
  o.setting_group = 2;
  auto m = srv::load_model_file(data_path("ed2_bay.cid"), "BAY1", {}, o);
  REQUIRE(m);
  const auto id = m->find(oref("Bay1Prot/PTOC1.StrVal.setMag.f[SG]"));
  REQUIRE(id);
  CHECK(m->at(*id).value == mms::data::floating_point(150.5F));
}

TEST_CASE("SCL model: unmappable content, lenient and strict", "[server][scl]") {
  const std::string xml = R"(<?xml version="1.0"?>
<SCL xmlns="http://www.iec.ch/61850/2003/SCL" version="2007" revision="B">
<Header id="t"/>
<IED name="X"><AccessPoint name="A"><Server><LDevice inst="LD">
  <LN0 lnClass="LLN0" inst="" lnType="L0">
    <DataSet name="Both">
      <FCDA ldInst="LD" lnClass="LLN0" doName="Cnt" daName="big" fc="ST"/>
      <FCDA ldInst="LD" lnClass="LLN0" doName="Cnt" daName="stVal" fc="ST"/>
    </DataSet>
    <DataSet name="Gone">
      <FCDA ldInst="LD" lnClass="LLN0" doName="Cnt" daName="big" fc="ST"/>
    </DataSet>
    <ReportControl name="rc" datSet="Gone" indexed="false"><TrgOps dchg="true"/><OptFields/></ReportControl>
    <ReportControl name="many" datSet="Both"><RptEnabled max="120"/></ReportControl>
    <DOI name="Cnt"><DAI name="stVal"><Val>99999</Val></DAI><DAI name="t"><Val>2020-01-01T00:00:00Z</Val></DAI></DOI>
  </LN0>
</LDevice></Server></AccessPoint></IED>
<DataTypeTemplates>
  <LNodeType id="L0" lnClass="LLN0"><DO name="Cnt" type="C"/></LNodeType>
  <DOType id="C" cdc="INS">
    <DA name="stVal" bType="INT8" fc="ST" dchg="true"/>
    <DA name="big" bType="INT64U" fc="ST"/>
    <DA name="t" bType="Timestamp" fc="ST"/>
  </DOType>
</DataTypeTemplates>
</SCL>
)";
  auto r = scl::load_string(xml);
  REQUIRE(r.ok());
  scl::diagnostics diags;
  auto m = srv::load_model(*r.doc, "X", {}, {}, &diags);
  for (const auto& d : diags) UNSCOPED_INFO(scl::to_string(d));
  REQUIRE(m);
  CHECK(diags.error_count() == 0);
  CHECK(diags.warning_count() >= 5);  // big, stVal value, t value, member, Gone, max
  CHECK(m->find(oref("XLD/LLN0.Cnt.big[ST]")).error() == srv::errc::object_not_found);
  REQUIRE(m->data_sets().size() == 1);
  CHECK(m->data_sets()[0].name == "Both");
  CHECK(m->data_sets()[0].members.size() == 1);
  REQUIRE(m->report_controls().size() == 100);
  CHECK(m->report_controls()[0].settings.name == "rc");
  CHECK(m->report_controls()[0].settings.data_set.empty());
  CHECK(m->report_controls()[1].settings.name == "many01");
  CHECK(m->report_controls()[99].settings.name == "many99");

  srv::scl_load_options strict;
  strict.strict = true;
  scl::diagnostics strict_diags;
  auto refused = srv::load_model(*r.doc, "X", {}, strict, &strict_diags);
  CHECK(refused.error() == srv::errc::invalid_model);
  CHECK(strict_diags.error_count() > 0);

  auto missing = srv::load_model(*r.doc, "NOPE");
  CHECK_FALSE(missing);
  auto no_file = srv::load_model_file(data_path("does_not_exist.icd"));
  CHECK_FALSE(no_file);
}
