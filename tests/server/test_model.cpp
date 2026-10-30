#include <catch2/catch_test_macros.hpp>

#include <algorithm>

#include "server_test_util.hpp"

using namespace server_test;
using model::basic_type;
using model::fc;

TEST_CASE("Model builder: tree, lookups and references", "[server]") {
  const auto m = make_model();
  CHECK(m.logical_devices().size() == 2);
  const auto ld = m.find_logical_device("IED1LD0");
  REQUIRE(ld != srv::no_node);
  const auto f = m.find(oref("IED1LD0/MMXU1.TotW.mag.f[MX]"));
  REQUIRE(f);
  CHECK(m.at(*f).type == basic_type::float32);
  CHECK(m.at(*f).fc == fc::MX);
  CHECK(m.at(*f).triggers.dchg);
  CHECK(m.reference_of(*f) == "IED1LD0/MMXU1.TotW.mag.f");
  CHECK(m.logical_node_of(*f) == *m.find(oref("IED1LD0/MMXU1")));

  // FC filtering: TotW has MX and CF attributes, but no ST.
  CHECK(m.find(oref("IED1LD0/MMXU1.TotW[CF]")));
  CHECK(m.find(oref("IED1LD0/MMXU1.TotW[ST]")).error() == srv::errc::object_not_found);
  CHECK(m.find(oref("IED1LD0/MMXU1.TotW.db[MX]")).error() == srv::errc::object_not_found);
  CHECK(m.find(oref("IED1LD0/NOPE1")).error() == srv::errc::object_not_found);

  CHECK(m.data_sets().size() == 2);
  CHECK(m.report_controls().size() == 4);
  const auto brcb = m.find(oref("IED1LD0/LLN0.brcb01[BR]"));
  REQUIRE(brcb);
  CHECK(m.at(*brcb).kind == srv::node_kind::control_block);
  CHECK(m.find(oref("IED1LD0/LLN0.brcb01.ResvTms[BR]")));
  CHECK(m.find(oref("IED1LD0/LLN0.urcb01.Resv[RP]")));
  CHECK(!m.find(oref("IED1LD0/LLN0.urcb01.EntryID[RP]")));
}

TEST_CASE("Model builder: MMS type descriptions follow IEC 61850-8-1", "[server]") {
  const auto m = make_model();
  const auto mmxu = *m.find(oref("IED1LD0/MMXU1"));
  auto ln = m.type_of(mmxu);
  REQUIRE(ln);
  REQUIRE(ln->components.size() == 2);
  CHECK(ln->components[0].name == "MX");  // FC order: ST MX SP SV CF ...
  CHECK(ln->components[1].name == "CF");
  const auto& mx = ln->components[0].type;
  REQUIRE(mx.components.size() == 2);
  CHECK(mx.components[0].name == "TotW");
  CHECK(mx.components[1].name == "PhV");
  const auto& totw = mx.components[0].type;
  REQUIRE(totw.components.size() == 3);  // mag, q, t (db is CF)
  CHECK(totw.components[0].type.components[0].type == mms::type_description::float32());
  CHECK(totw.components[1].type == mms::type_description::bit_string(13));
  CHECK(totw.components[2].type == mms::type_description::utc_time());

  const auto arr = *m.find(oref("IED1LD0/GGIO1.Arr.vals[SP]"));
  auto t = m.type_of(arr);
  REQUIRE(t);
  CHECK(*t == mms::type_description::array(4, mms::type_description::integer(32)));

  const auto urcb = *m.find(oref("IED1LD0/LLN0.urcb01[RP]"));
  auto rcb = m.type_of(urcb, fc::RP);
  REQUIRE(rcb);
  std::vector<std::string> names;
  for (const auto& c : rcb->components) names.push_back(c.name);
  CHECK(names == std::vector<std::string>{"RptID", "RptEna", "Resv", "DatSet", "ConfRev", "OptFlds",
                                          "BufTm", "SqNum", "TrgOps", "IntgPd", "GI", "Owner"});
}

TEST_CASE("Model builder: errors are recorded and reported by build()", "[server]") {
  {
    srv::model_builder b;
    auto ln = b.logical_device("LD").logical_node("GGIO1");
    ln.data_object("Ind1");
    ln.data_object("Ind1");
    CHECK(b.error() == srv::errc::object_exists);
    CHECK(b.build().error() == srv::errc::object_exists);
  }
  {
    srv::model_builder b;
    b.logical_device("1bad");
    CHECK(b.build().error() == openiec61850::errc::malformed_encoding);
  }
  {
    srv::model_builder b;
    auto ln = b.logical_device("LD").logical_node("GGIO1");
    ln.data_object("Ind1").attribute("stVal", fc::ST, basic_type::boolean,
                                     srv::attribute_options{}.with_value(mms::data::integer(3)));
    CHECK(b.build().error() == srv::errc::type_mismatch);
  }
  {
    srv::model_builder b;
    auto ln = b.logical_device("LD").logical_node("GGIO1");
    ln.data_object("Ind1").attribute("stVal", fc::ST, basic_type::boolean);
    ln.data_set("DS", {oref("LD/GGIO1.Ind2[ST]")});
    CHECK(b.build().error() == srv::errc::invalid_model);
  }
  {
    srv::model_builder b;
    auto ln = b.logical_device("LD").logical_node("GGIO1");
    ln.data_object("Ind1").structure("s", fc::ST);  // no components
    CHECK(b.build().error() == srv::errc::invalid_model);
  }
  {
    srv::model_builder b;
    auto ln = b.logical_device("LD").logical_node("LLN0");
    ln.data_object("Mod").attribute("stVal", fc::ST, basic_type::enumerated);
    srv::report_control_settings rc;
    rc.name = "rcb";
    rc.data_set = "missing";
    ln.report_control(rc);
    CHECK(b.build().error() == srv::errc::invalid_model);
  }
}

TEST_CASE("Values: defaults and SCL text", "[server]") {
  CHECK(*srv::default_value(basic_type::quality) == model::quality{}.to_mms());
  CHECK(*srv::default_value(basic_type::int32u, 0, 2) ==
        mms::data::array({mms::data::unsigned_integer(0), mms::data::unsigned_integer(0)}));
  CHECK(*srv::parse_value(basic_type::boolean, "true") == mms::data::boolean(true));
  CHECK(*srv::parse_value(basic_type::int32, "-12") == mms::data::integer(-12));
  CHECK(*srv::parse_value(basic_type::float32, "1.5") == mms::data::floating_point(1.5F));
  CHECK(*srv::parse_value(basic_type::dbpos, "on") == model::to_mms(model::dbpos::on));
  CHECK(*srv::parse_value(basic_type::entry_id, "0001020304050607") ==
        model::entry_id({0, 1, 2, 3, 4, 5, 6, 7}).to_mms());
  CHECK(srv::parse_value(basic_type::int8, "x").error() == srv::errc::type_mismatch);
}

TEST_CASE("Model builder: arrays of data objects", "[server]") {
  auto fill = [](srv::do_handle e, basic_type t) { e.attribute("v", fc::SP, t); };
  {
    srv::model_builder b;
    auto ln = b.logical_device("LD").logical_node("GGIO1");
    auto arr = ln.data_object("Sig", 2);
    fill(arr.element(1), basic_type::int32);  // creates element 0 too
    fill(arr.element(0), basic_type::int32);
    auto outer = ln.data_object("Out");
    auto sub = outer.sub_object("Sub", 1);
    sub.element(0).sub_object("In", 1).element(0).attribute("x", fc::ST, basic_type::boolean);
    auto m = b.build();
    REQUIRE(m);
    CHECK(m->reference_of(*m->find(oref("LD/GGIO1.Sig(1).v[SP]"))) == "LD/GGIO1.Sig(1).v");
    CHECK(m->reference_of(*m->find(oref("LD/GGIO1.Out.Sub(0).In(0).x"))) ==
          "LD/GGIO1.Out.Sub(0).In(0).x");
    const auto t = m->type_of(*m->find(oref("LD/GGIO1.Sig")), fc::SP);
    REQUIRE(t);
    CHECK(t->type == mms::data_type::array);
  }
  {
    srv::model_builder b;  // attributes go to the elements
    auto arr = b.logical_device("LD").logical_node("GGIO1").data_object("Sig", 2);
    arr.attribute("v", fc::SP, basic_type::int32);
    CHECK(b.error() == openiec61850::errc::invalid_state);
  }
  {
    srv::model_builder b;  // past the end
    auto arr = b.logical_device("LD").logical_node("GGIO1").data_object("Sig", 2);
    arr.element(2);
    CHECK(b.error() == openiec61850::errc::invalid_state);
  }
  {
    srv::model_builder b;  // an element missing
    auto arr = b.logical_device("LD").logical_node("GGIO1").data_object("Sig", 2);
    fill(arr.element(0), basic_type::int32);
    CHECK(b.build().error() == srv::errc::invalid_model);
  }
  {
    srv::model_builder b;  // elements of different types
    auto arr = b.logical_device("LD").logical_node("GGIO1").data_object("Sig", 2);
    fill(arr.element(0), basic_type::int32);
    fill(arr.element(1), basic_type::int16);
    CHECK(b.build().error() == srv::errc::invalid_model);
  }
}

TEST_CASE("Model builder: logs of other logical devices", "[server]") {
  auto build = [](std::string_view ld, std::string_view ln) {
    srv::model_builder b;
    auto a = b.logical_device("A").logical_node("LLN0");
    b.logical_device("B").logical_node("LLN0").log("L");
    srv::log_control_settings lc;
    lc.name = "lcb";
    lc.log_name = "L";
    lc.log_ld = ld;
    lc.log_ln = ln;
    a.log_control(lc);
    return b.build();
  };
  CHECK(build("B", "LLN0"));
  CHECK(build("B", "").error() == srv::errc::invalid_model);
  CHECK(build("C", "LLN0").error() == srv::errc::invalid_model);
  CHECK(build("", "LLN0").error() == srv::errc::invalid_model);  // not in this LD
}

TEST_CASE("Model values: Timestamp and EntryTime text", "[server]") {
  auto seconds = [](std::string_view text) {
    return srv::parse_value(basic_type::timestamp, text)->as_utc_time()->seconds;
  };
  CHECK(seconds("1970-01-01T00:00:10Z") == 10);
  CHECK(seconds(" 1970-01-01T01:00:10 ") == 3610);
  CHECK(seconds("1970-01-01T01:00:10+01:00") == 10);
  CHECK(seconds("1970-01-01T00:00:10-00:30") == 1810);
  CHECK(srv::parse_value(basic_type::timestamp, "2020-01-01T00:00:00.25Z")->as_utc_time()->fraction ==
        1U << 22);
  const auto et = srv::parse_value(basic_type::entry_time, "1984-01-02T00:00:01.5Z");
  REQUIRE(et);
  REQUIRE(et->as_binary_time());
  CHECK(et->as_binary_time()->days == 1);
  CHECK(et->as_binary_time()->ms_of_day == 1500);
  for (const auto* bad : {"", "2020-13-01T00:00:00Z", "2020-02-30T00:00:00Z", "2020-01-01 00:00:00",
                          "2020-01-01T24:00:00Z", "2020-01-01T00:00:00.Z", "2020-01-01T00:00:00Zx",
                          "2020-01-01T00:00:00+1", "1969-12-31T23:59:59Z"}) {
    INFO(bad);
    CHECK(srv::parse_value(basic_type::timestamp, bad).error() == srv::errc::type_mismatch);
  }
  CHECK(srv::parse_value(basic_type::entry_time, "1980-01-01T00:00:00Z").error() ==
        srv::errc::type_mismatch);
}
