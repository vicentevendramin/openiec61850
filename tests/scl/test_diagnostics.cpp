#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <string>

#include "scl_test_util.hpp"

namespace scl = openiec61850::scl;
using code = scl::diagnostic_code;
using openiec61850::errc;
using scl::severity;
using scl_test::wrap;

namespace {

constexpr std::string_view good_templates = R"(
<LNodeType id="LLN0_T" lnClass="LLN0">
  <DO name="Beh" type="SPS_T"/>
</LNodeType>
<LNodeType id="GGIO_T" lnClass="GGIO">
  <DO name="Ind1" type="SPS_T"/>
</LNodeType>
<DOType id="SPS_T" cdc="SPS">
  <DA name="stVal" bType="BOOLEAN" fc="ST" dchg="true"/>
  <DA name="q" bType="Quality" fc="ST" qchg="true"/>
</DOType>)";

std::string one_ied(std::string_view ln_content, std::string_view ln_type = "GGIO_T") {
  std::string s = R"(<IED name="D"><AccessPoint name="A"><Server><LDevice inst="LD">
<LN0 lnClass="LLN0" inst="" lnType=")";
  s += ln_type;
  s += R"(">)";
  s += ln_content;
  s += R"(</LN0>
<LN lnClass="GGIO" inst="1" lnType="GGIO_T"/>
</LDevice></Server></AccessPoint></IED>)";
  return s;
}

const scl::diagnostic* first(const scl::diagnostics& d, code c) {
  const auto it = std::find_if(d.begin(), d.end(), [&](const auto& x) { return x.code == c; });
  return it == d.end() ? nullptr : &*it;
}

void dump(const scl::diagnostics& d) {
  for (const auto& x : d) UNSCOPED_INFO(scl::to_string(x));
}

}  // namespace

TEST_CASE("Well-formed minimal document has no diagnostics", "[scl]") {
  const auto r = scl::load_string(wrap(one_ied("", "LLN0_T"), good_templates));
  dump(r.diags);
  REQUIRE(r.ok());
  CHECK(r.diags.empty());
  scl::diagnostics diags;
  REQUIRE(scl::instantiate(*r.doc, "D", {}, &diags));
  CHECK(diags.empty());
}

TEST_CASE("Malformed XML and non-SCL documents fail", "[scl]") {
  const auto bad = scl::load_string("<SCL>\n<Header id='x'>\n</SCL>");
  CHECK(bad.doc.error() == errc::malformed_encoding);
  REQUIRE(bad.diags.size() == 1);
  CHECK(bad.diags.items()[0].code == code::xml_syntax);
  CHECK(bad.diags.items()[0].line == 3);
  CHECK(bad.diags.items()[0].level == severity::error);

  const auto empty = scl::load_string("");
  CHECK_FALSE(empty.ok());

  const auto other = scl::load_string("<Foo/>");
  CHECK_FALSE(other.ok());
  CHECK(other.diags.count(code::not_scl) == 1);

  const auto foreign_ns = scl::load_string(R"(<SCL xmlns="urn:other"/>)");
  CHECK(foreign_ns.diags.count(code::not_scl) == 1);
}

TEST_CASE("Missing types are reported with their line", "[scl]") {
  const std::string xml = wrap(one_ied(""), R"(
<LNodeType id="GGIO_T" lnClass="GGIO">
  <DO name="Ind1" type="SPS_T"/>
  <DO name="Ind2" type="MISSING_DO"/>
</LNodeType>
<DOType id="SPS_T" cdc="SPS">
  <DA name="stVal" bType="BOOLEAN" fc="ST"/>
  <DA name="mag" bType="Struct" type="MISSING_DA" fc="MX"/>
  <DA name="e" bType="Enum" type="MISSING_ENUM" fc="ST"/>
</DOType>)");
  const auto r = scl::load_string(xml);
  REQUIRE(r.ok());  // lenient
  CHECK(r.diags.count(code::unknown_type, severity::error) == 3);
  const auto* d = first(r.diags, code::unknown_type);
  REQUIRE(d != nullptr);
  CHECK(d->line == 12);
  CHECK(d->message.find("MISSING_DO") != std::string::npos);

  // The broken parts are dropped from the instance.
  scl::diagnostics diags;
  auto ied = scl::instantiate(*r.doc, "D", {}, &diags);
  REQUIRE(ied);
  CHECK(diags.count(code::unknown_type) > 0);
  const auto* ln = ied->find("DLD")->find("GGIO1");
  REQUIRE(ln != nullptr);
  REQUIRE(ln->data_objects.size() == 1);
  CHECK(ln->data_objects[0].children.size() == 1);

  scl::load_options strict;
  strict.strict = true;
  const auto s = scl::load_string(xml, strict);
  CHECK(s.doc.error() == errc::malformed_encoding);
  CHECK(s.diags.count(code::unknown_type) == 3);

  scl::instantiate_options istrict;
  istrict.strict = true;
  CHECK(scl::instantiate(*r.doc, "D", {}, nullptr, istrict).error() == errc::malformed_encoding);
}

TEST_CASE("Unknown LNodeType", "[scl]") {
  const auto r = scl::load_string(wrap(one_ied("", "NOPE"), good_templates));
  REQUIRE(r.ok());
  CHECK(r.diags.count(code::unknown_type) == 1);
  scl::diagnostics diags;
  auto ied = scl::instantiate(*r.doc, "D", {}, &diags);
  REQUIRE(ied);
  // LLN0 stays (empty); other LNs are unaffected.
  REQUIRE(ied->lds[0].lns.size() == 2);
  CHECK(ied->lds[0].lns[0].data_objects.empty());
}

TEST_CASE("Bad bType and fc", "[scl]") {
  const auto r = scl::load_string(wrap(one_ied(""), R"(
<LNodeType id="GGIO_T" lnClass="GGIO"><DO name="Ind1" type="SPS_T"/></LNodeType>
<DOType id="SPS_T" cdc="SPS">
  <DA name="stVal" bType="BOOL" fc="ST"/>
  <DA name="q" bType="Quality" fc="QQ"/>
  <DA name="t" bType="Timestamp"/>
  <DA name="s" bType="VisString0" fc="DC"/>
  <DA name="ok" bType="VisString64" fc="DC"/>
</DOType>)"));
  REQUIRE(r.ok());
  CHECK(r.diags.count(code::unknown_btype) == 2);
  CHECK(r.diags.count(code::unknown_fc) == 1);
  CHECK(r.diags.count(code::missing_attribute) == 1);
  // Attributes without a valid fc are not kept; the bad bTypes are dropped at instantiation.
  CHECK(r.doc->templates.find_do_type("SPS_T")->attributes.size() == 3);
  auto ied = scl::instantiate(*r.doc, "D");
  REQUIRE(ied);
  const auto* ind = ied->find("DLD")->find("GGIO1")->find("Ind1");
  REQUIRE(ind != nullptr);
  REQUIRE(ind->children.size() == 1);
  CHECK(ind->children[0].name == "ok");
}

TEST_CASE("Duplicate names", "[scl]") {
  const auto r = scl::load_string(wrap(R"(
<IED name="D"><AccessPoint name="A"><Server>
  <LDevice inst="LD"><LN0 lnClass="LLN0" inst="" lnType="GGIO_T">
    <DataSet name="ds"><FCDA ldInst="LD" lnClass="GGIO" lnInst="1" doName="Ind1" fc="ST"/></DataSet>
    <DataSet name="ds"/>
  </LN0>
  <LN lnClass="GGIO" inst="1" lnType="GGIO_T"/>
  <LN lnClass="GGIO" inst="1" lnType="GGIO_T"/>
  </LDevice>
  <LDevice inst="LD"><LN0 lnClass="LLN0" inst="" lnType="GGIO_T"/></LDevice>
</Server></AccessPoint></IED>
<IED name="D"/>)",
                                       R"(
<LNodeType id="GGIO_T" lnClass="GGIO">
  <DO name="Ind1" type="SPS_T"/>
  <DO name="Ind1" type="SPS_T"/>
</LNodeType>
<DOType id="SPS_T" cdc="SPS"><DA name="stVal" bType="BOOLEAN" fc="ST"/></DOType>
<DOType id="SPS_T" cdc="SPS"/>
<EnumType id="E"><EnumVal ord="1">a</EnumVal><EnumVal ord="1">b</EnumVal></EnumType>)"));
  REQUIRE(r.ok());
  dump(r.diags);
  // data set, LN, LD, IED, DO, DOType, enum ord
  CHECK(r.diags.count(code::duplicate_name, severity::error) == 7);
  // LLN0 with a GGIO LNodeType
  CHECK(r.diags.count(code::type_mismatch, severity::warning) == 2);
}

TEST_CASE("Circular types", "[scl]") {
  const auto r = scl::load_string(wrap(one_ied(""), R"(
<LNodeType id="GGIO_T" lnClass="GGIO"><DO name="Ind1" type="A"/></LNodeType>
<DOType id="A" cdc="X"><SDO name="b" type="B"/></DOType>
<DOType id="B" cdc="X"><SDO name="a" type="A"/></DOType>
<DOType id="S" cdc="X"><DA name="v" bType="Struct" type="R" fc="ST"/></DOType>
<DAType id="R"><BDA name="r" bType="Struct" type="R"/></DAType>)"));
  REQUIRE(r.ok());
  CHECK(r.diags.count(code::circular_type) == 2);
  scl::diagnostics diags;
  auto ied = scl::instantiate(*r.doc, "D", {}, &diags);
  REQUIRE(ied);
  CHECK(diags.count(code::circular_type) > 0);
}

TEST_CASE("Unresolved references", "[scl]") {
  const auto r = scl::load_string(wrap(one_ied(R"(
<DataSet name="ds">
  <FCDA ldInst="LD" lnClass="GGIO" lnInst="1" doName="Ind1" fc="ST"/>
  <FCDA ldInst="LD" lnClass="GGIO" lnInst="1" doName="Ind9" fc="ST"/>
  <FCDA ldInst="LD" lnClass="GGIO" lnInst="1" doName="Ind1" daName="stVal" fc="MX"/>
  <FCDA ldInst="XX" lnClass="GGIO" lnInst="1" doName="Ind1" fc="ST"/>
</DataSet>
<ReportControl name="rc" datSet="nope"/>
<DOI name="Missing"><DAI name="x"/></DOI>
<DOI name="Ind1"/>)"),
                                       R"(
<LNodeType id="GGIO_T" lnClass="GGIO"><DO name="Ind1" type="SPS_T"/></LNodeType>
<DOType id="SPS_T" cdc="SPS"><DA name="stVal" bType="BOOLEAN" fc="ST"/></DOType>)"));
  REQUIRE(r.ok());
  CHECK(r.diags.count(code::unresolved_reference) == 1);  // rc -> nope
  scl::diagnostics diags;
  auto ied = scl::instantiate(*r.doc, "D", {}, &diags);
  REQUIRE(ied);
  dump(diags);
  // DOI Missing; 3 bad FCDAs
  CHECK(diags.count(code::unresolved_reference, severity::warning) == 1);
  CHECK(diags.count(code::unresolved_reference, severity::error) == 3);
  const auto* ds = ied->find("DLD")->find("LLN0")->find_data_set("ds");
  REQUIRE(ds != nullptr);
  REQUIRE(ds->members.size() == 1);
  CHECK(ds->members[0].to_string() == "DLD/GGIO1.Ind1[ST]");
}

TEST_CASE("Invalid values", "[scl]") {
  const auto r = scl::load_string(wrap(one_ied(R"(<DOI name="Ind1">
  <DAI name="stVal"><Val>maybe</Val></DAI>
  <DAI name="n"><Val>300</Val></DAI>
  <DAI name="e"><Val>b</Val></DAI>
  <DAI name="nope"><Val>1</Val></DAI>
</DOI>)"),
                                       R"(
<LNodeType id="GGIO_T" lnClass="GGIO"><DO name="Ind1" type="T"/></LNodeType>
<DOType id="T" cdc="X">
  <DA name="stVal" bType="BOOLEAN" fc="ST"/>
  <DA name="n" bType="INT8U" fc="CF"><Val>-1</Val></DA>
  <DA name="e" bType="Enum" type="E" fc="CF"><Val>z</Val></DA>
  <DA name="f" bType="FLOAT32" fc="CF"><Val>1e39</Val></DA>
</DOType>
<EnumType id="E"><EnumVal ord="1">a</EnumVal><EnumVal ord="2">b</EnumVal></EnumType>)"));
  REQUIRE(r.ok());
  // Template values: n, e, f.
  CHECK(r.diags.count(code::invalid_value, severity::warning) == 3);
  scl::diagnostics diags;
  auto ied = scl::instantiate(*r.doc, "D", {}, &diags);
  REQUIRE(ied);
  // Instance values: stVal, n.
  CHECK(diags.count(code::invalid_value) == 2);
  CHECK(diags.count(code::unresolved_reference) == 1);
  const auto* ind = ied->find("DLD")->find("LLN0")->find("Ind1");
  REQUIRE(ind != nullptr);
  const auto* e = ind->child("e");
  REQUIRE(e->values.size() == 1);
  CHECK(std::get<std::int64_t>(e->values[0].parsed) == 2);
  const auto* st = ind->child("stVal");
  CHECK(std::holds_alternative<std::monostate>(st->values.at(0).parsed));
}

TEST_CASE("Invalid attributes and required elements", "[scl]") {
  const auto r = scl::load_string(R"(<SCL>
<IED name="D"><AccessPoint name="A"><Server timeout="abc"><LDevice inst="LD">
  <LN lnClass="GGIO" lnType="X"/>
  <LN0 lnClass="LLN0" inst="" lnType="X">
    <ReportControl name="r" buffered="yes" confRev="-1"><RptEnabled max="0"/></ReportControl>
    <SettingControl numOfSGs="2" actSG="3"/>
  </LN0>
</LDevice><LDevice/></Server></AccessPoint></IED>
<Communication><SubNetwork name="N"><ConnectedAP iedName="Z" apName="A"/></SubNetwork></Communication>
<DataTypeTemplates><LNodeType id="X" lnClass="GGIO"/><EnumType id="E"><EnumVal>a</EnumVal></EnumType></DataTypeTemplates>
</SCL>)");
  REQUIRE(r.ok());
  dump(r.diags);
  CHECK(r.diags.count(code::invalid_attribute) == 5);  // timeout, buffered, confRev, max, actSG
  // LN inst, LDevice inst, EnumVal ord
  CHECK(r.diags.count(code::missing_attribute, severity::error) == 3);
  CHECK(r.diags.count(code::unresolved_reference, severity::warning) == 1);  // ConnectedAP Z
  CHECK(r.diags.count(code::missing_attribute, severity::warning) == 1);    // no Header
  CHECK(r.doc->ieds[0].access_points[0].srv->timeout == 30);
  CHECK(r.doc->ieds[0].access_points[0].srv->ldevices.size() == 1);
}

TEST_CASE("Diagnostic list behaviour", "[scl]") {
  scl::diagnostics d;
  d.set_limit(2);
  d.warning(code::invalid_name, 1, "a");
  d.error(code::unknown_type, 2, "b");
  d.error(code::unknown_type, 3, "c");
  CHECK(d.size() == 2);
  CHECK(d.dropped() == 1);
  CHECK(d.error_count() == 2);
  CHECK(d.warning_count() == 1);
  CHECK(scl::to_string(d.items()[1]) == "line 2: error: unknown_type: b");
  CHECK(scl::to_string(scl::diagnostic{severity::warning, code::not_scl, 0, "x"}) ==
        "warning: not_scl: x");
}
