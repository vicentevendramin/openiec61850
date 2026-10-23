#include <catch2/catch_test_macros.hpp>

#include <string>
#include <variant>
#include <vector>

#include "scl_test_util.hpp"

namespace scl = openiec61850::scl;
namespace model = openiec61850::model;
using model::basic_type;
using model::fc;
using model::object_reference;
using openiec61850::errc;
using scl_test::load_data;

namespace {

scl::instantiated_ied instantiate_ok(const scl::document& doc, std::string_view ied,
                                     std::string_view ap = {}) {
  scl::diagnostics diags;
  auto r = scl::instantiate(doc, ied, ap, &diags);
  for (const auto& d : diags) UNSCOPED_INFO(scl::to_string(d));
  REQUIRE(r);
  CHECK(diags.error_count() == 0);
  return std::move(*r);
}

const scl::data_node& node_at(const scl::instantiated_ied& ied, std::string_view ref) {
  auto r = object_reference::parse(ref);
  REQUIRE(r);
  const auto* n = ied.find(*r);
  INFO(ref);
  REQUIRE(n != nullptr);
  return *n;
}

std::vector<std::string> child_names(const scl::data_node& n) {
  std::vector<std::string> out;
  for (const auto& c : n.children) out.push_back(c.name);
  return out;
}

}  // namespace

TEST_CASE("Instantiate the Ed.1 ICD", "[scl]") {
  const auto doc = load_data("ed1_relay.icd");
  const auto ied = instantiate_ok(doc, "TEMPLATE");
  CHECK(ied.name == "TEMPLATE");
  CHECK(ied.access_point == "S1");
  CHECK(ied.edition == model::edition::ed1);
  REQUIRE(ied.lds.size() == 2);
  CHECK(ied.lds[0].name == "TEMPLATECTRL");
  CHECK(ied.lds[1].name == "TEMPLATEMEAS");

  const auto* ctrl = ied.find("TEMPLATECTRL");
  REQUIRE(ctrl != nullptr);
  REQUIRE(ctrl->lns.size() == 5);
  CHECK(ctrl->lns[0].name == "LLN0");
  CHECK(ctrl->lns[3].name == "Q0CSWI1");
  CHECK(ctrl->lns[3].prefix == "Q0");
  CHECK(ctrl->lns[3].ln_type == "CSWI_T");

  const auto* xcbr = ctrl->find("XCBR1");
  REQUIRE(xcbr != nullptr);
  REQUIRE(xcbr->data_objects.size() == 9);
  const auto& pos = *xcbr->find("Pos");
  CHECK(pos.is_data_object());
  CHECK(pos.cdc == "DPC");
  CHECK(pos.type_id == "DPC_Status");
  CHECK(child_names(pos) == std::vector<std::string>{"stVal", "q", "t", "ctlModel"});

  const auto& st_val = node_at(ied, "TEMPLATECTRL/XCBR1.Pos.stVal");
  CHECK_FALSE(st_val.is_data_object());
  CHECK(st_val.fc == fc::ST);
  CHECK(st_val.type == basic_type::dbpos);
  CHECK(st_val.btype == "Dbpos");
  CHECK(st_val.triggers.data_change());
  CHECK_FALSE(st_val.triggers.quality_change());
  CHECK(node_at(ied, "TEMPLATECTRL/XCBR1.Pos.q").triggers.quality_change());
  CHECK(node_at(ied, "TEMPLATECTRL/XCBR1.Pos.q").type == basic_type::quality);
  CHECK(node_at(ied, "TEMPLATECTRL/XCBR1.Pos.t").type == basic_type::timestamp);

  // Structures: Oper (CO) expands DAType Oper_BOOL with the nested Originator.
  const auto& oper = node_at(ied, "TEMPLATECTRL/Q0CSWI1.Pos.Oper");
  CHECK(oper.is_struct());
  CHECK(oper.fc == fc::CO);
  CHECK(oper.type_id == "Oper_BOOL");
  CHECK(child_names(oper) ==
        std::vector<std::string>{"ctlVal", "origin", "ctlNum", "T", "Test", "Check"});
  const auto& or_cat = node_at(ied, "TEMPLATECTRL/Q0CSWI1.Pos.Oper.origin.orCat");
  CHECK(or_cat.fc == fc::CO);  // inherited from the DA
  CHECK(or_cat.type == basic_type::enumerated);
  CHECK(or_cat.type_id == "orCategory");
  const auto& or_ident = node_at(ied, "TEMPLATECTRL/Q0CSWI1.Pos.Oper.origin.orIdent");
  CHECK(or_ident.type == basic_type::octet_string);
  CHECK(or_ident.size == 64);
  CHECK(node_at(ied, "TEMPLATECTRL/Q0CSWI1.Pos.Oper.Check").type == basic_type::check);

  // Sub-data objects and BDA trigger inheritance.
  const auto& phs_a = node_at(ied, "TEMPLATEMEAS/MMXU1.A.phsA");
  CHECK(phs_a.is_data_object());
  CHECK(phs_a.cdc == "CMV");
  const auto& f = node_at(ied, "TEMPLATEMEAS/MMXU1.A.phsA.cVal.mag.f");
  CHECK(f.type == basic_type::float32);
  CHECK(f.fc == fc::MX);
  CHECK(f.triggers.data_change());
  CHECK(f.s_addr == "ai:ia");

  // Arrays are described once with their size.
  const auto& hst = node_at(ied, "TEMPLATECTRL/GGIO1.Hist.hstVal");
  CHECK(hst.count == 8);
  CHECK(hst.type == basic_type::int32u);
  CHECK(node_at(ied, "TEMPLATECTRL/GGIO1.Hist.hstVal(7)").name == "hstVal");
  CHECK(ied.find(*object_reference::parse("TEMPLATECTRL/GGIO1.Hist.hstVal(8)")) == nullptr);

  CHECK(ied.node_count() > 100);
}

TEST_CASE("Initial values merge templates and instance overrides", "[scl]") {
  const auto doc = load_data("ed1_relay.icd");
  const auto ied = instantiate_ok(doc, "TEMPLATE");

  // Template default (DOType ENC_Mod) overridden by the DOI in LLN0 only.
  const auto& lln0_ctl = node_at(ied, "TEMPLATECTRL/LLN0.Mod.ctlModel");
  REQUIRE(lln0_ctl.values.size() == 1);
  CHECK(lln0_ctl.values[0].text == "status-only");
  CHECK(std::get<std::int64_t>(lln0_ctl.values[0].parsed) == 0);
  const auto& xcbr_mod = node_at(ied, "TEMPLATECTRL/XCBR1.Mod.ctlModel");
  REQUIRE(xcbr_mod.values.size() == 1);
  CHECK(std::get<std::int64_t>(xcbr_mod.values[0].parsed) == 1);

  // Enum default through the template, ord resolved.
  const auto& beh = node_at(ied, "TEMPLATECTRL/LLN0.Beh.stVal");
  REQUIRE(beh.values.size() == 1);
  CHECK(beh.values[0].text == "on");
  CHECK(std::get<std::int64_t>(beh.values[0].parsed) == 1);
  CHECK(std::get<std::int64_t>(node_at(ied, "TEMPLATECTRL/LLN0.Health.stVal").values[0].parsed) ==
        1);

  // valKind override; no template value.
  const auto& xcbr_ctl = node_at(ied, "TEMPLATECTRL/XCBR1.Pos.ctlModel");
  CHECK(xcbr_ctl.kind_of_value == scl::value_kind::ro);
  REQUIRE(xcbr_ctl.values.size() == 1);
  CHECK(std::get<std::int64_t>(xcbr_ctl.values[0].parsed) == 0);

  const auto& sbo = node_at(ied, "TEMPLATECTRL/Q0CSWI1.Pos.sboTimeout");
  REQUIRE(sbo.values.size() == 1);
  CHECK(std::get<std::uint64_t>(sbo.values[0].parsed) == 30000);

  const auto& ind1 = node_at(ied, "TEMPLATECTRL/GGIO1.Ind1.stVal");
  CHECK(std::get<bool>(ind1.values.at(0).parsed));
  CHECK(ind1.s_addr == "di:1");
  CHECK(node_at(ied, "TEMPLATECTRL/GGIO1.Ind1").desc == "Spare input 1");
  CHECK(node_at(ied, "TEMPLATECTRL/GGIO1.Ind2.stVal").values.empty());

  const auto& vendor = node_at(ied, "TEMPLATECTRL/LLN0.NamPlt.vendor");
  CHECK(std::get<std::string>(vendor.values.at(0).parsed) == "openiec61850");
  CHECK(vendor.type == basic_type::visible_string);
  CHECK(vendor.size == 255);

  // SIUnit override in a structure; multiplier with an empty literal (ord 0).
  const auto& unit = node_at(ied, "TEMPLATEMEAS/MMXU1.TotW.units.SIUnit");
  CHECK(std::get<std::int64_t>(unit.values.at(0).parsed) == 38);
  const auto& mult = node_at(ied, "TEMPLATEMEAS/MMXU1.TotW.units.multiplier");
  CHECK(std::get<std::int64_t>(mult.values.at(0).parsed) == 0);
  CHECK(std::get<std::uint64_t>(node_at(ied, "TEMPLATEMEAS/MMXU1.TotW.db").values.at(0).parsed) ==
        500);

  // Array default from the template applies to the whole array.
  const auto& hst = node_at(ied, "TEMPLATECTRL/GGIO1.Hist.hstVal");
  REQUIRE(hst.values.size() == 1);
  CHECK_FALSE(hst.values[0].index.has_value());

  // Only the EnumTypes used by the tree are copied.
  REQUIRE(ied.find_enum_type("ctlModel") != nullptr);
  CHECK(ied.find_enum_type("ctlModel")->find_ord(4)->text == "sbo-with-enhanced-security");
  CHECK(ied.find_enum_type("orCategory") != nullptr);
  CHECK(ied.find_enum_type("SIUnit") != nullptr);
}

TEST_CASE("Data sets resolve to functionally constrained references", "[scl]") {
  const auto doc = load_data("ed1_relay.icd");
  const auto ied = instantiate_ok(doc, "TEMPLATE");
  const auto* ds = ied.find("TEMPLATECTRL")->find("LLN0")->find_data_set("Positions");
  REQUIRE(ds != nullptr);
  REQUIRE(ds->members.size() == 4);
  CHECK(ds->members[0].to_string() == "TEMPLATECTRL/XCBR1.Pos.stVal[ST]");
  CHECK(ds->members[1].to_string() == "TEMPLATECTRL/XCBR1.Pos.q[ST]");
  CHECK(ds->members[2].to_string() == "TEMPLATECTRL/Q0CSWI1.Pos[ST]");
  CHECK(ds->members[3].to_string() == "TEMPLATEMEAS/MMXU1.TotW[MX]");
  for (const auto& m : ds->members) CHECK(ied.find(m) != nullptr);

  // FC must match: Pos has ST attributes but no MX ones.
  CHECK(ied.find(*object_reference::parse("TEMPLATECTRL/XCBR1.Pos[MX]")) == nullptr);
  CHECK(ied.find(*object_reference::parse("TEMPLATECTRL/XCBR1.Pos[CF]")) != nullptr);

  // Control blocks are carried over.
  const auto* lln0 = ied.find("TEMPLATECTRL")->find("LLN0");
  CHECK(lln0->report_controls.size() == 2);
  CHECK(lln0->gse_controls.size() == 1);

  // resolve_fcda on the document.
  const auto& fcda = doc.ieds[0].find_server()->find_ld("CTRL")->ln0.data_sets[0].members[3];
  auto ref = scl::resolve_fcda(doc, "TEMPLATE", fcda);
  REQUIRE(ref);
  CHECK(ref->to_string() == "TEMPLATEMEAS/MMXU1.TotW[MX]");
  CHECK(scl::resolve_fcda(doc, "NOPE", fcda).error() == errc::invalid_state);
}

TEST_CASE("Instantiate the Ed.2 CID", "[scl]") {
  const auto doc = load_data("ed2_bay.cid");
  const auto ied = instantiate_ok(doc, "BAY1", "P1");
  REQUIRE(ied.lds.size() == 1);
  CHECK(ied.lds[0].name == "Bay1Prot");
  CHECK(ied.lds[0].inst == "PROT");

  // SDOs and DAs keep their interleaved declaration order.
  CHECK(child_names(node_at(ied, "Bay1Prot/MMXU1.PhV")) ==
        std::vector<std::string>{"phsA", "q", "phsB", "phsC", "neut"});
  CHECK(node_at(ied, "Bay1Prot/MMXU1.PhV.phsA.cVal.mag.f").s_addr == "ai:va");

  // DOI override of a template value.
  const auto& db = node_at(ied, "Bay1Prot/MMXU1.Hz.db");
  REQUIRE(db.values.size() == 1);
  CHECK(std::get<std::uint64_t>(db.values[0].parsed) == 200);

  const auto& ctl = node_at(ied, "Bay1Prot/QA1CSWI1.Pos.ctlModel");
  CHECK(std::get<std::int64_t>(ctl.values.at(0).parsed) == 4);
  CHECK(std::get<std::int64_t>(node_at(ied, "Bay1Prot/XCBR1.Pos.ctlModel").values.at(0).parsed) ==
        0);
  const auto& beh = node_at(ied, "Bay1Prot/LLN0.Beh.stVal");
  CHECK(beh.triggers == model::trigger_conditions::of({model::trigger::data_change,
                                                       model::trigger::data_update}));

  // Value of one array element.
  const auto& an_in = node_at(ied, "Bay1Prot/GGIO1.AnIn.mag");
  CHECK(an_in.count == 4);
  CHECK(an_in.is_struct());
  const auto& an_f = node_at(ied, "Bay1Prot/GGIO1.AnIn.mag(1).f");
  REQUIRE(an_f.values.size() == 1);
  CHECK(an_f.values[0].index == 1U);
  CHECK(std::get<double>(an_f.values[0].parsed) == 1.5);

  // Setting group values.
  const auto& set_mag = node_at(ied, "Bay1Prot/PTOC1.StrVal.setMag.f");
  CHECK(set_mag.fc == fc::SG);
  REQUIRE(set_mag.values.size() == 2);
  CHECK(set_mag.values[0].sgroup == 1U);
  CHECK(std::get<double>(set_mag.values[0].parsed) == 100.0);
  CHECK(set_mag.values[1].sgroup == 2U);
  CHECK(std::get<double>(set_mag.values[1].parsed) == 150.5);

  const auto* lln0 = ied.find("Bay1Prot")->find("LLN0");
  REQUIRE(lln0->setting);
  CHECK(lln0->setting->num_of_sgs == 2);
  CHECK(lln0->smv_controls.size() == 1);
  CHECK(lln0->log_controls.size() == 1);

  const auto* meas = lln0->find_data_set("Meas");
  REQUIRE(meas != nullptr);
  REQUIRE(meas->members.size() == 3);
  CHECK(meas->members[0].to_string() == "Bay1Prot/MMXU1.PhV.phsA.cVal.mag.f[MX]");
  CHECK(meas->members[1].to_string() == "Bay1Prot/MMXU1.Hz[MX]");
  CHECK(meas->members[2].to_string() == "Bay1Prot/GGIO1.AnIn.mag(2)[MX]");
  const auto* status = lln0->find_data_set("Status");
  REQUIRE(status != nullptr);
  CHECK(status->members[1].to_string() == "Bay1Prot/QA1CSWI1.Pos.stVal[ST]");

  CHECK(ied.find_enum_type("BehKind") != nullptr);
  CHECK(ied.find_enum_type("Unused") == nullptr);
}

TEST_CASE("Instantiate IEDs of an SCD", "[scl]") {
  const auto doc = load_data("station.scd");
  const auto ied1 = instantiate_ok(doc, "IED1");
  REQUIRE(ied1.lds.size() == 2);
  const auto* ds = ied1.find("IED1LD0")->find("LLN0")->find_data_set("ds1");
  REQUIRE(ds != nullptr);
  REQUIRE(ds->members.size() == 2);
  // FCDA into another LD of the same server.
  CHECK(ds->members[1].to_string() == "IED1LD1/GGIO2.Ind1.stVal[ST]");

  // ServerAt: access point S2 exposes the server of S1.
  const auto ied2 = instantiate_ok(doc, "IED2", "S2");
  CHECK(ied2.access_point == "S2");
  REQUIRE(ied2.lds.size() == 1);
  const auto& ind = node_at(ied2, "IED2CTRL/GGIO1.Ind1.stVal");
  CHECK(std::get<bool>(ind.values.at(0).parsed));
  CHECK_FALSE(std::get<bool>(node_at(ied1, "IED1LD0/GGIO1.Ind1.stVal").values.at(0).parsed));

  scl::diagnostics diags;
  CHECK(scl::instantiate(doc, "IED3", {}, &diags).error() == errc::invalid_state);
  CHECK(scl::instantiate(doc, "IED2", "S9", &diags).error() == errc::invalid_state);
  CHECK(diags.count(scl::diagnostic_code::not_found) == 2);
}

TEST_CASE("Instantiation limits", "[scl]") {
  const auto doc = load_data("ed1_relay.icd");
  scl::instantiate_options opts;
  opts.max_nodes = 50;
  scl::diagnostics diags;
  CHECK(scl::instantiate(doc, "TEMPLATE", {}, &diags, opts).error() == errc::length_overflow);
  CHECK(diags.count(scl::diagnostic_code::limit_exceeded) == 1);

  opts.max_nodes = 1'000'000;
  opts.max_depth = 2;
  scl::diagnostics shallow;
  auto r = scl::instantiate(doc, "TEMPLATE", {}, &shallow, opts);
  REQUIRE(r);
  CHECK(shallow.count(scl::diagnostic_code::limit_exceeded) > 0);
  opts.strict = true;
  CHECK(scl::instantiate(doc, "TEMPLATE", {}, nullptr, opts).error() == errc::malformed_encoding);
}
