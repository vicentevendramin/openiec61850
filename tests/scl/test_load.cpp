#include <catch2/catch_test_macros.hpp>

#include "scl_test_util.hpp"

namespace scl = openiec61850::scl;
namespace model = openiec61850::model;
using model::fc;
using model::trigger;
using model::optional_field;
using scl_test::load_data;

TEST_CASE("Ed.1 ICD: header, edition and communication", "[scl]") {
  const auto doc = load_data("ed1_relay.icd");
  CHECK(doc.edition == model::edition::ed1);
  CHECK(doc.version.empty());
  CHECK(doc.hdr.id == "ed1_relay");
  CHECK(doc.hdr.tool_id == "handwritten");
  CHECK(doc.hdr.line == 4);

  REQUIRE(doc.comm.sub_networks.size() == 1);
  const auto& sn = doc.comm.sub_networks[0];
  CHECK(sn.name == "StationBus");
  CHECK(sn.type == "8-MMS");
  REQUIRE(sn.connected_aps.size() == 1);
  const auto* cap = doc.comm.find("TEMPLATE", "S1");
  REQUIRE(cap == &sn.connected_aps[0]);
  REQUIRE(cap->addr.find("IP") != nullptr);
  CHECK(*cap->addr.find("IP") == "192.168.0.10");
  CHECK(cap->addr.p.size() == 7);
  REQUIRE(cap->gse.size() == 1);
  CHECK(cap->gse[0].ld_inst == "CTRL");
  CHECK(cap->gse[0].cb_name == "gcbPos");
  CHECK(cap->gse[0].min_time == 4U);
  CHECK(cap->gse[0].max_time == 1000U);
  CHECK(*cap->gse[0].addr.find("APPID") == "0001");
}

TEST_CASE("Ed.1 ICD: IED, services and logical devices", "[scl]") {
  const auto doc = load_data("ed1_relay.icd");
  REQUIRE(doc.ieds.size() == 1);
  const auto* ied = doc.find_ied("TEMPLATE");
  REQUIRE(ied != nullptr);
  CHECK(doc.find_ied("OTHER") == nullptr);
  CHECK(ied->manufacturer == "openiec61850");
  CHECK(ied->config_version == "1.0");

  CHECK(ied->svc.present);
  CHECK(ied->svc.has("GetDirectory"));
  CHECK_FALSE(ied->svc.has("SetDataSetValue"));
  REQUIRE(ied->svc.find("ConfDataSet") != nullptr);
  CHECK(ied->svc.find("ConfDataSet")->max() == 4U);
  CHECK(*ied->svc.find("ConfDataSet")->attribute("maxAttributes") == "20");
  CHECK(*ied->svc.find("ReportSettings")->attribute("bufTime") == "Dyn");

  REQUIRE(ied->access_points.size() == 1);
  const auto* srv = ied->find_server();
  REQUIRE(srv != nullptr);
  CHECK(srv == ied->find_server("S1"));
  CHECK(srv->timeout == 30);
  CHECK(srv->auth.none);
  REQUIRE(srv->ldevices.size() == 2);

  const auto* ctrl = srv->find_ld("CTRL");
  REQUIRE(ctrl != nullptr);
  CHECK(ctrl->name(ied->name) == "TEMPLATECTRL");
  CHECK(ctrl->ln0.ln_class == "LLN0");
  CHECK(ctrl->ln0.name() == "LLN0");
  REQUIRE(ctrl->lns.size() == 4);
  CHECK(ctrl->lns[2].name() == "Q0CSWI1");
  CHECK(ctrl->find_ln("Q0CSWI1") == &ctrl->lns[2]);
  CHECK(ctrl->find_ln("LLN0") == &ctrl->ln0);
  CHECK(ctrl->find_ln("CSWI1") == nullptr);
}

TEST_CASE("Ed.1 ICD: data sets and control blocks", "[scl]") {
  const auto doc = load_data("ed1_relay.icd");
  const auto& ln0 = doc.ieds[0].find_server()->find_ld("CTRL")->ln0;

  REQUIRE(ln0.data_sets.size() == 1);
  const auto& ds = ln0.data_sets[0];
  CHECK(ds.name == "Positions");
  REQUIRE(ds.members.size() == 4);
  CHECK(ds.members[0].ln_class == "XCBR");
  CHECK(ds.members[0].do_name == "Pos");
  CHECK(ds.members[0].da_name == "stVal");
  CHECK(ds.members[0].fc == fc::ST);
  CHECK(ds.members[2].prefix == "Q0");
  CHECK(ds.members[2].da_name.empty());
  CHECK(ds.members[3].ld_inst == "MEAS");

  REQUIRE(ln0.report_controls.size() == 2);
  const auto& urcb = ln0.report_controls[0];
  CHECK(urcb.name == "urcbPos");
  CHECK(urcb.rpt_id == "TEMPLATECTRL/LLN0$RP$urcbPos");
  CHECK(urcb.dat_set == "Positions");
  CHECK(urcb.conf_rev == 1);
  CHECK_FALSE(urcb.buffered);
  CHECK(urcb.indexed);
  CHECK(urcb.trg_ops == model::trigger_conditions::of({trigger::data_change,
                                                       trigger::quality_change,
                                                       trigger::general_interrogation}));
  CHECK(urcb.opt_fields ==
        model::optional_fields::of({optional_field::sequence_number,
                                    optional_field::report_time_stamp,
                                    optional_field::reason_for_inclusion,
                                    optional_field::data_set_name,
                                    optional_field::buffer_overflow}));
  CHECK(urcb.rpt_enabled_max == 3);

  const auto& brcb = ln0.report_controls[1];
  CHECK(brcb.buffered);
  CHECK(brcb.buf_time == 100);
  CHECK(brcb.intg_pd == 5000);
  CHECK(brcb.conf_rev == 2);
  CHECK(brcb.trg_ops.integrity());
  CHECK(brcb.trg_ops.data_change());
  CHECK_FALSE(brcb.trg_ops.quality_change());
  CHECK(brcb.opt_fields.entry_id());
  CHECK(brcb.opt_fields.conf_revision());
  CHECK(brcb.opt_fields.data_reference());
  CHECK(brcb.rpt_enabled_max == 1);

  REQUIRE(ln0.gse_controls.size() == 1);
  CHECK(ln0.gse_controls[0].name == "gcbPos");
  CHECK(ln0.gse_controls[0].app_id == "TEMPLATE_GOOSE");
  CHECK(ln0.gse_controls[0].type == "GOOSE");
}

TEST_CASE("Ed.1 ICD: data type templates", "[scl]") {
  const auto doc = load_data("ed1_relay.icd");
  const auto& t = doc.templates;
  CHECK(t.lnode_types.size() == 6);
  const auto* xcbr = t.find_lnode_type("XCBR_T");
  REQUIRE(xcbr != nullptr);
  CHECK(xcbr->ln_class == "XCBR");
  CHECK(xcbr->data_objects.size() == 9);

  const auto* dpc = t.find_do_type("DPC_Ctl");
  REQUIRE(dpc != nullptr);
  CHECK(dpc->cdc == "DPC");
  REQUIRE(dpc->attributes.size() == 6);
  CHECK(dpc->attributes[0].btype == "Struct");
  CHECK(dpc->attributes[0].type == "Oper_BOOL");
  CHECK(dpc->attributes[0].fc == fc::CO);
  CHECK(dpc->attributes[1].dchg);
  CHECK(dpc->attributes[2].qchg);

  const auto* hst = t.find_do_type("HST_T");
  REQUIRE(hst != nullptr);
  CHECK(hst->attributes[0].count == 8);

  const auto* wye = t.find_do_type("WYE_T");
  REQUIRE(wye != nullptr);
  CHECK(wye->sub_data_objects.size() == 3);

  const auto* beh = t.find_enum_type("Beh");
  REQUIRE(beh != nullptr);
  REQUIRE(beh->find_text("test/blocked") != nullptr);
  CHECK(beh->find_text("test/blocked")->ord == 4);
  REQUIRE(beh->find_ord(5) != nullptr);
  CHECK(beh->find_ord(5)->text == "off");
  CHECK(t.find_enum_type("multiplier")->find_text("m")->ord == -3);

  const auto* enc = t.find_do_type("ENC_Mod");
  REQUIRE(enc->attributes[3].values.size() == 1);
  CHECK(enc->attributes[3].values[0].text == "direct-with-normal-security");
}

TEST_CASE("Ed.2 CID: prefixed namespace, extensions and Ed.2 attributes", "[scl]") {
  const auto doc = load_data("ed2_bay.cid");
  CHECK(doc.edition == model::edition::ed2);
  CHECK(doc.version == "2007");
  CHECK(doc.revision == "A");

  const auto* ied = doc.find_ied("BAY1");
  REQUIRE(ied != nullptr);
  CHECK(ied->original_scl_version == "2007");
  CHECK(ied->svc.find("DynAssociation")->max() == 5U);
  const auto* sg = ied->svc.find("SettingGroups");
  REQUIRE(sg != nullptr);
  CHECK(sg->find("SGEdit") != nullptr);
  CHECK(sg->find("ConfSG") != nullptr);
  REQUIRE(ied->svc.find("ClientServices")->find("TimeSyncProt") != nullptr);

  const auto* srv = ied->find_server();
  REQUIRE(srv != nullptr);
  CHECK(srv->timeout == 60);
  CHECK(srv->auth.password);
  const auto* ld = srv->find_ld("PROT");
  REQUIRE(ld != nullptr);
  CHECK(ld->ld_name == "Bay1Prot");
  CHECK(ld->name("BAY1") == "Bay1Prot");

  const auto& ln0 = ld->ln0;
  // The DOI inside the vendor extension is skipped.
  REQUIRE(ln0.data.size() == 1);
  CHECK(ln0.data[0].name == "Mod");

  const auto& brcb = ln0.report_controls.at(0);
  CHECK(brcb.conf_rev == 10000);
  CHECK(brcb.trg_ops == model::trigger_conditions::of({trigger::data_change,
                                                       trigger::quality_change,
                                                       trigger::data_update,
                                                       trigger::integrity}));
  CHECK_FALSE(brcb.opt_fields.buffer_overflow());
  CHECK(brcb.rpt_enabled_max == 2);
  REQUIRE(brcb.clients.size() == 1);
  CHECK(brcb.clients[0].ied_name == "HMI");
  CHECK(brcb.clients[0].ln_class == "IHMI");
  CHECK(brcb.clients[0].ap_ref == "S1");

  const auto& urcb = ln0.report_controls.at(1);
  CHECK_FALSE(urcb.indexed);
  CHECK(urcb.opt_fields == model::optional_fields::of({optional_field::buffer_overflow}));
  CHECK_FALSE(urcb.has_rpt_enabled);

  REQUIRE(ln0.log_controls.size() == 1);
  CHECK(ln0.log_controls[0].log_name == "Bay1Log");
  CHECK(ln0.log_controls[0].ln_class == "LLN0");
  CHECK(ln0.log_controls[0].trg_ops.quality_change());

  REQUIRE(ln0.smv_controls.size() == 1);
  const auto& sv = ln0.smv_controls[0];
  CHECK(sv.smv_id == "Bay1MU01");
  CHECK(sv.smp_rate == 80);
  CHECK(sv.nof_asdu == 1);
  CHECK(sv.smp_mod == "SmpPerPeriod");
  CHECK(sv.opts.refresh_time);
  CHECK(sv.opts.sample_synchronized);
  CHECK(sv.opts.data_set);
  CHECK_FALSE(sv.opts.security);

  REQUIRE(ln0.setting);
  CHECK(ln0.setting->num_of_sgs == 2);
  CHECK(ln0.setting->act_sg == 1);

  const auto& ds = ln0.data_sets.at(0);
  CHECK(ds.members.at(0).do_name == "PhV.phsA");
  CHECK(ds.members.at(0).da_name == "cVal.mag.f");
  CHECK(ds.members.at(2).ix == 2U);

  const auto* ptoc = ld->find_ln("PTOC1");
  REQUIRE(ptoc != nullptr);
  const auto& vals = ptoc->data.at(0).sub_instances.at(0).attributes.at(0).values;
  REQUIRE(vals.size() == 2);
  CHECK(vals[0].sgroup == 1U);
  CHECK(vals[1].text == "150.5");

  const auto* wye = doc.templates.find_do_type("WYE_2");
  REQUIRE(wye != nullptr);
  CHECK(wye->sub_data_objects[0].position == 0);
  CHECK(wye->attributes[0].position == 1);
  CHECK(wye->sub_data_objects[1].position == 2);
}

TEST_CASE("Ed.2.1 SCD with two IEDs", "[scl]") {
  const auto doc = load_data("station.scd");
  CHECK(doc.edition == model::edition::ed2_1);
  CHECK(doc.release == 4U);
  REQUIRE(doc.ieds.size() == 2);
  CHECK(doc.comm.sub_networks.size() == 2);

  const auto* ied2 = doc.find_ied("IED2");
  REQUIRE(ied2 != nullptr);
  REQUIRE(ied2->access_points.size() == 2);
  CHECK(ied2->access_points[1].server_at == "S1");
  CHECK_FALSE(ied2->access_points[1].srv.has_value());
  CHECK(ied2->find_server("S2") == ied2->find_server("S1"));
  CHECK(ied2->find_server("S3") == nullptr);
  CHECK(doc.comm.find("IED2", "S2") == &doc.comm.sub_networks[1].connected_aps[0]);
}

TEST_CASE("Loading from a string and from a missing file", "[scl]") {
  const auto ok = scl::load_string(R"(<SCL><Header id="x"/></SCL>)");
  REQUIRE(ok.ok());
  CHECK(ok.diags.empty());
  CHECK(ok.doc->edition == model::edition::ed1);
  CHECK(ok.doc->ieds.empty());

  const auto missing = scl::load_file(scl_test::data_path("does_not_exist.scd"));
  CHECK_FALSE(missing.ok());
  CHECK(missing.diags.count(scl::diagnostic_code::not_found) == 1);

  scl::load_options small;
  small.max_input_size = 10;
  const auto big = scl::load_string(R"(<SCL><Header id="x"/></SCL>)", small);
  CHECK(big.doc.error() == openiec61850::errc::length_overflow);
}
