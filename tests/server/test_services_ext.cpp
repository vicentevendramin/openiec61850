// Setting groups, logs, files and GoCBs: the server against our client.

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

#include <asio/io_context.hpp>

#include "../../src/server/detail.hpp"
#include "openiec61850/server/scl_model.hpp"
#include "server_test_util.hpp"

using namespace server_test;
using asio::awaitable;
using model::trigger;

namespace {

namespace assoc = openiec61850::association;

// IED1LD0:
//   LLN0   SGCB (3 groups, active 1), Mod.stVal [ST], log EventLog, lcb01 (DSLOG -> EventLog),
//          gcb01 (DSLOG), urcb01 (DSSG)
//   PTOC1  StrVal.setMag.f [SG] = 1 / 2 / 3 per group, Op.general [ST]
//   GGIO1  Ind1{stVal [ST], q, t}
srv::data_model make_ext_model(std::uint16_t resv_tms = 0) {
  using model::basic_type;
  using model::fc;
  srv::model_builder b;
  auto ld = b.logical_device("IED1LD0");
  auto lln0 = ld.logical_node("LLN0");
  lln0.data_object("Mod").attribute("stVal", fc::ST, basic_type::enumerated,
                                    srv::attribute_options{}.with_value(mms::data::integer(1)));
  auto ptoc = ld.logical_node("PTOC1");
  ptoc.data_object("StrVal")
      .structure("setMag", fc::SG)
      .attribute("f", basic_type::float32, srv::attribute_options{}.with_triggers(srv::on_dchg))
      .group_value(1, mms::data::floating_point(1.0F))
      .group_value(2, mms::data::floating_point(2.0F))
      .group_value(3, mms::data::floating_point(3.0F));
  ptoc.data_object("Op").attribute("general", fc::ST, basic_type::boolean);
  auto ggio = ld.logical_node("GGIO1");
  auto ind = ggio.data_object("Ind1");
  ind.attribute("stVal", fc::ST, basic_type::boolean, srv::attribute_options{}.with_triggers(srv::on_dchg));
  ind.attribute("q", fc::ST, basic_type::quality, srv::attribute_options{}.with_triggers(srv::on_qchg));
  ind.attribute("t", fc::ST, basic_type::timestamp);

  srv::setting_group_settings sg;
  sg.num_of_sgs = 3;
  sg.act_sg = 1;
  sg.resv_tms = resv_tms;
  lln0.setting_group_control(sg);
  lln0.data_set("DSLOG", {oref("IED1LD0/GGIO1.Ind1.stVal[ST]")});
  lln0.data_set("DSSG", {oref("IED1LD0/PTOC1.StrVal.setMag.f[SG]")});
  lln0.log("EventLog");
  srv::log_control_settings lc;
  lc.name = "lcb01";
  lc.data_set = "DSLOG";
  lc.log_name = "EventLog";
  lc.log_ena = true;
  lc.trg_ops = model::trigger_conditions::of({trigger::data_change, trigger::integrity});
  lln0.log_control(lc);
  srv::goose_control_settings gc;
  gc.name = "gcb01";
  gc.go_id = "GO1";
  gc.data_set = "DSLOG";
  gc.app_id = 0x1000;
  gc.min_time = 4;
  gc.max_time = 1000;
  lln0.goose_control(gc);
  srv::report_control_settings rc;
  rc.name = "urcb01";
  rc.data_set = "DSSG";
  rc.trg_ops = model::trigger_conditions::of({trigger::data_change});
  lln0.report_control(rc);
  auto m = b.build();
  REQUIRE(m);
  return std::move(*m);
}

srv::server start_ext(asio::any_io_executor ex, srv::server_options o = {}, std::uint16_t resv_tms = 0) {
  o.association.transport.handshake_timeout = 2s;
  o.association.association_timeout = 2s;
  auto s = srv::server::start(std::move(ex), make_ext_model(resv_tms), loopback, std::move(o));
  REQUIRE(s);
  return std::move(*s);
}

const char* const set_mag = "IED1LD0/PTOC1.StrVal.setMag.f[SG]";
const char* const set_mag_se = "IED1LD0/PTOC1.StrVal.setMag.f[SE]";

asio::awaitable<mms::data> read_ok(client::client& c, const char* ref) {
  auto r = co_await c.read(oref(ref));
  REQUIRE(r);
  co_return std::move(*r);
}

}  // namespace

TEST_CASE("Setting groups: activation, edit buffer and reservation", "[server][sg]") {
  run([]() -> awaitable<void> {
    std::vector<srv::setting_group_event> events;
    srv::server_options o;
    o.on_setting_group = [&](const srv::setting_group_event& e) -> std::optional<mms::data_access_error> {
      events.push_back(e);
      return std::nullopt;
    };
    auto s = start_ext(co_await asio::this_coro::executor, o);
    auto c = co_await connect(options_for(s));

    auto v = co_await c.get_sgcb_values("IED1LD0");
    REQUIRE(v);
    CHECK(v->num_of_sgs == 3);
    CHECK(v->act_sg == 1);
    CHECK(v->edit_sg == 0);
    CHECK_FALSE(v->cnf_edit);
    CHECK(v->resv_tms == 0);
    CHECK(co_await read_ok(c, set_mag) == mms::data::floating_point(1.0F));
    auto lnd = co_await c.get_logical_node_directory(oref("IED1LD0/LLN0"));
    REQUIRE(lnd);
    CHECK(lnd->sgcb);
    CHECK(lnd->lcbs == std::vector<std::string>{"lcb01"});
    CHECK(lnd->gocbs == std::vector<std::string>{"gcb01"});

    // Activation switches the SG values and reports the change.
    auto en = co_await c.enable_reporting(oref("IED1LD0/LLN0.urcb01[RP]"));
    REQUIRE(en);
    auto act = co_await c.select_active_sg("IED1LD0", 2);
    CHECK(act);
    CHECK(co_await read_ok(c, set_mag) == mms::data::floating_point(2.0F));
    auto rpt = co_await next_report(c);
    REQUIRE(rpt.entries.size() == 1);
    CHECK(rpt.entries[0].value == mms::data::floating_point(2.0F));
    v = co_await c.get_sgcb_values("IED1LD0");
    REQUIRE(v);
    CHECK(v->act_sg == 2);
    REQUIRE(v->lact_tm);
    auto bad = co_await c.select_active_sg("IED1LD0", 4);
    CHECK(bad.error() == client::errc::value_invalid);
    REQUIRE(events.size() == 1);
    CHECK(events[0].action == srv::setting_group_action::select_active);
    CHECK(events[0].group == 2);
    CHECK(events[0].logical_device == "IED1LD0");

    // The edit buffer needs SelectEditSG, and belongs to one association.
    auto no_edit = co_await c.set_edit_sg_value(oref(set_mag_se), mms::data::floating_point(9.0F));
    CHECK(no_edit.error() == client::errc::temporarily_unavailable);
    auto misuse = co_await c.set_edit_sg_value(oref(set_mag), mms::data::floating_point(9.0F));
    CHECK(misuse.error() == openiec61850::errc::invalid_state);
    auto sel = co_await c.select_edit_sg("IED1LD0", 3);
    CHECK(sel);
    auto edit = co_await c.get_edit_sg_value(oref(set_mag_se));
    REQUIRE(edit);
    CHECK(*edit == mms::data::floating_point(3.0F));
    auto set = co_await c.set_edit_sg_value(oref(set_mag_se), mms::data::floating_point(3.5F));
    CHECK(set);
    CHECK(co_await read_ok(c, set_mag_se) == mms::data::floating_point(3.5F));
    CHECK(co_await read_ok(c, set_mag) == mms::data::floating_point(2.0F));  // not confirmed

    auto other = co_await connect(options_for(s));
    auto busy = co_await other.select_edit_sg("IED1LD0", 1);
    CHECK(busy.error() == client::errc::temporarily_unavailable);
    auto denied = co_await other.set_edit_sg_value(oref(set_mag_se), mms::data::floating_point(0.0F));
    CHECK(denied.error() == client::errc::access_denied);
    auto denied_cnf = co_await other.confirm_edit_sg_values("IED1LD0");
    CHECK(denied_cnf.error() == client::errc::access_denied);

    auto cnf = co_await c.confirm_edit_sg_values("IED1LD0");
    CHECK(cnf);
    auto stored = co_await s.read_setting_group(oref(set_mag), 3);
    REQUIRE(stored);
    CHECK(*stored == mms::data::floating_point(3.5F));
    auto g2 = co_await s.read_setting_group(oref(set_mag), 2);
    REQUIRE(g2);
    CHECK(*g2 == mms::data::floating_point(2.0F));
    auto act3 = co_await c.select_active_sg("IED1LD0", 3);
    CHECK(act3);
    CHECK(co_await read_ok(c, set_mag) == mms::data::floating_point(3.5F));
    (void)co_await next_report(c);

    // Confirming the active group changes the SG values at once.
    auto set2 = co_await c.set_edit_sg_value(oref(set_mag_se), mms::data::floating_point(4.0F));
    CHECK(set2);
    auto cnf2 = co_await c.confirm_edit_sg_values("IED1LD0");
    CHECK(cnf2);
    CHECK(co_await read_ok(c, set_mag) == mms::data::floating_point(4.0F));
    auto rpt2 = co_await next_report(c);
    CHECK(rpt2.entries[0].value == mms::data::floating_point(4.0F));

    // Read-only attributes; a released edit buffer is free for another association.
    auto ro = co_await c.write(oref("IED1LD0/LLN0.SGCB.NumOfSG[SP]"), mms::data::unsigned_integer(5));
    CHECK(ro.error() == client::errc::access_denied);
    auto rel = co_await c.select_edit_sg("IED1LD0", 0);
    CHECK(rel);
    auto taken = co_await other.select_edit_sg("IED1LD0", 1);
    CHECK(taken);
    // Closing the association releases it too.
    auto closed = co_await other.release();
    CHECK(closed);
    co_await sleep(100ms);
    v = co_await c.get_sgcb_values("IED1LD0");
    REQUIRE(v);
    CHECK(v->edit_sg == 0);

    // Local activation; the application cannot write SG / SE values directly.
    CHECK(s.select_active_setting_group("IED1LD0", 1));
    CHECK(s.select_active_setting_group("IED1LD0", 9).error() == openiec61850::errc::value_out_of_range);
    CHECK(s.select_active_setting_group("NOPE", 1).error() == srv::errc::object_not_found);
    CHECK(s.update(oref(set_mag_se), mms::data::floating_point(1.0F)).error() == srv::errc::access_denied);
    co_await sleep(50ms);
    CHECK(co_await read_ok(c, set_mag) == mms::data::floating_point(1.0F));
    s.stop();
  });
}

TEST_CASE("Setting groups: Ed.2 ResvTms ends an idle edit reservation", "[server][sg]") {
  run([]() -> awaitable<void> {
    auto s = start_ext(co_await asio::this_coro::executor, {}, 1);
    auto c = co_await connect(options_for(s));
    auto sel = co_await c.select_edit_sg("IED1LD0", 2);
    CHECK(sel);
    auto v = co_await c.get_sgcb_values("IED1LD0");
    REQUIRE(v);
    CHECK(v->edit_sg == 2);
    CHECK(v->resv_tms == 1);
    co_await sleep(1300ms);
    v = co_await c.get_sgcb_values("IED1LD0");
    REQUIRE(v);
    CHECK(v->edit_sg == 0);
    s.stop();
  });
}

TEST_CASE("Logs: LCB attributes, logging and journal queries", "[server][log]") {
  run([]() -> awaitable<void> {
    srv::server_options o;
    o.log_capacity = 5;
    auto s = start_ext(co_await asio::this_coro::executor, o);
    auto c = co_await connect(options_for(s));
    const auto log = oref("IED1LD0/LLN0.EventLog");
    const auto lcb = oref("IED1LD0/LLN0.lcb01[LG]");

    auto journals = co_await c.get_name_list(mms::object_class::journal, "IED1LD0");
    REQUIRE(journals);
    CHECK(*journals == std::vector<std::string>{"LLN0$EventLog"});

    auto empty = co_await c.query_log_by_time(log, std::nullopt, std::nullopt);
    REQUIRE(empty);
    CHECK(empty->empty());

    REQUIRE(s.update(oref("IED1LD0/GGIO1.Ind1.stVal[ST]"), mms::data::boolean(true)));
    REQUIRE(s.update(oref("IED1LD0/GGIO1.Ind1.stVal[ST]"), mms::data::boolean(true)));  // no dchg
    REQUIRE(s.update(oref("IED1LD0/GGIO1.Ind1.stVal[ST]"), mms::data::boolean(false)));
    co_await sleep(50ms);
    auto all = co_await c.query_log_by_time(log, std::nullopt, std::nullopt);
    REQUIRE(all);
    REQUIRE(all->size() == 2);
    REQUIRE((*all)[0].data.size() == 1);
    CHECK((*all)[0].data[0].reference == "IED1LD0/GGIO1$ST$Ind1$stVal");
    CHECK((*all)[0].data[0].value == mms::data::boolean(true));
    CHECK((*all)[0].data[0].reason == model::trigger_conditions::of({trigger::data_change}));
    CHECK((*all)[1].data[0].value == mms::data::boolean(false));

    auto values = co_await c.get_lcb_values(lcb);
    REQUIRE(values);
    CHECK(values->log_ena == true);
    CHECK(values->log_ref == "IED1LD0/LLN0$EventLog");
    CHECK(values->dat_set == "IED1LD0/LLN0$DSLOG");
    CHECK(values->old_ent == (*all)[0].entry_id);
    CHECK(values->new_ent == (*all)[1].entry_id);
    CHECK(values->new_entr_tm == (*all)[1].time);
    CHECK(values->trg_ops == model::trigger_conditions::of({trigger::data_change, trigger::integrity}));
    CHECK(values->intg_pd == 0U);

    auto after = co_await c.query_log_after(log, (*all)[0].time, (*all)[0].entry_id);
    REQUIRE(after);
    REQUIRE(after->size() == 1);
    CHECK(after->front().entry_id == (*all)[1].entry_id);
    auto by_time = co_await c.query_log_by_time(log, (*all)[1].time, std::nullopt);
    REQUIRE(by_time);
    CHECK(!by_time->empty());
    auto status = co_await c.get_log_status(log);
    REQUIRE(status);
    CHECK(*status == 2U);

    // The log is bounded: the oldest entries are dropped.
    for (int i = 0; i < 8; ++i) {
      REQUIRE(s.update(oref("IED1LD0/GGIO1.Ind1.stVal[ST]"), mms::data::boolean(i % 2 == 0)));
    }
    co_await sleep(50ms);
    auto bounded = co_await c.query_log_by_time(log, std::nullopt, std::nullopt);
    REQUIRE(bounded);
    CHECK(bounded->size() == 5);

    // Disabled: nothing more is logged; the configuration is locked while enabled.
    client::lcb_settings w;
    w.intg_pd = 1000;
    w.log_ena = false;
    auto off = co_await c.set_lcb_values(lcb, w);
    CHECK(off);
    REQUIRE(s.update(oref("IED1LD0/GGIO1.Ind1.stVal[ST]"), mms::data::boolean(true)));
    co_await sleep(50ms);
    auto st2 = co_await c.get_log_status(log);
    REQUIRE(st2);
    CHECK(*st2 == 5U);
    client::lcb_settings ds;
    ds.dat_set = oref("IED1LD0/LLN0.DSSG");
    auto changed = co_await c.set_lcb_values(lcb, ds);
    CHECK(changed);
    client::lcb_settings on;
    on.log_ena = true;
    auto enabled = co_await c.set_lcb_values(lcb, on);
    CHECK(enabled);
    auto locked = co_await c.set_lcb_values(lcb, ds);
    CHECK(locked.error() == client::errc::temporarily_unavailable);
    auto ro = co_await c.write(oref("IED1LD0/LLN0.lcb01.LogRef[LG]"), mms::data::visible_string("x"));
    CHECK(ro.error() == client::errc::access_denied);

    // Integrity period: entries with every member.
    client::lcb_settings intg;
    intg.intg_pd = 100;
    auto ip = co_await c.set_lcb_values(lcb, intg);
    CHECK(ip);
    co_await sleep(350ms);
    auto periodic = co_await c.query_log_by_time(log, std::nullopt, std::nullopt);
    REQUIRE(periodic);
    REQUIRE(!periodic->empty());
    CHECK(periodic->back().data[0].reference == "IED1LD0/PTOC1$SG$StrVal$setMag$f");
    CHECK(periodic->back().data[0].reason == model::trigger_conditions::of({trigger::integrity}));

    auto missing = co_await c.query_log_by_time(oref("IED1LD0/LLN0.NoLog"), std::nullopt, std::nullopt);
    CHECK(missing.error() == client::errc::object_not_found);
    s.stop();
  });
}

TEST_CASE("Logs: continuation with moreFollows and InitializeJournal", "[server][log]") {
  run([]() -> awaitable<void> {
    auto s = start_ext(co_await asio::this_coro::executor);
    auto o = options_for(s);
    o.association.initiate.local_detail_calling = 400;  // small PDUs: several pages
    auto c = co_await connect(o);
    for (int i = 0; i < 30; ++i) {
      REQUIRE(s.update(oref("IED1LD0/GGIO1.Ind1.stVal[ST]"), mms::data::boolean(i % 2 == 0)));
    }
    co_await sleep(100ms);
    const auto log = oref("IED1LD0/LLN0.EventLog");
    auto all = co_await c.query_log_by_time(log, std::nullopt, std::nullopt);
    REQUIRE(all);
    CHECK(all->size() == 30);
    for (std::size_t i = 1; i < all->size(); ++i) CHECK((*all)[i].entry_id != (*all)[i - 1].entry_id);

    s.stop();
  });
}

TEST_CASE("Files: directory, chunked download, delete, rename, traversal", "[server][files]") {
  run([]() -> awaitable<void> {
    auto store = std::make_shared<srv::memory_file_store>();
    openiec61850::byte_buffer big(200000);
    for (std::size_t i = 0; i < big.size(); ++i) big[i] = static_cast<std::uint8_t>(i * 7);
    REQUIRE(store->put("COMTRADE/fault1.cfg", {'c', 'f', 'g'}));
    REQUIRE(store->put("COMTRADE/fault1.dat", big));
    REQUIRE(store->put("readme.txt", {'h', 'i'}, std::chrono::system_clock::time_point{std::chrono::seconds{1700000000}}));
    srv::server_options o;
    o.files = store;
    auto s = start_ext(co_await asio::this_coro::executor, o);
    auto c = co_await connect(options_for(s));

    auto dir = co_await c.get_file_directory();
    REQUIRE(dir);
    REQUIRE(dir->size() == 3);
    CHECK((*dir)[0].name == "COMTRADE/fault1.cfg");
    CHECK((*dir)[1].size == 200000U);
    CHECK((*dir)[2].name == "readme.txt");
    REQUIRE((*dir)[2].last_modified);
    CHECK(*(*dir)[2].last_modified == std::chrono::system_clock::time_point{std::chrono::seconds{1700000000}});
    auto sub = co_await c.get_file_directory("COMTRADE");
    REQUIRE(sub);
    CHECK(sub->size() == 2);
    auto star = co_await c.get_file_directory("COMTRADE/*");
    REQUIRE(star);
    CHECK(star->size() == 2);

    auto small = co_await c.get_file("readme.txt");
    REQUIRE(small);
    CHECK(*small == openiec61850::byte_buffer{'h', 'i'});
    std::size_t chunks = 0;
    openiec61850::byte_buffer streamed;
    auto n = co_await c.get_file("/COMTRADE/fault1.dat", [&](openiec61850::byte_buffer b) {
      ++chunks;
      streamed.insert(streamed.end(), b.begin(), b.end());
    });
    REQUIRE(n);
    CHECK(*n == 200000U);
    CHECK(chunks > 1);
    CHECK(streamed == big);

    client::error_details d;
    auto missing = co_await c.get_file("nope.txt", d);
    CHECK(missing.error() == assoc::errc::service_error);
    REQUIRE(d.service_error);
    CHECK(d.service_error->cls == mms::error_class::file);
    CHECK(d.service_error->code == mms::error_code::file::file_non_existent);
    for (const char* bad : {"../etc/passwd", "COMTRADE/../../x", "a\\b", "./readme.txt"}) {
      auto t = co_await c.get_file(bad, d);
      CHECK_FALSE(t);
      REQUIRE(d.service_error);
      CHECK(d.service_error->code == mms::error_code::file::filename_syntax_error);
    }

    auto ren = co_await c.rename_file("readme.txt", "README");
    CHECK(ren);
    auto dup = co_await c.rename_file("README", "COMTRADE/fault1.cfg", d);
    CHECK_FALSE(dup);
    CHECK(d.service_error->code == mms::error_code::file::duplicate_filename);
    auto del = co_await c.delete_file("README");
    CHECK(del);
    CHECK_FALSE(store->get("README"));
    auto del2 = co_await c.delete_file("README", d);
    CHECK_FALSE(del2);
    CHECK(d.service_error->code == mms::error_code::file::file_non_existent);

    // Paging of the directory with a small PDU size.
    for (int i = 0; i < 40; ++i) REQUIRE(store->put("many/file" + std::to_string(100 + i) + ".txt", {}));
    auto po = options_for(s);
    po.association.initiate.local_detail_calling = 300;
    auto pc = co_await connect(po);
    auto many = co_await pc.get_file_directory("many");
    REQUIRE(many);
    CHECK(many->size() == 40);
    auto chunked = co_await pc.get_file("COMTRADE/fault1.dat");
    REQUIRE(chunked);
    CHECK(*chunked == big);
    s.stop();
  });
}

TEST_CASE("Files: no store configured", "[server][files]") {
  run([]() -> awaitable<void> {
    auto s = start_ext(co_await asio::this_coro::executor);
    auto c = co_await connect(options_for(s));
    auto dir = co_await c.get_file_directory();
    CHECK(dir.error() == assoc::errc::request_rejected);
    s.stop();
  });
}

TEST_CASE("Files: directory store stays inside its root", "[server][files]") {
  namespace fs = std::filesystem;
  const auto base = fs::temp_directory_path() / ("oiec_files_" + std::to_string(::getpid()));
  fs::remove_all(base);
  fs::create_directories(base / "root" / "sub");
  { std::ofstream(base / "root" / "sub" / "a.txt") << "hello"; }
  { std::ofstream(base / "secret.txt") << "secret"; }
  std::error_code ec;
  fs::create_symlink(base / "secret.txt", base / "root" / "link.txt", ec);
  const bool links = !ec;

  auto store = srv::directory_file_store::open(base / "root");
  REQUIRE(store);
  auto list = (*store)->list("");
  REQUIRE(list);
  REQUIRE(list->size() == 1);  // the escaping link is not listed
  CHECK((*list)[0].name == "sub/a.txt");
  CHECK((*list)[0].size == 5U);
  std::array<std::uint8_t, 16> buf{};
  auto n = (*store)->read("sub/a.txt", 1, buf);
  REQUIRE(n);
  CHECK(*n == 4U);
  CHECK((*store)->read("../secret.txt", 0, buf).error() == srv::file_errc::invalid_name);
  if (links) CHECK((*store)->read("link.txt", 0, buf).error() == srv::file_errc::access_denied);
  CHECK((*store)->stat("sub").error() == srv::file_errc::access_denied);  // a directory
  CHECK((*store)->stat("nope").error() == srv::file_errc::not_found);
  CHECK((*store)->rename("sub/a.txt", "../out.txt").error() == srv::file_errc::invalid_name);
  CHECK((*store)->rename("sub/a.txt", "b.txt"));
  CHECK(fs::exists(base / "root" / "b.txt"));
  CHECK((*store)->remove("b.txt"));
  CHECK_FALSE(fs::exists(base / "root" / "b.txt"));
  CHECK(fs::exists(base / "secret.txt"));
  CHECK_FALSE(srv::directory_file_store::open(base / "missing"));
  fs::remove_all(base);

  CHECK(*srv::normalize_file_path("/a/b/") == "a/b");
  CHECK(srv::normalize_file_path("")->empty());
  CHECK_FALSE(srv::normalize_file_path("a//b"));
  CHECK_FALSE(srv::normalize_file_path("C:x"));
}

TEST_CASE("GoCB: attributes, writes and change callback", "[server][goose]") {
  run([]() -> awaitable<void> {
    std::vector<srv::goose_control_event> events;
    srv::server_options o;
    o.on_goose_control = [&](const srv::goose_control_event& e) { events.push_back(e); };
    auto s = start_ext(co_await asio::this_coro::executor, o);
    auto c = co_await connect(options_for(s));
    const auto gcb = oref("IED1LD0/LLN0.gcb01[GO]");

    auto v = co_await c.get_gocb_values(gcb);
    REQUIRE(v);
    CHECK(v->go_ena == false);
    CHECK(v->go_id == "GO1");
    CHECK(v->dat_set == "IED1LD0/LLN0$DSLOG");
    CHECK(v->conf_rev == 1U);
    CHECK(v->nds_com == false);
    REQUIRE(v->dst_address);
    CHECK(v->dst_address->mac == openiec61850::byte_buffer{0x01, 0x0C, 0xCD, 0x01, 0x00, 0x00});
    CHECK(v->dst_address->app_id == 0x1000);
    CHECK(v->dst_address->priority == 4);
    CHECK(v->min_time == 4U);
    CHECK(v->max_time == 1000U);
    CHECK(v->fixed_offs == false);

    client::gocb_settings w;
    w.go_id = "GO2";
    w.dat_set = oref("IED1LD0/LLN0.DSSG");
    w.go_ena = true;
    auto set = co_await c.set_gocb_values(gcb, w);
    CHECK(set);
    REQUIRE(events.size() == 3);
    CHECK(events.back().state.go_ena);
    CHECK(events.back().state.go_id == "GO2");
    CHECK(events.back().state.conf_rev == 2U);
    REQUIRE(events.back().state.members.size() == 1);
    CHECK(events.back().state.members[0] == oref(set_mag));

    client::gocb_settings locked;
    locked.go_id = "GO3";
    auto busy = co_await c.set_gocb_values(gcb, locked);
    CHECK(busy.error() == client::errc::temporarily_unavailable);
    auto ro = co_await c.write(oref("IED1LD0/LLN0.gcb01.ConfRev[GO]"), mms::data::unsigned_integer(9));
    CHECK(ro.error() == client::errc::access_denied);

    auto st = co_await s.goose_control(gcb);
    REQUIRE(st);
    CHECK(st->go_ena);
    CHECK(st->app_id == 0x1000);
    auto all = co_await s.goose_controls();
    CHECK(all.size() == 1);
    // Local misuse is caught before any request.
    auto wrong_fc = co_await c.get_gocb_values(oref("IED1LD0/LLN0.gcb01[LG]"));
    CHECK(wrong_fc.error() == openiec61850::errc::invalid_state);
    auto wrong_lcb = co_await c.get_lcb_values(oref("IED1LD0/LLN0.gcb01[GO]"));
    CHECK(wrong_lcb.error() == openiec61850::errc::invalid_state);
    auto wrong_log = co_await c.get_log_status(oref("IED1LD0/LLN0.a.b"));
    CHECK(wrong_log.error() == openiec61850::errc::invalid_state);
    auto no_name = co_await c.get_file("");
    CHECK(no_name.error() == openiec61850::errc::invalid_state);
    auto none = co_await s.goose_control(oref("IED1LD0/LLN0.nope[GO]"));
    CHECK(none.error() == srv::errc::object_not_found);
    s.stop();
  });
}

TEST_CASE("SCL model: setting groups, log and GOOSE control blocks", "[server][scl]") {
  run([]() -> awaitable<void> {
    const auto dir = std::filesystem::path(__FILE__).parent_path().parent_path() / "scl" / "data";
    auto m = srv::load_model_file(dir / "ed2_bay.cid", "BAY1");
    REQUIRE(m);
    REQUIRE(m->setting_group_controls().size() == 1);
    CHECK(m->setting_group_controls()[0].settings.num_of_sgs == 2);
    REQUIRE(m->log_controls().size() == 1);
    CHECK(m->log_controls()[0].settings.log_name == "Bay1Log");
    CHECK(m->logs().size() == 1);
    auto s = srv::server::start(co_await asio::this_coro::executor, std::move(*m), loopback);
    REQUIRE(s);
    auto g2 = co_await s->read_setting_group(oref("Bay1Prot/PTOC1.StrVal.setMag.f[SG]"), 2);
    REQUIRE(g2);
    CHECK(*g2 == mms::data::floating_point(150.5F));
    auto c = co_await connect(options_for(*s));
    auto se = co_await c.read(oref("Bay1Prot/PTOC1.StrVal.setMag.f[SE]"));
    REQUIRE(se);
    CHECK(*se == mms::data::floating_point(100.0F));
    s->stop();

    auto ed1 = srv::load_model_file(dir / "ed1_relay.icd", "TEMPLATE");
    REQUIRE(ed1);
    REQUIRE(ed1->goose_controls().size() == 1);
    const auto& gc = ed1->goose_controls()[0].settings;
    CHECK(gc.name == "gcbPos");
    CHECK(gc.go_id == "TEMPLATE_GOOSE");
    CHECK(gc.app_id == 1);
    CHECK(gc.dst_mac == std::array<std::uint8_t, 6>{0x01, 0x0C, 0xCD, 0x01, 0x00, 0x01});
    CHECK(gc.max_time == 1000U);
  });
}

TEST_CASE("Logs: InitializeJournal and ReportJournalStatus on the dispatcher", "[server][log]") {
  namespace detail = openiec61850::server::detail;
  asio::io_context ctx;
  auto st = detail::make_offline_state(ctx.get_executor(), make_ext_model(), {});
  REQUIRE(st);
  detail::session s((*st)->strand);
  s.id = 1;
  const auto holder = (*st)->model.find(oref("IED1LD0/GGIO1.Ind1.stVal[ST]"));
  REQUIRE(holder);
  for (int i = 0; i < 4; ++i) {
    std::vector<detail::assignment> plan;
    plan.push_back({*holder, {}, mms::data::boolean(i % 2 == 0)});
    (*st)->apply(std::move(plan));
  }
  const auto journal = mms::object_name::domain("IED1LD0", "LLN0$EventLog");
  auto status = [&] {
    detail::reply out;
    (*st)->dispatch(s, mms::report_journal_status_request{journal}, out);
    REQUIRE(out.type == detail::reply::kind::response);
    return std::get<mms::report_journal_status_response>(out.response).current_entries;
  };
  CHECK(status() == 4U);

  // Delete up to the second entry (limitingEntry), then everything.
  std::array<std::uint8_t, 8> second{};
  {
    detail::reply out;
    (*st)->dispatch(s, mms::read_journal_request{journal, {}, {}, {}, 2, {}, {}}, out);
    REQUIRE(out.type == detail::reply::kind::response);
    const auto& rj = std::get<mms::read_journal_response>(out.response);
    std::vector<mms::journal_entry> entries(rj.entries.begin(), rj.entries.end());
    REQUIRE(entries.size() == 2);
    std::copy(entries[1].entry_id.begin(), entries[1].entry_id.end(), second.begin());
    CHECK_FALSE(rj.more_follows);
  }
  {
    mms::initialize_journal_request req{journal, mms::binary_time{86'399'999, std::uint16_t{65535}},
                                        openiec61850::byte_view{second}};
    detail::reply out;
    (*st)->dispatch(s, req, out);
    REQUIRE(out.type == detail::reply::kind::response);
    CHECK(std::get<mms::initialize_journal_response>(out.response).deleted == 2U);
  }
  CHECK(status() == 2U);
  {
    detail::reply out;
    (*st)->dispatch(s, mms::initialize_journal_request{journal, {}, {}}, out);
    CHECK(std::get<mms::initialize_journal_response>(out.response).deleted == 2U);
  }
  CHECK(status() == 0U);
  detail::reply missing;
  (*st)->dispatch(s, mms::report_journal_status_request{mms::object_name::domain("IED1LD0", "X")}, missing);
  CHECK(missing.type == detail::reply::kind::error);
  (*st)->shutdown();
  ctx.poll();
}
