#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <optional>
#include <string>
#include <vector>

#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>

#include "client_test_util.hpp"

namespace client = openiec61850::client;
namespace mms = openiec61850::mms;
namespace model = openiec61850::model;
namespace testing = openiec61850::testing;
using asio::awaitable;
using client_test::connect;
using client_test::options_for;
using client_test::ref;
using client_test::run;
using namespace std::chrono_literals;
using model::optional_field;
using kind = client::connection_event::kind;

// Note: GCC evaluates a co_await inside a Catch2 assertion macro twice, so results are always
// stored in a variable before being checked.

namespace {

const char* const brcb_text = "IED1LD0/LLN0.brcb01[BR]";
const char* const urcb_text = "IED1LD0/LLN0.urcb01[RP]";

// TotW (a structure mag{f}, q, t) -> mag.f
float totw_mag(const mms::data& totw) {
  return client::to_float(client::component(client::component(totw, 0).value(), 0).value()).value();
}

std::ptrdiff_t position(const std::vector<std::string>& log, std::string_view item) {
  const auto it = std::find(log.begin(), log.end(), item);
  return it == log.end() ? -1 : it - log.begin();
}

awaitable<client::connection_event> wait_event(client::client& c, kind k) {
  for (;;) {
    auto e = co_await c.next_event();
    REQUIRE(e);
    if (e->type == k) co_return std::move(*e);
  }
}

}  // namespace

TEST_CASE("RCB attributes are read and written", "[client]") {
  run([]() -> awaitable<void> {
    testing::fake_server server(co_await asio::this_coro::executor);
    REQUIRE(server.start());
    auto c = co_await connect(options_for(server));

    auto b = co_await c.get_rcb_values(ref(brcb_text));
    REQUIRE(b);
    CHECK(b->rpt_id == "brcb01-id");
    CHECK(b->rpt_ena == false);
    CHECK(b->dat_set == "IED1LD0/LLN0$DS1");
    CHECK(b->data_set() == ref("IED1LD0/LLN0.DS1"));
    CHECK(b->conf_rev == 1U);
    CHECK(b->trg_ops->data_change());
    CHECK(b->entry_id->is_zero());
    CHECK(b->time_of_entry);
    CHECK(b->resv_tms == 0);
    CHECK(!b->resv);

    auto u = co_await c.get_rcb_values(ref(urcb_text));
    REQUIRE(u);
    CHECK(u->rpt_id == "");
    CHECK(u->resv == false);
    CHECK(!u->entry_id);
    CHECK(!u->purge_buf);

    client::rcb_settings w;
    w.rpt_id = "u1";
    w.intg_pd = 1000;
    w.trg_ops = model::trigger_conditions::of({model::trigger::integrity});
    auto set = co_await c.set_rcb_values(ref(urcb_text), w);
    CHECK(set);
    CHECK(server.value("IED1LD0", "LLN0$RP$urcb01$RptID") == mms::data::visible_string("u1"));
    CHECK(server.value("IED1LD0", "LLN0$RP$urcb01$IntgPd") == mms::data::unsigned_integer(1000));
    CHECK(server.value("IED1LD0", "LLN0$RP$urcb01$Resv") == mms::data::boolean(true));

    // Another client cannot touch the reserved URCB.
    auto other = co_await connect(options_for(server));
    client::rcb_settings w2;
    w2.rpt_id = "mine";
    auto denied = co_await other.set_rcb_values(ref(urcb_text), w2);
    CHECK(denied.error() == client::errc::access_denied);

    auto not_rcb = co_await c.get_rcb_values(ref("IED1LD0/MMXU1.TotW[MX]"));
    CHECK(not_rcb.error() == openiec61850::errc::invalid_state);
    auto missing = co_await c.get_rcb_values(ref("IED1LD0/LLN0.brcb99[BR]"));
    CHECK(missing.error() == client::errc::object_not_found);
  });
}

TEST_CASE("URCB reporting: enable, GI, data changes, disable", "[client]") {
  run([]() -> awaitable<void> {
    testing::fake_server server(co_await asio::this_coro::executor);
    REQUIRE(server.start());
    auto c = co_await connect(options_for(server));

    client::report_settings s;
    s.opt_flds = model::optional_fields::of(
        {optional_field::sequence_number, optional_field::reason_for_inclusion,
         optional_field::data_set_name, optional_field::conf_revision, optional_field::entry_id});
    s.general_interrogation = true;
    auto values = co_await c.enable_reporting(ref(urcb_text), s);
    REQUIRE(values);
    CHECK(values->dat_set == "IED1LD0/LLN0$DS1");
    CHECK(server.rcb_enabled("urcb01"));
    const auto& log = server.write_log();
    REQUIRE(log.size() == 4);
    CHECK(log[0] == "IED1LD0/LLN0$RP$urcb01$Resv");
    CHECK(log[1] == "IED1LD0/LLN0$RP$urcb01$OptFlds");
    CHECK(log[2] == "IED1LD0/LLN0$RP$urcb01$RptEna");
    CHECK(log[3] == "IED1LD0/LLN0$RP$urcb01$GI");
    // EntryID is not configurable on a URCB.
    const auto opt = model::optional_fields::from_mms(
        *server.value("IED1LD0", "LLN0$RP$urcb01$OptFlds"));
    CHECK(!opt->entry_id());

    auto gi = co_await c.next_report();
    REQUIRE(gi);
    CHECK(gi->rcb == ref(urcb_text));
    CHECK(gi->rpt_id == "IED1LD0/LLN0$RP$urcb01");  // empty RptID: the RCB reference
    CHECK(gi->seq_num == 0U);
    CHECK(gi->conf_rev == 1U);
    CHECK(gi->data_set == "IED1LD0/LLN0$DS1");
    CHECK(!gi->entry_id);
    REQUIRE(gi->entries.size() == 4);
    CHECK(gi->entries[0].reference == ref("IED1LD0/MMXU1.TotW[MX]"));
    CHECK(gi->entries[3].reference == ref("IED1LD0/MMXU1.PhV.phsA.cVal.mag.f[MX]"));
    CHECK(gi->entries[0].reason->general_interrogation());
    CHECK(totw_mag(gi->entries[0].value) == 1.5F);

    REQUIRE(server.update("MMXU1$MX$TotW$mag$f", mms::data::floating_point(2.5F)));
    auto change = co_await c.next_report();
    REQUIRE(change);
    CHECK(change->seq_num == 1U);
    CHECK(change->inclusion == std::vector<bool>{true, false, false, false});
    REQUIRE(change->entries.size() == 1);
    CHECK(change->entries[0].index == 0);
    CHECK(totw_mag(change->entries[0].value) == 2.5F);
    CHECK(change->entries[0].reason->data_change());

    model::quality q;
    q.set_validity(model::validity::invalid);
    REQUIRE(server.update("XCBR1$ST$Pos$q", q.to_mms(),
                          model::trigger_conditions::of({model::trigger::quality_change})));
    auto qchg = co_await c.next_report();
    REQUIRE(qchg);
    REQUIRE(qchg->entries.size() == 1);
    CHECK(qchg->entries[0].reference == ref("IED1LD0/XCBR1.Pos.q[ST]"));
    CHECK(client::to_quality(qchg->entries[0].value).value() == q);
    CHECK(qchg->entries[0].reason->quality_change());

    auto trig = co_await c.trigger_gi(ref(urcb_text));
    CHECK(trig);
    auto gi2 = co_await c.next_report();
    REQUIRE(gi2);
    CHECK(gi2->entries.size() == 4);
    CHECK(gi2->seq_num == 3U);

    // Configuration cannot change while enabled.
    client::rcb_settings w;
    w.intg_pd = 5;
    auto busy = co_await c.set_rcb_values(ref(urcb_text), w);
    CHECK(busy.error() == client::errc::temporarily_unavailable);

    auto disabled = co_await c.disable_reporting(ref(urcb_text));
    CHECK(disabled);
    CHECK(!server.rcb_enabled("urcb01"));
    CHECK(server.value("IED1LD0", "LLN0$RP$urcb01$Resv") == mms::data::boolean(false));
    CHECK(c.reports_dropped() == 0);
  });
}

TEST_CASE("report callback; malformed reports are counted", "[client]") {
  run([]() -> awaitable<void> {
    testing::fake_server server(co_await asio::this_coro::executor);
    REQUIRE(server.start());
    auto c = co_await connect(options_for(server));
    std::vector<client::report> got;
    c.set_report_handler([&](client::report r) { got.push_back(std::move(r)); });
    co_await client_test::yield();

    server.send_report({mms::data::visible_string("x")});  // no OptFlds
    server.send_report({mms::data::visible_string("raw"), model::optional_fields{}.to_mms(),
                        mms::data::bit_string(std::vector<std::uint8_t>{0x80}, 1),
                        mms::data::integer(42)});
    while (got.empty()) co_await client_test::yield();
    REQUIRE(got.size() == 1);
    CHECK(got[0].rpt_id == "raw");
    CHECK(!got[0].rcb);
    CHECK(got[0].lost_before == 1);
    CHECK(got[0].entries[0].value == mms::data::integer(42));
    CHECK(c.reports_dropped() == 1);

    // The callback is exclusive with next_report() only while set.
    c.set_report_handler({});
    server.send_report({mms::data::visible_string("queued"), model::optional_fields{}.to_mms(),
                        mms::data::bit_string(std::vector<std::uint8_t>{0x00}, 1)});
    auto queued = co_await c.next_report();
    REQUIRE(queued);
    CHECK(queued->rpt_id == "queued");
    CHECK(queued->entries.empty());
  });
}

TEST_CASE("BRCB recovery resumes from the last EntryID", "[client]") {
  run([]() -> awaitable<void> {
    testing::fake_server server(co_await asio::this_coro::executor);
    REQUIRE(server.start());
    auto o = options_for(server);
    o.recovery.enabled = true;
    o.recovery.backoff = {10ms};
    o.recovery.max_attempts = 50;
    auto c = co_await connect(o);

    client::report_settings s;
    s.opt_flds = model::optional_fields::of({optional_field::sequence_number,
                                             optional_field::entry_id,
                                             optional_field::reason_for_inclusion});
    auto enabled = co_await c.enable_reporting(ref(brcb_text), s);
    REQUIRE(enabled);
    CHECK(enabled->rpt_id == "brcb01-id");

    REQUIRE(server.update("MMXU1$MX$TotW$mag$f", mms::data::floating_point(10.0F)));
    REQUIRE(server.update("MMXU1$MX$TotW$mag$f", mms::data::floating_point(11.0F)));
    auto r1 = co_await c.next_report();
    REQUIRE(r1);
    auto r2 = co_await c.next_report();
    REQUIRE(r2);
    CHECK(r1->rcb == ref(brcb_text));
    CHECK(totw_mag(r2->entries[0].value) == 11.0F);
    REQUIRE(r2->entry_id);
    CHECK(r1->entry_id != r2->entry_id);
    CHECK(c.last_entry_id(ref(brcb_text)) == r2->entry_id);

    server.clear_write_log();
    server.drop_connections();
    // Buffered by the server while the client is away.
    REQUIRE(server.update("MMXU1$MX$TotW$mag$f", mms::data::floating_point(12.0F)));
    REQUIRE(server.update("MMXU1$MX$TotW$mag$f", mms::data::floating_point(13.0F)));
    CHECK(server.buffered_entries("brcb01") == 4);

    auto lost = co_await c.next_event();
    REQUIRE(lost);
    CHECK(lost->type == kind::lost);
    CHECK(lost->error);
    auto reconnecting = co_await c.next_event();
    REQUIRE(reconnecting);
    CHECK(reconnecting->type == kind::reconnecting);
    CHECK(reconnecting->attempt == 1);
    auto restored = co_await wait_event(c, kind::restored);
    CHECK(restored.rcb_errors.empty());
    CHECK(c.state() == client::connection_state::established);
    CHECK(server.associations_accepted() == 2);

    // EntryID (the last one received) is written before RptEna.
    const auto& log = server.write_log();
    const auto entry_pos = position(log, "IED1LD0/LLN0$BR$brcb01$EntryID");
    const auto ena_pos = position(log, "IED1LD0/LLN0$BR$brcb01$RptEna");
    REQUIRE(entry_pos >= 0);
    REQUIRE(ena_pos >= 0);
    CHECK(entry_pos < ena_pos);
    CHECK(server.value("IED1LD0", "LLN0$BR$brcb01$EntryID") == r2->entry_id->to_mms());

    // The stream resumes after r2: no loss, no duplicates.
    auto r3 = co_await c.next_report();
    REQUIRE(r3);
    CHECK(totw_mag(r3->entries[0].value) == 12.0F);
    auto r4 = co_await c.next_report();
    REQUIRE(r4);
    CHECK(totw_mag(r4->entries[0].value) == 13.0F);
    CHECK(r4->rcb == ref(brcb_text));
    CHECK(c.last_entry_id(ref(brcb_text)) == r4->entry_id);

    REQUIRE(server.update("MMXU1$MX$TotW$mag$f", mms::data::floating_point(14.0F)));
    auto r5 = co_await c.next_report();
    REQUIRE(r5);
    CHECK(totw_mag(r5->entries[0].value) == 14.0F);
    auto read = co_await c.read(ref("IED1LD0/MMXU1.TotW.mag.f[MX]"));
    REQUIRE(read);
    CHECK(client::to_float(*read).value() == 14.0F);
  });
}

TEST_CASE("URCB recovery re-enables and repeats the GI", "[client]") {
  run([]() -> awaitable<void> {
    testing::fake_server server(co_await asio::this_coro::executor);
    REQUIRE(server.start());
    auto o = options_for(server);
    o.recovery.enabled = true;
    o.recovery.backoff = {};
    auto c = co_await connect(o);

    client::report_settings s;
    s.opt_flds = model::optional_fields::of({optional_field::reason_for_inclusion});
    s.general_interrogation = true;
    auto enabled = co_await c.enable_reporting(ref(urcb_text), s);
    REQUIRE(enabled);
    auto gi = co_await c.next_report();
    REQUIRE(gi);
    CHECK(gi->entries.size() == 4);

    server.drop_connections();
    (void)co_await wait_event(c, kind::restored);
    CHECK(server.rcb_enabled("urcb01"));
    auto again = co_await c.next_report();
    REQUIRE(again);
    CHECK(again->rcb == ref(urcb_text));
    CHECK(again->entries[0].reason->general_interrogation());
  });
}

TEST_CASE("requests pending at the loss fail and are not replayed", "[client]") {
  run([]() -> awaitable<void> {
    testing::fake_server server(co_await asio::this_coro::executor);
    REQUIRE(server.start());
    auto o = options_for(server);
    o.recovery.enabled = true;
    o.recovery.backoff = {200ms};
    auto c = co_await connect(o);

    server.hold_requests(true);
    std::optional<openiec61850::result<mms::data>> pending;
    asio::co_spawn(
        co_await asio::this_coro::executor,
        [&]() -> awaitable<void> { pending.emplace(co_await c.read(ref("IED1LD0/MMXU1.TotW.mag.f[MX]"))); },
        asio::detached);
    while (server.requests(mms::confirmed_service::read) == 0) co_await client_test::yield();
    server.hold_requests(false);
    server.drop_connections();
    while (!pending) co_await client_test::yield();
    REQUIRE(!*pending);
    CHECK(pending->error() != client::errc::not_connected);

    (void)co_await wait_event(c, kind::reconnecting);
    auto during = co_await c.read(ref("IED1LD0/MMXU1.TotW.mag.f[MX]"));
    CHECK(during.error() == client::errc::not_connected);
    CHECK(c.state() == client::connection_state::reconnecting);

    (void)co_await wait_event(c, kind::restored);
    CHECK(server.requests(mms::confirmed_service::read) == 1);
    auto after = co_await c.read(ref("IED1LD0/MMXU1.TotW.mag.f[MX]"));
    CHECK(after);
    CHECK(server.requests(mms::confirmed_service::read) == 2);
  });
}

TEST_CASE("recovery gives up after max_attempts; close stops it", "[client]") {
  run([]() -> awaitable<void> {
    testing::fake_server server(co_await asio::this_coro::executor);
    REQUIRE(server.start());
    auto o = options_for(server);
    o.recovery.enabled = true;
    o.recovery.backoff = {5ms};
    o.recovery.max_attempts = 2;
    auto c = co_await connect(o);
    auto slow = o;
    slow.recovery.backoff = {5s};
    auto d = co_await connect(slow);

    server.stop();
    std::vector<kind> seen;
    for (;;) {
      auto e = co_await c.next_event();
      if (!e) break;
      seen.push_back(e->type);
      if (e->type == kind::failed) {
        CHECK(e->attempt == 2);
        CHECK(e->error);
      }
    }
    CHECK(seen == std::vector<kind>{kind::lost, kind::reconnecting, kind::reconnecting, kind::failed});
    const auto why = co_await c.wait_closed();
    CHECK(why == client::errc::recovery_failed);
    CHECK(c.state() == client::connection_state::closed);

    // release() while reconnecting just stops the recovery.
    (void)co_await wait_event(d, kind::reconnecting);
    auto released = co_await d.release();
    CHECK(released);
    CHECK(d.state() == client::connection_state::closed);
  });
}
