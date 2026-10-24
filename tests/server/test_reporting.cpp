#include <catch2/catch_test_macros.hpp>

#include <set>
#include <string>

#include "server_test_util.hpp"

using namespace server_test;
using asio::awaitable;
using model::optional_field;
using model::trigger;

namespace {

const char* const brcb = "IED1LD0/LLN0.brcb01[BR]";
const char* const urcb = "IED1LD0/LLN0.urcb01[RP]";

model::optional_fields all_fields() {
  return model::optional_fields::of(
      {optional_field::sequence_number, optional_field::report_time_stamp,
       optional_field::reason_for_inclusion, optional_field::data_set_name,
       optional_field::data_reference, optional_field::buffer_overflow, optional_field::entry_id,
       optional_field::conf_revision});
}

void set_ind1(srv::server& s, bool v) {
  REQUIRE(s.update(oref("IED1LD0/GGIO1.Ind1.stVal[ST]"), mms::data::boolean(v)));
}

}  // namespace

TEST_CASE("URCB: reservation, GI and data change reports", "[server]") {
  run([]() -> awaitable<void> {
    auto s = start(co_await asio::this_coro::executor);
    auto c = co_await connect(options_for(s));

    client::report_settings rs;
    rs.opt_flds = all_fields();
    rs.general_interrogation = true;
    auto values = co_await c.enable_reporting(oref(urcb), rs);
    REQUIRE(values);
    CHECK(values->resv == true);
    CHECK(values->dat_set == "IED1LD0/LLN0$DS1");
    CHECK(values->owner == openiec61850::byte_buffer{127, 0, 0, 1});

    auto gi = co_await next_report(c);
    CHECK(gi.rpt_id == "IED1LD0/LLN0$RP$urcb01");  // empty RptID: the RCB reference
    CHECK(gi.rcb == oref(urcb));
    CHECK(gi.seq_num == 0U);
    CHECK(gi.data_set == "IED1LD0/LLN0$DS1");
    CHECK(gi.conf_rev == 1U);
    CHECK(!gi.entry_id);  // not sent by a URCB
    CHECK(!gi.buffer_overflow);
    REQUIRE(gi.entries.size() == 4);
    CHECK(gi.entries[0].data_reference == "IED1LD0/MMXU1$MX$TotW");
    CHECK(gi.entries[0].reference == oref("IED1LD0/MMXU1.TotW[MX]"));
    for (const auto& e : gi.entries) CHECK(e.reason->general_interrogation());

    REQUIRE(s.update(oref("IED1LD0/XCBR1.Pos.stVal[ST]"), model::to_mms(model::dbpos::on)));
    auto dchg = co_await next_report(c);
    CHECK(dchg.seq_num == 1U);
    REQUIRE(dchg.entries.size() == 1);
    CHECK(dchg.entries[0].index == 1);
    CHECK(dchg.entries[0].value == model::to_mms(model::dbpos::on));
    CHECK(dchg.entries[0].reason == model::trigger_conditions::of({trigger::data_change}));

    // The same value again: no dchg. A quality change: qchg on the q member.
    REQUIRE(s.update(oref("IED1LD0/XCBR1.Pos.stVal[ST]"), model::to_mms(model::dbpos::on)));
    REQUIRE(s.update(oref("IED1LD0/XCBR1.Pos.stVal[ST]"), model::to_mms(model::dbpos::on),
                     model::quality{}.set_validity(model::validity::invalid)));
    auto qchg = co_await next_report(c);
    CHECK(qchg.seq_num == 2U);
    REQUIRE(qchg.entries.size() == 1);
    CHECK(qchg.entries[0].index == 2);
    CHECK(qchg.entries[0].reason == model::trigger_conditions::of({trigger::quality_change}));

    // A batch changing value and quality of one FCD member: one entry, both reasons.
    std::vector<srv::data_update> batch;
    batch.push_back({oref("IED1LD0/GGIO1.Ind1.stVal[ST]"), mms::data::boolean(true),
                     model::quality{}.set(model::quality_flag::test), std::nullopt});
    REQUIRE(s.update(std::move(batch)));
    auto both = co_await next_report(c);
    REQUIRE(both.entries.size() == 1);
    CHECK(both.entries[0].index == 3);
    CHECK(both.entries[0].reason ==
          model::trigger_conditions::of({trigger::data_change, trigger::quality_change}));
    CHECK(client::component(both.entries[0].value, 0).value() == mms::data::boolean(true));

    // A client write to a member triggers too (MMXU1.TotW is MX: not writable; use the CF db,
    // which is not in DS1: no report). Another client cannot take the reserved URCB.
    auto other = co_await connect(options_for(s));
    auto denied = co_await other.enable_reporting(oref(urcb), rs);
    CHECK(denied.error() == client::errc::access_denied);
    client::rcb_settings w;
    w.buf_tm = 10;
    auto locked = co_await c.set_rcb_values(oref(urcb), w);
    CHECK(locked.error() == client::errc::temporarily_unavailable);

    auto off = co_await c.disable_reporting(oref(urcb));
    CHECK(off);
    auto after = co_await other.get_rcb_values(oref(urcb));
    REQUIRE(after);
    CHECK(after->rpt_ena == false);
    CHECK(after->resv == false);
    CHECK(after->sq_num == 4U);
    CHECK(after->owner == openiec61850::byte_buffer{});
    s.stop();
  });
}

TEST_CASE("BRCB: EntryID resynchronisation after reconnection", "[server]") {
  run([]() -> awaitable<void> {
    auto s = start(co_await asio::this_coro::executor);
    model::entry_id first;
    {
      auto c = co_await connect(options_for(s));
      client::report_settings rs;
      rs.opt_flds = all_fields();
      auto v = co_await c.enable_reporting(oref(brcb), rs);
      REQUIRE(v);
      set_ind1(s, true);
      auto r1 = co_await next_report(c);
      REQUIRE(r1.entry_id);
      CHECK(r1.rpt_id == "brcb01-id");
      CHECK(r1.buffer_overflow == false);
      first = *r1.entry_id;
      set_ind1(s, false);
      auto r2 = co_await next_report(c);
      REQUIRE(r2.entry_id);
      CHECK(r2.seq_num == *r1.seq_num + 1);
      CHECK(c.last_entry_id(oref(brcb)) == r2.entry_id);
      c.abort();
    }
    co_await sleep(50ms);
    // Buffered while nobody is connected.
    set_ind1(s, true);
    set_ind1(s, false);
    co_await sleep(20ms);

    auto c2 = co_await connect(options_for(s));
    client::report_settings rs;
    rs.opt_flds = all_fields();
    rs.entry_id = first;  // resume after the first entry: 2, 3 and 4 follow
    auto v = co_await c2.enable_reporting(oref(brcb), rs);
    REQUIRE(v);
    std::vector<client::report> got;
    for (int i = 0; i < 3; ++i) got.push_back(co_await next_report(c2));
    CHECK(got[0].entries[0].value.elements()[0] == mms::data::boolean(false));
    CHECK(got[1].entries[0].value.elements()[0] == mms::data::boolean(true));
    CHECK(got[2].entries[0].value.elements()[0] == mms::data::boolean(false));
    CHECK(*got[1].seq_num == *got[0].seq_num + 1);
    CHECK(*got[2].seq_num == *got[1].seq_num + 1);
    CHECK(got[0].entry_id != first);
    auto values = co_await c2.get_rcb_values(oref(brcb));
    REQUIRE(values);
    CHECK(values->entry_id == got[2].entry_id);
    CHECK(values->rpt_ena == true);

    // A second client cannot write the enabled BRCB.
    auto other = co_await connect(options_for(s));
    client::rcb_settings w;
    w.rpt_ena = false;
    auto denied = co_await other.set_rcb_values(oref(brcb), w);
    CHECK(denied.error() == client::errc::access_denied);
    s.stop();
  });
}

TEST_CASE("BRCB: buffer overflow is reported with BufOvfl", "[server]") {
  run([]() -> awaitable<void> {
    srv::server_options o;
    o.brcb_buffer_capacity = 2;
    auto s = start(co_await asio::this_coro::executor, o);
    model::entry_id last;
    {
      auto c = co_await connect(options_for(s));
      client::report_settings rs;
      rs.opt_flds = all_fields();
      auto v = co_await c.enable_reporting(oref(brcb), rs);
      REQUIRE(v);
      set_ind1(s, true);
      auto r = co_await next_report(c);
      last = *r.entry_id;
      c.abort();
    }
    co_await sleep(50ms);
    for (int i = 0; i < 4; ++i) {
      set_ind1(s, i % 2 == 0 ? false : true);
      co_await sleep(5ms);
    }
    auto c2 = co_await connect(options_for(s));
    client::report_settings rs;
    rs.opt_flds = all_fields();
    rs.entry_id = last;  // no longer buffered
    auto v = co_await c2.enable_reporting(oref(brcb), rs);
    REQUIRE(v);
    auto r1 = co_await next_report(c2);
    auto r2 = co_await next_report(c2);
    CHECK(r1.buffer_overflow == true);
    CHECK(r2.buffer_overflow == false);
    CHECK(r2.entries[0].value.elements()[0] == mms::data::boolean(true));
    s.stop();
  });
}

TEST_CASE("Integrity period and buffer time", "[server]") {
  run([]() -> awaitable<void> {
    auto s = start(co_await asio::this_coro::executor);
    auto c = co_await connect(options_for(s));

    client::report_settings rs;
    rs.opt_flds = all_fields();
    rs.trg_ops = model::trigger_conditions::of({trigger::integrity});
    rs.intg_pd = 40;
    auto v = co_await c.enable_reporting(oref(urcb), rs);
    REQUIRE(v);
    for (int i = 0; i < 2; ++i) {
      auto r = co_await next_report(c);
      CHECK(r.entries.size() == 4);
      CHECK(r.entries[0].reason == model::trigger_conditions::of({trigger::integrity}));
    }
    auto off = co_await c.disable_reporting(oref(urcb));
    REQUIRE(off);
    // Drop an integrity report that may have been queued meanwhile.
    co_await sleep(60ms);
    c.set_report_handler([](client::report) {});
    co_await sleep(5ms);
    c.set_report_handler({});

    rs.trg_ops = model::trigger_conditions::of({trigger::data_change});
    rs.intg_pd = 0;
    rs.buf_tm = 150;
    v = co_await c.enable_reporting(oref(urcb), rs);
    REQUIRE(v);
    // Two members within the buffer time: one report.
    set_ind1(s, true);
    REQUIRE(s.update(oref("IED1LD0/XCBR1.Pos.stVal[ST]"), model::to_mms(model::dbpos::off)));
    auto r = co_await next_report(c);
    REQUIRE(r.entries.size() == 2);
    CHECK(r.entries[0].index == 1);
    CHECK(r.entries[1].index == 3);
    // The same member twice: the pending report is sent first.
    set_ind1(s, false);
    co_await sleep(10ms);
    set_ind1(s, true);
    auto r1 = co_await next_report(c);
    auto r2 = co_await next_report(c);
    REQUIRE(r1.entries.size() == 1);
    REQUIRE(r2.entries.size() == 1);
    CHECK(r1.entries[0].value.elements()[0] == mms::data::boolean(false));
    CHECK(r2.entries[0].value.elements()[0] == mms::data::boolean(true));
    CHECK(*r2.seq_num == *r1.seq_num + 1);
    s.stop();
  });
}

TEST_CASE("Reports larger than the negotiated PDU size are segmented", "[server]") {
  run([]() -> awaitable<void> {
    auto s = start(co_await asio::this_coro::executor);
    std::vector<srv::data_update> batch;
    for (std::size_t i = 1; i <= big_members; ++i) {
      batch.push_back({oref("IED1LD0/GGIO1.Str" + std::to_string(i) + ".stVal[ST]"),
                       mms::data::visible_string(std::string(100, static_cast<char>('a' + i))),
                       std::nullopt, std::nullopt});
    }
    REQUIRE(s.update(std::move(batch)));

    auto o = options_for(s);
    o.association.initiate.local_detail_calling = 1000;
    auto c = co_await connect(o);
    client::report_settings rs;
    rs.opt_flds = all_fields();
    rs.general_interrogation = true;
    auto v = co_await c.enable_reporting(oref("IED1LD0/LLN0.urcb02[RP]"), rs);
    REQUIRE(v);
    std::set<std::size_t> seen;
    std::vector<client::report> segments;
    for (;;) {
      segments.push_back(co_await next_report(c));
      const auto& r = segments.back();
      CHECK(r.opt_flds.segmentation());
      REQUIRE(r.sub_seq_num);
      CHECK(*r.sub_seq_num == segments.size() - 1);
      CHECK(r.seq_num == segments.front().seq_num);
      for (const auto& e : r.entries) {
        seen.insert(e.index);
        CHECK(e.value == mms::data::visible_string(std::string(100, static_cast<char>('a' + e.index + 1))));
      }
      if (!r.more_segments_follow.value_or(false)) break;
    }
    CHECK(segments.size() >= 2);
    CHECK(seen.size() == big_members);
    s.stop();
  });
}
