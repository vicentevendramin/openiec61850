// Our client (client::control) against our server for the four control models.

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <mutex>
#include <optional>
#include <thread>
#include <vector>

#include "openiec61850/client/control.hpp"
#include "server_test_util.hpp"

using namespace server_test;
using asio::awaitable;
using client::add_cause;

namespace {

using model::basic_type;
using model::fc;
using cm = model::ctl_model;

const mms::data on = mms::data::boolean(true);
const mms::data off = mms::data::boolean(false);

// LD "CTL": LLN0 Mod/Beh (on), GGIO1 SPCSO1 direct-normal, SPCSO2 sbo-normal, SPCSO3
// direct-enhanced (with operTm), SPCSO4 sbo-enhanced; sboTimeout 300 ms.
void add_spc(srv::ln_handle ln, std::string_view name, cm ctl, bool oper_tm) {
  auto d = ln.data_object(name);
  d.attribute("stVal", fc::ST, basic_type::boolean, srv::attribute_options{}.with_triggers(srv::on_dchg));
  d.attribute("q", fc::ST, basic_type::quality);
  d.attribute("t", fc::ST, basic_type::timestamp);
  d.attribute("ctlModel", fc::CF, basic_type::enumerated,
              srv::attribute_options{}.with_value(model::to_mms(ctl)));
  d.attribute("sboTimeout", fc::CF, basic_type::int32u,
              srv::attribute_options{}.with_value(mms::data::unsigned_integer(300)));
  if (ctl == cm::sbo_with_normal_security) d.attribute("SBO", fc::CO, basic_type::object_reference);
  auto request = [&](std::string_view sname, bool check) {
    auto o = d.structure(sname, fc::CO);
    o.attribute("ctlVal", basic_type::boolean);
    if (oper_tm) o.attribute("operTm", basic_type::timestamp);
    auto origin = o.structure("origin");
    origin.attribute("orCat", basic_type::enumerated);
    origin.attribute("orIdent", basic_type::octet_string, srv::attribute_options{}.with_size(64));
    o.attribute("ctlNum", basic_type::int8u);
    o.attribute("T", basic_type::timestamp);
    o.attribute("Test", basic_type::boolean);
    if (check) o.attribute("Check", basic_type::check);
  };
  if (ctl == cm::sbo_with_enhanced_security) request("SBOw", true);
  request("Oper", true);
  if (ctl != cm::direct_with_normal_security) request("Cancel", false);
}

srv::data_model control_model() {
  srv::model_builder b;
  auto ld = b.logical_device("CTL");
  auto lln0 = ld.logical_node("LLN0");
  for (const char* n : {"Mod", "Beh"}) {
    lln0.data_object(n).attribute("stVal", fc::ST, basic_type::enumerated,
                                  srv::attribute_options{}.with_value(mms::data::integer(1)));
  }
  auto ggio = ld.logical_node("GGIO1");
  add_spc(ggio, "SPCSO1", cm::direct_with_normal_security, false);
  add_spc(ggio, "SPCSO2", cm::sbo_with_normal_security, false);
  add_spc(ggio, "SPCSO3", cm::direct_with_enhanced_security, true);
  add_spc(ggio, "SPCSO4", cm::sbo_with_enhanced_security, false);
  auto m = b.build();
  REQUIRE(m);
  return std::move(*m);
}

// Application state shared with the handler (which runs on the server strand).
struct app_state {
  std::mutex mutex;
  std::vector<srv::control_request> requests;
  // How the next Operate is answered.
  enum class mode { ok, refuse, pending_thread, pending_never } operate = mode::ok;
  srv::add_cause refuse_cause = srv::add_cause::blocked_by_interlocking;
  srv::control_result complete_with = srv::control_result::ok();
  std::chrono::milliseconds delay{100};
  std::vector<std::thread> threads;
  std::optional<srv::control_completion> last_completion;
  std::atomic<bool> first_complete{false};
  std::atomic<bool> second_complete{true};

  void reset() {
    join();
    const std::lock_guard l(mutex);
    requests.clear();
    operate = mode::ok;
    complete_with = srv::control_result::ok();
    delay = 100ms;
    last_completion.reset();
  }
  void join() {
    for (auto& t : threads) t.join();
    threads.clear();
  }
  std::vector<srv::control_request> taken() {
    const std::lock_guard l(mutex);
    return requests;
  }
};

app_state& app() {
  static app_state a;
  return a;
}

srv::server start_control(asio::any_io_executor ex, srv::server_options o = {}) {
  o.association.transport.handshake_timeout = 2s;
  o.on_control = [](const srv::control_request& r) {
    auto& a = app();
    const std::lock_guard l(a.mutex);
    a.requests.push_back(r);
    if (r.action != srv::control_action::operate) return srv::control_result::ok();
    a.last_completion = r.completion;
    switch (a.operate) {
      case app_state::mode::ok:
        return srv::control_result::ok();
      case app_state::mode::refuse:
        return srv::control_result::refused(a.refuse_cause);
      case app_state::mode::pending_thread:
        // The physical action ends later, on another thread.
        a.threads.emplace_back([c = r.completion, res = a.complete_with, d = a.delay] {
          std::this_thread::sleep_for(d);
          app().first_complete = c.complete(res);
          app().second_complete = c.complete(srv::control_result::ok());
        });
        return srv::control_result::pending();
      case app_state::mode::pending_never:
        return srv::control_result::pending();
    }
    return srv::control_result::ok();
  };
  auto s = srv::server::start(std::move(ex), control_model(), loopback, std::move(o));
  REQUIRE(s);
  return std::move(*s);
}

awaitable<client::control> control_of(client::client& c, std::string_view object) {
  auto ctl = co_await c.get_control(oref(object));
  REQUIRE(ctl);
  co_return std::move(*ctl);
}

client::control_options as(std::uint8_t ident) {
  client::control_options o;
  o.origin.category = model::orcat::station_control;
  o.origin.identifier = {ident};
  return o;
}

}  // namespace

TEST_CASE("Control models: our client against our server", "[server][control]") {
  app().reset();
  run([]() -> awaitable<void> {
    auto s = start_control(co_await asio::this_coro::executor);
    auto c = co_await connect(options_for(s));

    auto direct = co_await control_of(c, "CTL/GGIO1.SPCSO1");
    CHECK(direct.ctl_model() == cm::direct_with_normal_security);
    auto r1 = co_await direct.operate(on, as(1));
    CHECK(r1);

    auto sbo = co_await control_of(c, "CTL/GGIO1.SPCSO2");
    CHECK(sbo.ctl_model() == cm::sbo_with_normal_security);
    CHECK(sbo.sbo_timeout() == std::chrono::milliseconds(300));
    auto sel = co_await sbo.select(as(2));
    CHECK(sel);
    auto r2 = co_await sbo.operate(on, as(2));
    CHECK(r2);

    auto denh = co_await control_of(c, "CTL/GGIO1.SPCSO3");
    CHECK(denh.ctl_model() == cm::direct_with_enhanced_security);
    CHECK(denh.has_oper_time() == true);
    auto r3 = co_await denh.operate(on, as(3));
    CHECK(r3);

    auto senh = co_await control_of(c, "CTL/GGIO1.SPCSO4");
    CHECK(senh.ctl_model() == cm::sbo_with_enhanced_security);
    auto selw = co_await senh.select_with_value(on, as(4));
    CHECK(selw);
    auto r4 = co_await senh.operate(on, as(4));
    CHECK(r4);

    const auto reqs = app().taken();
    REQUIRE(reqs.size() == 6);
    CHECK(reqs[0].action == srv::control_action::operate);
    CHECK(reqs[0].object == oref("CTL/GGIO1.SPCSO1"));
    CHECK(reqs[0].or_cat == model::orcat::station_control);
    CHECK(reqs[0].or_ident == openiec61850::byte_buffer{1});
    CHECK(reqs[1].action == srv::control_action::select);
    CHECK(reqs[2].ctl_model == cm::sbo_with_normal_security);
    CHECK(reqs[3].ctl_model == cm::direct_with_enhanced_security);
    CHECK_FALSE(reqs[3].oper_time);
    CHECK(reqs[3].completion.valid());
    CHECK(reqs[4].action == srv::control_action::select);
    CHECK(reqs[4].ctl_val == on);
    CHECK(reqs[4].ctl_num == reqs[5].ctl_num);
    CHECK(reqs[5].action == srv::control_action::operate);
    // ok() completed the operation: the handle no longer completes anything.
    CHECK_FALSE(reqs[5].completion.complete(srv::control_result::ok()));

    // Services outside the object's control model.
    auto no_sbo = co_await c.read(oref("CTL/GGIO1.SPCSO4.SBOw[CO]"));
    CHECK(no_sbo);
    auto wrong = co_await c.write(oref("CTL/GGIO1.SPCSO1.Oper.ctlVal[CO]"), on);
    CHECK(wrong.error() == client::errc::access_denied);
    s.stop();
  });
}

namespace {

// Runs `op` concurrently; the result lands in `out`.
void spawn(asio::any_io_executor ex, asio::awaitable<openiec61850::result<void>> op,
           std::shared_ptr<std::optional<openiec61850::result<void>>> out) {
  asio::co_spawn(ex, std::move(op), [out](std::exception_ptr, openiec61850::result<void> r) {
    *out = std::move(r);
  });
}

awaitable<openiec61850::result<void>> wait_for(
    const std::shared_ptr<std::optional<openiec61850::result<void>>>& r) {
  for (int i = 0; i < 300 && !*r; ++i) co_await sleep(10ms);
  REQUIRE(*r);
  co_return **r;
}

}  // namespace

TEST_CASE("Control models: enhanced security completed from another thread", "[server][control]") {
  app().reset();
  run([]() -> awaitable<void> {
    const auto ex = co_await asio::this_coro::executor;
    auto s = start_control(ex);
    auto c = co_await connect(options_for(s));
    auto other = co_await connect(options_for(s));
    auto denh = co_await control_of(c, "CTL/GGIO1.SPCSO3");
    auto denh2 = co_await control_of(other, "CTL/GGIO1.SPCSO3");

    app().operate = app_state::mode::pending_thread;
    app().delay = 300ms;
    const auto t0 = std::chrono::steady_clock::now();
    auto first = std::make_shared<std::optional<openiec61850::result<void>>>();
    spawn(ex, denh.operate(on, as(1)), first);
    co_await sleep(100ms);
    CHECK_FALSE(*first);  // waiting for the CommandTermination
    // A second operation while the first one runs.
    auto busy = co_await denh2.operate(off, as(2));
    CHECK(busy.error() == add_cause::command_already_in_execution);
    auto r = co_await wait_for(first);
    CHECK(r);
    CHECK(std::chrono::steady_clock::now() - t0 >= 300ms);
    app().join();
    CHECK(app().first_complete);
    CHECK_FALSE(app().second_complete);  // only the first complete() counts

    // Negative termination with AddCause, from the other thread.
    app().complete_with = srv::control_result::refused(srv::add_cause::blocked_by_synchrocheck);
    app().delay = 50ms;
    client::error_details details;
    auto neg = co_await denh.operate(on, as(1), details);
    CHECK(neg.error() == add_cause::blocked_by_synchrocheck);
    auto lae = denh.last_error();
    REQUIRE(lae);
    CHECK(lae->cause == add_cause::blocked_by_synchrocheck);
    CHECK(lae->control_object == "CTL/GGIO1$CO$SPCSO3$Oper");
    CHECK(lae->ctl_num == denh.ctl_num());
    CHECK(lae->origin.category == model::orcat::station_control);
    CHECK(lae->origin.identifier == openiec61850::byte_buffer{1});
    app().join();

    // Refused at once: negative Oper response with LastApplError, no termination.
    app().operate = app_state::mode::refuse;
    auto refused = co_await denh.operate(on, as(1));
    CHECK(refused.error() == add_cause::blocked_by_interlocking);

    // Normal security: a pending operation is answered at once, has no termination and blocks
    // further operates until completed.
    app().operate = app_state::mode::pending_thread;
    app().complete_with = srv::control_result::ok();
    app().delay = 200ms;
    auto direct = co_await control_of(c, "CTL/GGIO1.SPCSO1");
    auto n1 = co_await direct.operate(on, as(1));
    CHECK(n1);
    auto n2 = co_await direct.operate(on, as(1));
    CHECK(n2.error() == add_cause::command_already_in_execution);
    app().join();
    co_await sleep(20ms);
    app().operate = app_state::mode::ok;
    auto n3 = co_await direct.operate(on, as(1));
    CHECK(n3);
    s.stop();
  });
}

TEST_CASE("Control models: operate timeout and time-activated operate", "[server][control]") {
  app().reset();
  run([]() -> awaitable<void> {
    srv::server_options o;
    o.operate_timeout = 200ms;
    auto s = start_control(co_await asio::this_coro::executor, o);
    auto c = co_await connect(options_for(s));
    auto denh = co_await control_of(c, "CTL/GGIO1.SPCSO3");

    // Never completed: time-limit-over.
    app().operate = app_state::mode::pending_never;
    auto late = co_await denh.operate(on, as(1));
    CHECK(late.error() == add_cause::time_limit_over);
    {
      const std::lock_guard l(app().mutex);
      REQUIRE(app().last_completion);
      CHECK_FALSE(app().last_completion->complete(srv::control_result::ok()));
    }

    // operTm: accepted at once, handed to the application when the time comes.
    app().operate = app_state::mode::ok;
    auto opts = as(1);
    const auto when = std::chrono::system_clock::now() + 300ms;
    opts.oper_time = *model::timestamp::from_time_point(when);
    const auto t0 = std::chrono::steady_clock::now();
    auto timed = co_await denh.operate(on, opts);
    CHECK(timed);
    CHECK(std::chrono::steady_clock::now() - t0 >= 250ms);
    const auto reqs = app().taken();
    REQUIRE(!reqs.empty());
    CHECK(reqs.back().oper_time);

    // Cancel while waiting for operTm (a raw Write of Cancel on the same association: the
    // handle is busy waiting for the termination), which ends with CommandTermination-.
    const auto ex = co_await asio::this_coro::executor;
    auto pending = std::make_shared<std::optional<openiec61850::result<void>>>();
    opts.oper_time = *model::timestamp::from_time_point(std::chrono::system_clock::now() + 2s);
    spawn(ex, denh.operate(on, opts), pending);
    co_await sleep(100ms);
    const auto cancel = mms::data::structure(
        {on, opts.oper_time->to_mms(),
         mms::data::structure({model::to_mms(model::orcat::station_control),
                               mms::data::octet_string(openiec61850::byte_buffer{1})}),
         mms::data::unsigned_integer(denh.ctl_num()), model::timestamp::now().to_mms(), off});
    auto cancelled = co_await c.write(oref("CTL/GGIO1.SPCSO3.Cancel[CO]"), cancel);
    CHECK(cancelled);
    auto aborted = co_await wait_for(pending);
    CHECK(aborted.error() == add_cause::abortion_by_cancel);
    CHECK(app().taken().back().action == srv::control_action::cancel);
    s.stop();
  });
}

TEST_CASE("Control models: sbo-enhanced selection rules", "[server][control]") {
  app().reset();
  run([]() -> awaitable<void> {
    auto s = start_control(co_await asio::this_coro::executor);
    auto c = co_await connect(options_for(s));
    auto other = co_await connect(options_for(s));
    auto senh = co_await control_of(c, "CTL/GGIO1.SPCSO4");
    auto senh2 = co_await control_of(other, "CTL/GGIO1.SPCSO4");

    // Not selected.
    auto unselected = co_await senh.operate(on, as(1));
    CHECK(unselected.error() == add_cause::object_not_selected);

    // Selected by another client.
    auto sel = co_await senh.select_with_value(on, as(1));
    CHECK(sel);
    auto taken = co_await senh2.select_with_value(on, as(2));
    CHECK(taken.error() == add_cause::object_already_selected);
    auto foreign = co_await senh2.operate(on, as(2));
    CHECK(foreign.error() == add_cause::object_not_selected);

    // Oper must repeat the SBOw: ctlVal, origin, ctlNum.
    auto other_value = co_await senh.operate(off, as(1));
    CHECK(other_value.error() == add_cause::inconsistent_parameters);
    auto other_origin = co_await senh.operate(on, as(7));
    CHECK(other_origin.error() == add_cause::inconsistent_parameters);
    auto num = as(1);
    num.ctl_num = static_cast<std::uint8_t>(senh.ctl_num() + 1);
    auto other_num = co_await senh.operate(on, num);
    CHECK(other_num.error() == add_cause::inconsistent_parameters);
    auto ok = co_await senh.operate(on, as(1));
    CHECK(ok);

    // Cancel deselects.
    auto sel2 = co_await senh.select_with_value(off, as(1));
    CHECK(sel2);
    auto cancelled = co_await senh.cancel(as(1));
    CHECK(cancelled);
    auto after_cancel = co_await senh.operate(off, as(1));
    CHECK(after_cancel.error() == add_cause::object_not_selected);
    auto cancel_unselected = co_await senh.cancel(as(1));
    CHECK(cancel_unselected.error() == add_cause::object_not_selected);

    // sboTimeout (300 ms).
    auto sel3 = co_await senh.select_with_value(on, as(1));
    CHECK(sel3);
    co_await sleep(400ms);
    auto expired = co_await senh.operate(on, as(1));
    CHECK(expired.error() == add_cause::object_not_selected);
    // Free again for the other client.
    auto sel4 = co_await senh2.select_with_value(on, as(2));
    CHECK(sel4);
    auto op4 = co_await senh2.operate(on, as(2));
    CHECK(op4);

    // sbo-normal: Cancel after Select.
    auto sbo = co_await control_of(c, "CTL/GGIO1.SPCSO2");
    auto s1 = co_await sbo.select(as(1));
    CHECK(s1);
    auto c1 = co_await sbo.cancel(as(1));
    CHECK(c1);
    auto o1 = co_await sbo.operate(on, as(1));
    CHECK(o1.error() == add_cause::object_not_selected);
    s.stop();
  });
}

TEST_CASE("Control models: Test flag against the behaviour", "[server][control]") {
  app().reset();
  run([]() -> awaitable<void> {
    auto s = start_control(co_await asio::this_coro::executor);
    auto c = co_await connect(options_for(s));
    auto direct = co_await control_of(c, "CTL/GGIO1.SPCSO1");
    auto test = as(1);
    test.test = true;
    auto refused = co_await direct.operate(on, test);
    CHECK(refused.error() == add_cause::blocked_by_mode);
    auto normal = co_await direct.operate(on, as(1));
    CHECK(normal);

    // Beh = test: only Test = true commands.
    auto upd = s.update(oref("CTL/LLN0.Beh.stVal[ST]"), mms::data::integer(3));
    CHECK(upd);
    co_await sleep(20ms);
    auto in_test = co_await direct.operate(on, test);
    CHECK(in_test);
    auto not_test = co_await direct.operate(on, as(1));
    CHECK(not_test.error() == add_cause::blocked_by_mode);

    // Beh = off: nothing.
    auto upd2 = s.update(oref("CTL/LLN0.Beh.stVal[ST]"), mms::data::integer(5));
    CHECK(upd2);
    co_await sleep(20ms);
    auto off_mode = co_await direct.operate(on, test);
    CHECK(off_mode.error() == add_cause::blocked_by_mode);
    const auto reqs = app().taken();
    CHECK(reqs.size() == 2);
    CHECK(reqs[1].test);
    s.stop();
  });

  // Without the check, Test is only passed on.
  app().reset();
  run([]() -> awaitable<void> {
    srv::server_options o;
    o.check_test_mode = false;
    auto s = start_control(co_await asio::this_coro::executor, o);
    auto c = co_await connect(options_for(s));
    auto direct = co_await control_of(c, "CTL/GGIO1.SPCSO1");
    auto test = as(1);
    test.test = true;
    auto r = co_await direct.operate(on, test);
    CHECK(r);
    s.stop();
  });
}

TEST_CASE("Control models: a closed association abandons its termination", "[server][control]") {
  app().reset();
  run([]() -> awaitable<void> {
    const auto ex = co_await asio::this_coro::executor;
    auto s = start_control(ex);
    auto c = co_await connect(options_for(s));
    auto denh = co_await control_of(c, "CTL/GGIO1.SPCSO3");
    app().operate = app_state::mode::pending_thread;
    app().delay = 200ms;
    auto first = std::make_shared<std::optional<openiec61850::result<void>>>();
    spawn(ex, denh.operate(on, as(1)), first);
    co_await sleep(50ms);
    c.abort();
    (void)co_await wait_for(first);
    co_await sleep(250ms);  // completion arrives with no association: nothing is sent
    app().join();
    // The object is free again.
    auto c2 = co_await connect(options_for(s));
    auto again = co_await control_of(c2, "CTL/GGIO1.SPCSO3");
    app().operate = app_state::mode::ok;
    auto r = co_await again.operate(on, as(1));
    CHECK(r);
    s.stop();
  });
  app().join();
}
