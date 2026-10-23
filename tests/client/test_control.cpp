#include <catch2/catch_test_macros.hpp>

#include <optional>
#include <string>
#include <vector>

#include "client_test_util.hpp"
#include "openiec61850/client/control.hpp"
#include "openiec61850/transport/spawn.hpp"

namespace client = openiec61850::client;
namespace mms = openiec61850::mms;
namespace model = openiec61850::model;
namespace testing = openiec61850::testing;
using asio::awaitable;
using client::add_cause;
using client_test::connect;
using client_test::options_for;
using client_test::ref;
using client_test::run;
using openiec61850::byte_buffer;
using openiec61850::result;
using namespace std::chrono_literals;

// Note: GCC evaluates a co_await inside a Catch2 assertion macro twice, so results are always
// stored in a variable before being checked.

namespace {

using mode = testing::fake_server::termination_mode;

const mms::data on = mms::data::boolean(true);
const mms::data off = mms::data::boolean(false);

mms::data lae_value(std::string_view object, std::int64_t cause, std::uint64_t num) {
  const byte_buffer id{'o', 'p'};
  return mms::data::structure({mms::data::visible_string(object), mms::data::integer(1),
                               mms::data::structure({mms::data::integer(3), mms::data::octet_string(id)}),
                               mms::data::unsigned_integer(num), mms::data::integer(cause)});
}

// Component `i` of a request recorded by the fake server.
mms::data part(const std::optional<mms::data>& request, std::size_t i) {
  REQUIRE(request);
  REQUIRE(request->elements().size() > i);
  return request->elements()[i];
}

std::uint64_t ctl_num_of(const std::optional<mms::data>& request, std::size_t index) {
  return part(request, index).as_uint64().value();
}

}  // namespace

TEST_CASE("control messages and AddCause error codes", "[client][control]") {
  const auto lae = lae_value("IED1LD1/XCBR1$CO$Pos$Oper", 10, 7);
  const auto oper = mms::data::structure({on});

  // LastApplError alone.
  std::vector<mms::variable_spec> one{mms::object_name::vmd("LastApplError")};
  std::vector<mms::access_result> lae_only{mms::data_ref(lae)};
  const mms::information_report refused{mms::variable_access_specification::list(one), lae_only};
  REQUIRE(client::is_control_message(refused));
  auto m = client::parse_control_message(refused);
  REQUIRE(m);
  CHECK(m->type == client::control_message::kind::last_appl_error);
  CHECK(!m->positive());
  REQUIRE(m->error);
  CHECK(m->control_object == "IED1LD1/XCBR1$CO$Pos$Oper");
  CHECK(m->error->cause == add_cause::blocked_by_interlocking);
  CHECK(m->error->error == client::control_error::unknown);
  CHECK(m->error->origin.category == model::orcat::remote_control);
  CHECK(m->error->origin.identifier == byte_buffer{'o', 'p'});
  CHECK(m->error->ctl_num == 7);

  // Negative CommandTermination: LastApplError + Oper.
  std::vector<mms::variable_spec> two{mms::object_name::vmd("LastApplError"),
                                      mms::object_name::domain("IED1LD1", "XCBR1$CO$Pos$Oper")};
  std::vector<mms::access_result> both{mms::data_ref(lae), mms::data_ref(oper)};
  const mms::information_report negative{mms::variable_access_specification::list(two), both};
  auto n = client::parse_control_message(negative);
  REQUIRE(n);
  CHECK(n->type == client::control_message::kind::command_termination);
  CHECK(!n->positive());
  CHECK(n->control_object == "IED1LD1/XCBR1$CO$Pos$Oper");
  CHECK(n->oper == oper);

  // Positive CommandTermination.
  std::vector<mms::variable_spec> op{mms::object_name::domain("IED1LD1", "XCBR1$CO$Pos$Oper")};
  std::vector<mms::access_result> oper_only{mms::data_ref(oper)};
  const mms::information_report positive{mms::variable_access_specification::list(op), oper_only};
  auto p = client::parse_control_message(positive);
  REQUIRE(p);
  CHECK(p->positive());

  // Not control messages, or malformed ones.
  const mms::information_report rpt{
      mms::variable_access_specification::named(mms::object_name::vmd("RPT")), oper_only};
  CHECK(!client::is_control_message(rpt));
  CHECK(client::parse_control_message(rpt).error() == openiec61850::errc::unsupported);
  std::vector<mms::access_result> missing{mms::data_ref(lae)};
  const mms::information_report short_negative{mms::variable_access_specification::list(two), missing};
  CHECK(client::parse_control_message(short_negative).error() ==
        openiec61850::errc::protocol_violation);
  const auto bad = mms::data::structure({mms::data::visible_string("x"), mms::data::integer(1)});
  std::vector<mms::access_result> bad_result{mms::data_ref(bad)};
  const mms::information_report malformed{mms::variable_access_specification::list(one), bad_result};
  CHECK(client::parse_control_message(malformed).error() == openiec61850::errc::protocol_violation);
  CHECK(client::parse_last_appl_error(mms::data::integer(3)).error() ==
        openiec61850::errc::protocol_violation);

  // Error codes.
  const std::error_code ec = add_cause::unknown;
  CHECK(ec);  // AddCause 0 is still an error
  CHECK(ec == add_cause::unknown);
  CHECK(ec != add_cause::not_supported);
  CHECK(client::to_add_cause(ec) == add_cause::unknown);
  CHECK(client::to_add_cause(client::make_error_code(client::errc::select_failed)) == std::nullopt);
  CHECK(std::error_code(add_cause::blocked_by_interlocking).message() == "blocked-by-interlocking");
  CHECK(client::to_string(add_cause::one_of_n_control) == "1-of-n-control");
  CHECK(client::to_string(static_cast<add_cause>(99)) == "unknown-add-cause");
  CHECK(client::to_string(client::control_error::timeout_test_not_ok) == "timeout-test-not-ok");
}

TEST_CASE("direct-with-normal-security control", "[client][control]") {
  run([]() -> awaitable<void> {
    testing::fake_server server(co_await asio::this_coro::executor);
    REQUIRE(server.start());
    auto c = co_await connect(options_for(server));

    auto ctl = co_await c.get_control(ref("IED1LD1/GGIO1.SPCSO1"));
    REQUIRE(ctl);
    CHECK(ctl->reference() == ref("IED1LD1/GGIO1.SPCSO1"));
    CHECK(ctl->ctl_model() == model::ctl_model::direct_with_normal_security);
    CHECK(ctl->ctl_val_type() == mms::data_type::boolean);
    CHECK(ctl->has_oper_time() == false);
    CHECK(!ctl->sbo_timeout());  // SPCSO1 has no sboTimeout
    REQUIRE(ctl->structure());

    client::control_options o;
    o.origin = {model::orcat::station_control, byte_buffer{'h', 'm', 'i'}};
    o.test = true;
    o.check = model::check_conditions(false, true);
    auto r = co_await ctl->operate(on, o);
    REQUIRE(r);
    CHECK(server.value("IED1LD1", "GGIO1$ST$SPCSO1$stVal") == on);
    CHECK(server.operations("GGIO1.SPCSO1") == 1);
    const auto req = server.last_control_request("GGIO1.SPCSO1");
    // { ctlVal, origin{orCat, orIdent}, ctlNum, T, Test, Check }
    CHECK(part(req, 0) == on);
    CHECK(part(req, 1) == mms::data::structure({mms::data::integer(2),
                                                mms::data::octet_string(byte_buffer{'h', 'm', 'i'})}));
    CHECK(ctl_num_of(req, 2) == 0);
    CHECK(part(req, 3).type() == mms::data_type::utc_time);
    CHECK(part(req, 4) == mms::data::boolean(true));
    CHECK(model::check_conditions::from_mms(part(req, 5)).value() == model::check_conditions(false, true));

    // ctlNum increments per sequence.
    auto r2 = co_await ctl->operate(off);
    REQUIRE(r2);
    CHECK(ctl_num_of(server.last_control_request("GGIO1.SPCSO1"), 2) == 1);
    CHECK(ctl->ctl_num() == 1);
    CHECK(server.value("IED1LD1", "GGIO1$ST$SPCSO1$stVal") == off);

    // Interlocking: refused only when the client asks for the check.
    REQUIRE(server.set_interlocked("GGIO1.SPCSO1", true));
    client::control_options checked;
    checked.check.set_interlock_check(true);
    auto blocked = co_await ctl->operate(on, checked);
    CHECK(blocked.error() == add_cause::blocked_by_interlocking);
    const auto e = ctl->last_error();
    REQUIRE(e);
    CHECK(e->cause == add_cause::blocked_by_interlocking);
    CHECK(e->control_object == "IED1LD1/GGIO1$CO$SPCSO1$Oper");
    CHECK(e->ctl_num == 2);
    CHECK(e->origin.category == model::orcat::remote_control);
    CHECK(server.operations("GGIO1.SPCSO1") == 2);
    // The refused sequence stays open: the retry keeps its ctlNum.
    auto unchecked = co_await ctl->operate(on);
    REQUIRE(unchecked);
    CHECK(ctl_num_of(server.last_control_request("GGIO1.SPCSO1"), 2) == 2);

    REQUIRE(server.set_synchrocheck_blocked("GGIO1.SPCSO1", true));
    client::control_options sync;
    sync.check.set_synchrocheck(true);
    sync.ctl_num = 200;
    auto no_sync = co_await ctl->operate(on, sync);
    CHECK(no_sync.error() == add_cause::blocked_by_synchrocheck);
    CHECK(ctl->last_error()->ctl_num == 200);

    // Services the ctlModel does not have, and local validation.
    auto sel = co_await ctl->select();
    CHECK(sel.error() == client::errc::control_model_mismatch);
    auto sbow = co_await ctl->select_with_value(on);
    CHECK(sbow.error() == client::errc::control_model_mismatch);
    auto cancel = co_await ctl->cancel();
    CHECK(cancel.error() == client::errc::control_model_mismatch);
    const auto requests = server.requests(mms::confirmed_service::write);
    auto wrong_type = co_await ctl->operate(mms::data::integer(1));
    CHECK(wrong_type.error() == client::errc::type_mismatch);
    client::control_options timed;
    timed.oper_time = model::timestamp::now();
    auto no_oper_tm = co_await ctl->operate(on, timed);
    CHECK(no_oper_tm.error() == openiec61850::errc::unsupported);
    CHECK(server.requests(mms::confirmed_service::write) == requests);

    // Without reading the structure the Ed.2 layout is sent, which matches this object.
    client::control_config cfg;
    cfg.read_structure = false;
    cfg.ctl_model = model::ctl_model::direct_with_normal_security;
    auto blind = co_await c.get_control(ref("IED1LD1/GGIO1.SPCSO1"), cfg);
    REQUIRE(blind);
    CHECK(!blind->structure());
    CHECK(!blind->ctl_val_type());
    auto blind_op = co_await blind->operate(off);
    CHECK(blind_op);

    // Errors of get_control().
    auto missing = co_await c.get_control(ref("IED1LD1/GGIO1.SPCSO9"));
    CHECK(missing.error() == client::errc::object_not_found);
    auto not_do = co_await c.get_control(ref("IED1LD1/GGIO1"));
    CHECK(not_do.error() == openiec61850::errc::invalid_state);
    client::control empty;
    auto none = co_await empty.operate(on);
    CHECK(none.error() == openiec61850::errc::invalid_state);
  });
}

TEST_CASE("sbo-with-normal-security control", "[client][control]") {
  run([]() -> awaitable<void> {
    testing::fake_server server(co_await asio::this_coro::executor);
    REQUIRE(server.start());
    auto c = co_await connect(options_for(server));
    auto other = co_await connect(options_for(server));

    auto ctl = co_await c.get_control(ref("IED1LD1/GGIO1.SPCSO2[CO]"));  // the FC is ignored
    REQUIRE(ctl);
    CHECK(ctl->reference() == ref("IED1LD1/GGIO1.SPCSO2"));
    CHECK(ctl->ctl_model() == model::ctl_model::sbo_with_normal_security);
    CHECK(ctl->sbo_timeout() == 30000ms);

    // Operate without a selection.
    auto unselected = co_await ctl->operate(on);
    CHECK(unselected.error() == add_cause::object_not_selected);
    CHECK(server.operations("GGIO1.SPCSO2") == 0);

    auto sel = co_await ctl->select();
    REQUIRE(sel);
    CHECK(ctl->selected());
    CHECK(server.selected("GGIO1.SPCSO2"));
    CHECK(server.requests(mms::confirmed_service::read) >= 2);

    // Another client cannot select it meanwhile.
    auto rival = co_await other.get_control(ref("IED1LD1/GGIO1.SPCSO2"));
    REQUIRE(rival);
    auto rival_sel = co_await rival->select();
    CHECK(rival_sel.error() == client::errc::select_failed);

    auto op = co_await ctl->operate(on);
    REQUIRE(op);
    CHECK(!ctl->selected());
    CHECK(!server.selected("GGIO1.SPCSO2"));
    CHECK(server.value("IED1LD1", "GGIO1$ST$SPCSO2$stVal") == on);

    // Cancel releases the selection.
    auto sel2 = co_await ctl->select();
    REQUIRE(sel2);
    const auto num = ctl->ctl_num();
    auto cancelled = co_await ctl->cancel();
    REQUIRE(cancelled);
    CHECK(server.cancellations("GGIO1.SPCSO2") == 1);
    CHECK(!server.selected("GGIO1.SPCSO2"));
    const auto cancel_req = server.last_control_request("GGIO1.SPCSO2");
    CHECK(part(cancel_req, 0) == off);  // no ctlVal in a normal-security selection: default
    CHECK(ctl_num_of(cancel_req, 2) == num);
    CHECK(part(cancel_req, 1).type() == mms::data_type::structure);
    CHECK(cancel_req->elements().size() == 5);  // Cancel has no Check
    auto late = co_await ctl->operate(on);
    CHECK(late.error() == add_cause::object_not_selected);
    auto cancel_again = co_await ctl->cancel();
    CHECK(cancel_again.error() == add_cause::object_not_selected);

    // Select timeout (sboTimeout on the server).
    REQUIRE(server.set_value("IED1LD1", "GGIO1$CF$SPCSO2$sboTimeout", mms::data::unsigned_integer(50)));
    auto sel3 = co_await ctl->select();
    REQUIRE(sel3);
    co_await client_test::sleep(120ms);
    CHECK(!server.selected("GGIO1.SPCSO2"));
    auto expired = co_await ctl->operate(on);
    CHECK(expired.error() == add_cause::object_not_selected);

    // The other client may select it now.
    auto rival_sel2 = co_await rival->select();
    CHECK(rival_sel2);

    // A status-only object refuses everything locally.
    REQUIRE(server.set_value("IED1LD1", "GGIO1$CF$SPCSO2$ctlModel", mms::data::integer(0)));
    auto status = co_await c.get_control(ref("IED1LD1/GGIO1.SPCSO2"));
    REQUIRE(status);
    CHECK(status->ctl_model() == model::ctl_model::status_only);
    CHECK(!status->structure());
    auto status_op = co_await status->operate(on);
    CHECK(status_op.error() == client::errc::control_model_mismatch);
    auto status_once = co_await c.operate(ref("IED1LD1/GGIO1.SPCSO2"), on);
    CHECK(status_once.error() == client::errc::control_model_mismatch);
  });
}

TEST_CASE("direct-with-enhanced-security control", "[client][control]") {
  run([]() -> awaitable<void> {
    testing::fake_server server(co_await asio::this_coro::executor);
    REQUIRE(server.start());
    auto c = co_await connect(options_for(server));

    auto ctl = co_await c.get_control(ref("IED1LD1/GGIO1.SPCSO3"));
    REQUIRE(ctl);
    CHECK(ctl->ctl_model() == model::ctl_model::direct_with_enhanced_security);
    CHECK(ctl->has_oper_time() == true);

    // Positive termination.
    auto op = co_await ctl->operate(on);
    REQUIRE(op);
    CHECK(server.value("IED1LD1", "GGIO1$ST$SPCSO3$stVal") == on);

    // operTm (time-activated operate).
    client::control_options timed;
    const auto when = model::timestamp::from_time_point(
                          std::chrono::sys_seconds{std::chrono::seconds{1700000000}})
                          .value();
    timed.oper_time = when;
    auto at = co_await ctl->operate(off, timed);
    REQUIRE(at);
    const auto req = server.last_control_request("GGIO1.SPCSO3");
    // { ctlVal, operTm, origin, ctlNum, T, Test, Check }
    CHECK(part(req, 1) == when.to_mms());
    CHECK(ctl_num_of(req, 3) == 1);

    // Negative termination: the AddCause of its LastApplError.
    REQUIRE(server.set_command_termination("GGIO1.SPCSO3", mode::negative, 16));
    auto neg = co_await ctl->operate(on);
    CHECK(neg.error() == add_cause::time_limit_over);
    const auto e = ctl->last_error();
    REQUIRE(e);
    CHECK(e->cause == add_cause::time_limit_over);
    CHECK(e->ctl_num == 2);
    CHECK(server.operations("GGIO1.SPCSO3") == 3);  // accepted, then terminated negatively

    // No termination at all.
    REQUIRE(server.set_command_termination("GGIO1.SPCSO3", mode::none));
    client::control_options quick;
    quick.termination_timeout = 100ms;
    auto silent = co_await ctl->operate(on, quick);
    CHECK(silent.error() == client::errc::termination_timeout);

    // A late termination from an earlier operation does not complete the next one: messages
    // are cleared when an operation starts.
    REQUIRE(server.set_command_termination("GGIO1.SPCSO3", mode::positive, 16, 200ms));
    auto slow = co_await ctl->operate(on, quick);
    CHECK(slow.error() == client::errc::termination_timeout);
    co_await client_test::sleep(250ms);
    REQUIRE(server.set_command_termination("GGIO1.SPCSO3", mode::positive));
    auto fine = co_await ctl->operate(off);
    CHECK(fine);

    // Cancel exists in direct-with-enhanced-security.
    auto cancelled = co_await ctl->cancel();
    CHECK(cancelled);
    CHECK(server.cancellations("GGIO1.SPCSO3") == 1);

    // Without the structure, operTm is sent only when requested.
    client::control_config cfg;
    cfg.read_structure = false;
    auto blind = co_await c.get_control(ref("IED1LD1/GGIO1.SPCSO3"), cfg);
    REQUIRE(blind);
    CHECK(!blind->has_oper_time());
    auto shape = co_await blind->operate(on);
    CHECK(shape.error() == client::errc::type_inconsistent);
    auto blind_timed = co_await blind->operate(on, timed);
    CHECK(blind_timed);
  });
}

TEST_CASE("sbo-with-enhanced-security control", "[client][control]") {
  run([]() -> awaitable<void> {
    testing::fake_server server(co_await asio::this_coro::executor);
    REQUIRE(server.start());
    auto c = co_await connect(options_for(server));
    auto other = co_await connect(options_for(server));

    auto ctl = co_await c.get_control(ref("IED1LD1/XCBR1.Pos"));
    REQUIRE(ctl);
    CHECK(ctl->ctl_model() == model::ctl_model::sbo_with_enhanced_security);
    CHECK(ctl->sbo_timeout() == 30000ms);
    auto plain = co_await ctl->select();
    CHECK(plain.error() == client::errc::control_model_mismatch);

    // SelectWithValue then Operate with the same ctlNum; positive termination.
    auto sel = co_await ctl->select_with_value(on);
    REQUIRE(sel);
    CHECK(ctl->selected());
    CHECK(server.selected("XCBR1.Pos"));
    CHECK(server.value("IED1LD1", "XCBR1$ST$Pos$stSeld") == mms::data::boolean(true));
    const auto num = ctl_num_of(server.last_control_request("XCBR1.Pos"), 2);
    auto op = co_await ctl->operate(on);
    REQUIRE(op);
    CHECK(ctl_num_of(server.last_control_request("XCBR1.Pos"), 2) == num);
    CHECK(client::to_dbpos(*server.value("IED1LD1", "XCBR1$ST$Pos$stVal")).value() ==
          model::dbpos::on);
    CHECK(!server.selected("XCBR1.Pos"));
    CHECK(!ctl->selected());

    // Operate without a selection.
    auto unselected = co_await ctl->operate(off);
    CHECK(unselected.error() == add_cause::object_not_selected);

    // Operate parameters differing from the SelectWithValue.
    auto sel2 = co_await ctl->select_with_value(off);
    REQUIRE(sel2);
    client::control_options wrong;
    wrong.ctl_num = static_cast<std::uint8_t>(ctl->ctl_num() + 1);
    auto mismatch = co_await ctl->operate(off, wrong);
    CHECK(mismatch.error() == add_cause::inconsistent_parameters);
    CHECK(ctl->last_error()->ctl_num == wrong.ctl_num);
    CHECK(server.selected("XCBR1.Pos"));

    // Selected by another client.
    auto rival = co_await other.get_control(ref("IED1LD1/XCBR1.Pos"));
    REQUIRE(rival);
    auto rival_sel = co_await rival->select_with_value(on);
    CHECK(rival_sel.error() == add_cause::object_already_selected);
    CHECK(rival->last_error()->cause == add_cause::object_already_selected);

    // Cancel with the selection's ctlVal and ctlNum.
    auto cancelled = co_await ctl->cancel();
    REQUIRE(cancelled);
    CHECK(!server.selected("XCBR1.Pos"));
    const auto cancel_req = server.last_control_request("XCBR1.Pos");
    CHECK(part(cancel_req, 0) == off);
    CHECK(ctl_num_of(cancel_req, 2) == ctl->ctl_num());

    // Interlocking checked at selection.
    REQUIRE(server.set_interlocked("XCBR1.Pos", true));
    client::control_options checked;
    checked.check = model::check_conditions(false, true);
    auto blocked = co_await ctl->select_with_value(on, checked);
    CHECK(blocked.error() == add_cause::blocked_by_interlocking);
    REQUIRE(server.set_interlocked("XCBR1.Pos", false));

    // Negative termination ends the sequence.
    REQUIRE(server.set_command_termination("XCBR1.Pos", mode::negative, 17));
    auto sel3 = co_await ctl->select_with_value(off);
    REQUIRE(sel3);
    auto neg = co_await ctl->operate(off);
    CHECK(neg.error() == add_cause::abortion_by_trip);
    CHECK(!ctl->selected());
  });
}

TEST_CASE("one-shot operate follows the control model", "[client][control]") {
  run([]() -> awaitable<void> {
    testing::fake_server server(co_await asio::this_coro::executor);
    REQUIRE(server.start());
    auto c = co_await connect(options_for(server));

    for (const char* object : {"GGIO1.SPCSO1", "GGIO1.SPCSO2", "GGIO1.SPCSO3", "XCBR1.Pos"}) {
      INFO(object);
      auto r = co_await c.operate(client_test::ref(std::string("IED1LD1/") + object), on);
      CHECK(r);
      CHECK(server.operations(object) == 1);
    }
    CHECK(client::to_dbpos(*server.value("IED1LD1", "XCBR1$ST$Pos$stVal")).value() ==
          model::dbpos::on);

    REQUIRE(server.set_interlocked("XCBR1.Pos", true));
    client::control_options checked;
    checked.check.set_interlock_check(true);
    auto blocked = co_await c.operate(ref("IED1LD1/XCBR1.Pos"), off, checked);
    CHECK(blocked.error() == add_cause::blocked_by_interlocking);

    auto missing = co_await c.operate(ref("IED1LD1/GGIO1.Nope"), on);
    CHECK(missing.error() == client::errc::object_not_found);
  });
}

TEST_CASE("waiting for a command termination", "[client][control]") {
  run([]() -> awaitable<void> {
    testing::fake_server server(co_await asio::this_coro::executor);
    REQUIRE(server.start());
    auto c = co_await connect(options_for(server));
    auto ctl = co_await c.get_control(ref("IED1LD1/GGIO1.SPCSO3"));
    REQUIRE(ctl);
    REQUIRE(server.set_command_termination("GGIO1.SPCSO3", mode::none));

    // One operation at a time per object.
    std::optional<result<void>> first;
    openiec61850::transport::spawn(c.get_executor(), ctl->operate(on),
                                   [&](result<void> r) { first.emplace(r); });
    while (server.operations("GGIO1.SPCSO3") == 0) co_await client_test::yield();
    auto second = co_await ctl->operate(off);
    CHECK(second.error() == openiec61850::errc::invalid_state);
    CHECK(!first);

    // Losing the association ends the wait with the loss error.
    server.drop_connections();
    while (!first) co_await client_test::yield();
    REQUIRE(!*first);
    CHECK(first->error() != client::errc::termination_timeout);
    auto after = co_await ctl->operate(on);
    CHECK(after.error() == client::errc::not_connected);
  });
}
