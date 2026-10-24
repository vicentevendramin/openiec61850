#include <catch2/catch_test_macros.hpp>

#include <vector>

#include "server_test_util.hpp"

using namespace server_test;
using asio::awaitable;

namespace {

mms::data oper(bool value, std::uint64_t ctl_num, bool with_check = true) {
  std::vector<mms::data> f{
      mms::data::boolean(value),
      mms::data::structure({model::to_mms(model::orcat::remote_control),
                            mms::data::octet_string(openiec61850::byte_buffer{'o', 'p'})}),
      mms::data::unsigned_integer(ctl_num), model::timestamp::now().to_mms(), mms::data::boolean(false)};
  if (with_check) f.push_back(model::check_conditions{}.to_mms());
  return mms::data::structure(std::move(f));
}

std::vector<srv::control_request>& requests() {
  static std::vector<srv::control_request> r;
  return r;
}

srv::server_options control_options() {
  requests().clear();
  srv::server_options o;
  o.on_control = [](const srv::control_request& r) {
    requests().push_back(r);
    if (r.action == srv::control_action::operate && r.ctl_val == mms::data::boolean(false)) {
      return srv::control_result::refused(srv::add_cause::blocked_by_interlocking);
    }
    return srv::control_result::ok();
  };
  return o;
}

}  // namespace

TEST_CASE("Control: direct-normal operate through the application handler", "[server]") {
  run([]() -> awaitable<void> {
    auto s = start(co_await asio::this_coro::executor, control_options());
    auto c = co_await connect(options_for(s));
    auto ok = co_await c.write(oref("IED1LD0/XCBR1.Pos.Oper[CO]"), oper(true, 7));
    CHECK(ok);
    REQUIRE(requests().size() == 1);
    const auto& r = requests()[0];
    CHECK(r.action == srv::control_action::operate);
    CHECK(r.object == oref("IED1LD0/XCBR1.Pos"));
    CHECK(r.ctl_model == model::ctl_model::direct_with_normal_security);
    CHECK(r.ctl_val == mms::data::boolean(true));
    CHECK(r.or_cat == model::orcat::remote_control);
    CHECK(r.or_ident == openiec61850::byte_buffer{'o', 'p'});
    CHECK(r.ctl_num == 7U);
    CHECK(r.t);

    auto refused = co_await c.write(oref("IED1LD0/XCBR1.Pos.Oper[CO]"), oper(false, 8));
    CHECK(refused.error() == client::errc::access_denied);
    auto partial = co_await c.write(oref("IED1LD0/XCBR1.Pos.Oper.ctlVal[CO]"), mms::data::boolean(true));
    CHECK(partial.error() == client::errc::access_denied);
    auto malformed = co_await c.write(oref("IED1LD0/XCBR1.Pos.Oper[CO]"), mms::data::boolean(true));
    CHECK(malformed.error() == client::errc::type_inconsistent);
    s.stop();
  });
}

TEST_CASE("Control: sbo-normal select, operate, cancel and timeout", "[server]") {
  run([]() -> awaitable<void> {
    auto s = start(co_await asio::this_coro::executor, control_options());
    auto c = co_await connect(options_for(s));
    auto other = co_await connect(options_for(s));
    const auto sbo = oref("IED1LD0/CSWI1.Pos.SBO[CO]");
    const auto op = oref("IED1LD0/CSWI1.Pos.Oper[CO]");

    auto not_selected = co_await c.write(op, oper(true, 1));
    CHECK(not_selected.error() == client::errc::access_denied);

    auto sel = co_await c.read(sbo);
    REQUIRE(sel);
    CHECK(*sel == mms::data::visible_string("IED1LD0/CSWI1.Pos"));
    auto busy = co_await other.read(sbo);
    REQUIRE(busy);
    CHECK(*busy == mms::data::visible_string(""));
    auto foreign = co_await other.write(op, oper(true, 2));
    CHECK(foreign.error() == client::errc::access_denied);
    auto operated = co_await c.write(op, oper(true, 3));
    CHECK(operated);
    auto twice = co_await c.write(op, oper(true, 4));
    CHECK(twice.error() == client::errc::access_denied);  // deselected by the operate

    // Cancel deselects.
    auto sel2 = co_await c.read(sbo);
    CHECK(sel2);
    auto cancel = co_await c.write(oref("IED1LD0/CSWI1.Pos.Cancel[CO]"), oper(true, 5, false));
    CHECK(cancel);
    auto after_cancel = co_await c.write(op, oper(true, 6));
    CHECK(after_cancel.error() == client::errc::access_denied);

    // sboTimeout = 500 ms.
    auto sel3 = co_await c.read(sbo);
    CHECK(sel3);
    co_await sleep(600ms);
    auto late = co_await c.write(op, oper(true, 7));
    CHECK(late.error() == client::errc::access_denied);

    // A selection is released with its association.
    auto sel4 = co_await other.read(sbo);
    REQUIRE(sel4);
    CHECK(*sel4 == mms::data::visible_string("IED1LD0/CSWI1.Pos"));
    other.abort();
    co_await sleep(50ms);
    auto sel5 = co_await c.read(sbo);
    REQUIRE(sel5);
    CHECK(*sel5 == mms::data::visible_string("IED1LD0/CSWI1.Pos"));

    std::size_t selects = 0;
    for (const auto& r : requests()) selects += r.action == srv::control_action::select ? 1U : 0U;
    CHECK(selects == 5);
    s.stop();
  });
}
