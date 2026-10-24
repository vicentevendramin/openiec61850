#include <catch2/catch_test_macros.hpp>

#include <memory>
#include <optional>
#include <string>

#include "client_test_util.hpp"
#include "openiec61850/client/error_details.hpp"
#include "openiec61850/transport/spawn.hpp"

namespace association = openiec61850::association;
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

namespace {

testing::fake_server::injected_failure service_error(mms::error_class cls, std::int64_t code,
                                                     std::optional<std::int64_t> additional = {},
                                                     std::optional<std::string> text = {},
                                                     std::optional<std::uint32_t> modifier = {}) {
  association::service_error_info e;
  e.cls = cls;
  e.code = code;
  e.additional_code = additional;
  e.additional_description = std::move(text);
  return {e, modifier, 0};
}

}  // namespace

TEST_CASE("error details of Confirmed-ErrorPDUs and Rejects", "[client][error_details]") {
  run([]() -> awaitable<void> {
    testing::fake_server server(co_await asio::this_coro::executor);
    REQUIRE(server.start());
    auto c = co_await connect(options_for(server));
    const auto tot_w = ref("IED1LD0/MMXU1.TotW.mag.f[MX]");

    // A ServiceError with every optional field; the error code is unchanged.
    server.fail_next(mms::confirmed_service::read,
                     service_error(mms::error_class::access, mms::error_code::access::object_access_denied,
                                   42, "locked by the operator", 3));
    client::error_details d;
    auto denied = co_await c.read(tot_w, d);
    CHECK(denied.error() == client::errc::access_denied);
    CHECK(d.code == client::errc::access_denied);
    CHECK(d.from_server());
    REQUIRE(d.service_error);
    CHECK(d.service_error->cls == mms::error_class::access);
    CHECK(d.service_error->code == mms::error_code::access::object_access_denied);
    CHECK(d.service_error->additional_code == 42);
    CHECK(d.service_error->additional_description == "locked by the operator");
    CHECK(d.modifier_position == 3u);
    CHECK(!d.reject);
    CHECK(!d.last_appl_error);

    // A ServiceError without a client::errc mapping stays association::errc::service_error.
    server.fail_next(mms::confirmed_service::get_name_list,
                     service_error(mms::error_class::resource, mms::error_code::resource::memory_unavailable));
    auto busy = co_await c.get_server_directory(d);
    CHECK(busy.error() == association::errc::service_error);
    CHECK(d.code == association::errc::service_error);
    REQUIRE(d.service_error);
    CHECK(d.service_error->cls == mms::error_class::resource);
    CHECK(!d.service_error->additional_code);
    CHECK(!d.service_error->additional_description);
    CHECK(!d.modifier_position);

    // A Reject.
    server.fail_next(mms::confirmed_service::write,
                     {std::nullopt, std::nullopt, mms::reject_code::confirmed_request::invalid_argument});
    auto rejected = co_await c.write(ref("IED1LD0/MMXU1.TotW.db[CF]"),
                                     mms::data::unsigned_integer(5), d);
    CHECK(rejected.error() == association::errc::request_rejected);
    CHECK(d.code == association::errc::request_rejected);
    CHECK(!d.service_error);
    REQUIRE(d.reject);
    CHECK(d.reject->type == mms::reject_type::confirmed_request);
    CHECK(d.reject->reason == mms::reject_code::confirmed_request::invalid_argument);

    // Success clears the object; the overloads without details are unaffected.
    auto ok = co_await c.read(tot_w, d);
    CHECK(ok);
    CHECK(!d.code);
    CHECK(!d.from_server());
    server.fail_next(mms::confirmed_service::read,
                     service_error(mms::error_class::access, mms::error_code::access::object_non_existent));
    auto plain = co_await c.read(tot_w);
    CHECK(plain.error() == client::errc::object_not_found);

    // A multi-request operation keeps the details of the request that failed.
    server.fail_next(mms::confirmed_service::get_named_variable_list_attributes,
                     service_error(mms::error_class::definition,
                                   mms::error_code::definition::object_undefined, 7));
    client::report_settings rs;
    auto en = co_await c.enable_reporting(ref("IED1LD0/LLN0.urcb01[RP]"), rs, d);
    CHECK(en.error() == client::errc::object_not_found);
    REQUIRE(d.service_error);
    CHECK(d.service_error->additional_code == 7);

    // Local errors carry only the code.
    auto misuse = co_await c.read(ref("IED1LD0/MMXU1.TotW.mag.f"), d);
    CHECK(misuse.error() == openiec61850::errc::invalid_state);
    CHECK(d.code == openiec61850::errc::invalid_state);
    CHECK(!d.from_server());

    // Through the transport::spawn bridge, with the details owned by the handler.
    auto shared = std::make_shared<client::error_details>();
    server.fail_next(mms::confirmed_service::read,
                     service_error(mms::error_class::access, mms::error_code::access::object_invalidated, 9));
    std::optional<std::error_code> spawned;
    std::optional<std::int64_t> spawned_additional;
    openiec61850::transport::spawn(c.get_executor(), c.read(tot_w, *shared),
                                   [shared, &spawned, &spawned_additional](
                                       openiec61850::result<mms::data> r) {
                                     spawned = r.error();
                                     if (shared->service_error) {
                                       spawned_additional = shared->service_error->additional_code;
                                     }
                                   });
    for (int i = 0; i < 200 && !spawned; ++i) co_await client_test::sleep(5ms);
    REQUIRE(spawned);
    CHECK(*spawned == association::errc::service_error);
    CHECK(spawned_additional == 9);
  });
}

TEST_CASE("error details of control services", "[client][error_details][control]") {
  run([]() -> awaitable<void> {
    testing::fake_server server(co_await asio::this_coro::executor);
    REQUIRE(server.start());
    auto c = co_await connect(options_for(server));

    client::error_details d;
    auto ctl = co_await c.get_control(ref("IED1LD1/GGIO1.SPCSO1"), {}, d);
    REQUIRE(ctl);
    CHECK(!d.code);

    REQUIRE(server.set_interlocked("GGIO1.SPCSO1", true));
    client::control_options checked;
    checked.check.set_interlock_check(true);
    auto blocked = co_await ctl->operate(mms::data::boolean(true), checked, d);
    CHECK(blocked.error() == client::add_cause::blocked_by_interlocking);
    CHECK(d.code == client::add_cause::blocked_by_interlocking);
    REQUIRE(d.last_appl_error);
    CHECK(d.last_appl_error->cause == client::add_cause::blocked_by_interlocking);
    CHECK(d.last_appl_error->control_object == "IED1LD1/GGIO1$CO$SPCSO1$Oper");
    CHECK(d.from_server());

    // Negative CommandTermination through the one-shot operate().
    REQUIRE(server.set_command_termination("XCBR1.Pos", testing::fake_server::termination_mode::negative, 16));
    auto negative = co_await c.operate(ref("IED1LD1/XCBR1.Pos"), mms::data::boolean(true), {}, d);
    CHECK(negative.error() == client::add_cause::time_limit_over);
    REQUIRE(d.last_appl_error);
    CHECK(d.last_appl_error->cause == client::add_cause::time_limit_over);

    // A Reject of the Oper write.
    server.fail_next(mms::confirmed_service::write,
                     {std::nullopt, std::nullopt, mms::reject_code::confirmed_request::other});
    auto rejected = co_await ctl->operate(mms::data::boolean(false), {}, d);
    CHECK(rejected.error() == association::errc::request_rejected);
    REQUIRE(d.reject);
    CHECK(!d.last_appl_error);

    // get_control() errors.
    auto missing = co_await c.get_control(ref("IED1LD1/GGIO1.SPCSO9"), {}, d);
    CHECK(missing.error() == client::errc::object_not_found);
    CHECK(d.code == client::errc::object_not_found);

    client::control empty;
    auto none = co_await empty.cancel({}, d);
    CHECK(none.error() == openiec61850::errc::invalid_state);
    CHECK(d.code == openiec61850::errc::invalid_state);
  });
}
