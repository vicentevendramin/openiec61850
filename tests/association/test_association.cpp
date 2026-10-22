#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <exception>
#include <future>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <asio/bind_cancellation_slot.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/io_context.hpp>
#include <asio/post.hpp>
#include <asio/steady_timer.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>

#include "openiec61850/association/association.hpp"
#include "openiec61850/transport/io_runtime.hpp"

using openiec61850::byte_buffer;
using openiec61850::result;
using namespace openiec61850::association;
namespace mms = openiec61850::mms;
namespace acse = openiec61850::iso::acse;
namespace transport = openiec61850::transport;
using asio::awaitable;
using asio::ip::tcp;
using namespace std::chrono_literals;

// Note: GCC evaluates a co_await inside a Catch2 assertion macro twice, so results are always
// stored in a variable before being checked.

namespace {

const tcp::endpoint any_loopback{asio::ip::address_v4::loopback(), 0};

void run(awaitable<void> (*test)()) {
  asio::io_context ctx;
  std::exception_ptr failure;
  bool done = false;
  asio::co_spawn(ctx, test(), [&](std::exception_ptr e) {
    failure = e;
    done = true;
  });
  ctx.run_for(5s);
  REQUIRE(done);
  if (failure) std::rethrow_exception(failure);
}

awaitable<void> yield() {
  co_await asio::post(co_await asio::this_coro::executor, asio::use_awaitable);
}

awaitable<void> sleep(std::chrono::milliseconds d) {
  asio::steady_timer t(co_await asio::this_coro::executor, d);
  co_await t.async_wait(asio::use_awaitable);
}

template <typename T>
awaitable<T> wait_for(std::optional<T>& slot) {
  while (!slot) co_await yield();
  co_return std::move(*slot);
}

association_params client_params() {
  association_params p;
  p.transport.connect_timeout = 1s;
  p.transport.handshake_timeout = 1s;
  p.association_timeout = 1s;
  p.request_timeout = 2s;
  p.release_timeout = 1s;
  return p;
}

server_options server_opts() {
  server_options o;
  o.transport.handshake_timeout = 1s;
  o.association_timeout = 1s;
  return o;
}

struct connected {
  result<client_association> client;
  result<server_association> server;
};

awaitable<connected> try_connect(association_params cp = client_params(), server_options so = server_opts()) {
  const auto ex = co_await asio::this_coro::executor;
  auto listener = association_listener::listen(ex, any_loopback, std::move(so));
  REQUIRE(listener);
  std::optional<result<server_association>> accepted;
  asio::co_spawn(
      ex,
      [](association_listener& l, std::optional<result<server_association>>& out) -> awaitable<void> {
        out.emplace(co_await l.accept());
      }(*listener, accepted),
      asio::detached);
  cp.port = listener->local_endpoint().port();
  auto client = co_await client_association::connect(ex, std::move(cp));
  auto server = co_await wait_for(accepted);
  co_return connected{std::move(client), std::move(server)};
}

struct pair {
  client_association client;
  server_association server;
};

awaitable<pair> connect_pair(association_params cp = client_params(), server_options so = server_opts()) {
  auto c = co_await try_connect(std::move(cp), std::move(so));
  REQUIRE(c.client);
  REQUIRE(c.server);
  co_return pair{std::move(*c.client), std::move(*c.server)};
}

// A Read of the vmd-specific variable "v<n>"; the test server answers with integer n. Not
// copyable: the request views `name`.
struct read_of {
  explicit read_of(int n) : name("v" + std::to_string(n)), vars{mms::variable_spec(mms::object_name::vmd(name))} {}
  read_of(const read_of&) = delete;
  read_of& operator=(const read_of&) = delete;
  mms::confirmed_service_request request() const {
    return mms::read_request{false, mms::variable_access_specification::list(vars)};
  }
  std::string name;
  std::vector<mms::variable_spec> vars;
};

int requested_index(const incoming_request& r) {
  const auto& rr = std::get<mms::read_request>(r.service());
  const auto item = (*rr.spec.variables.begin()).name.item_id;
  return std::stoi(std::string(item.substr(1)));
}

awaitable<result<void>> answer_read(incoming_request& r) {
  const auto value = mms::data::integer(requested_index(r));
  const std::vector<mms::access_result> results{mms::access_result(mms::data_ref(value))};
  co_return co_await r.respond(mms::read_response{std::nullopt, results});
}

std::int64_t read_value(const service_response& r) {
  const auto& rr = std::get<mms::read_response>(r.service());
  const auto ar = *rr.results.begin();
  return *ar.value.view().as_int64();
}

// Serves Reads until the association ends.
awaitable<void> serve_reads(server_association& s) {
  for (;;) {
    auto r = co_await s.next_request();
    if (!r) co_return;
    const auto sent = co_await answer_read(*r);
    if (!sent) co_return;
  }
}

mms::information_report report(const mms::data& value, std::vector<mms::access_result>& storage) {
  storage = {mms::access_result(mms::data_ref(value))};
  return mms::information_report{mms::variable_access_specification::named(mms::object_name::vmd("RPT")),
                                 storage};
}

std::int64_t report_value(const unconfirmed_message& m) {
  const auto* r = m.information_report();
  REQUIRE(r != nullptr);
  return *(*r->results.begin()).value.view().as_int64();
}

}  // namespace

TEST_CASE("association establishment negotiates the Initiate parameters", "[association]") {
  run([]() -> awaitable<void> {
    auto so = server_opts();
    so.limits.local_detail_called = 32000;
    so.limits.max_serv_outstanding_calling = 3;
    so.limits.max_serv_outstanding_called = 4;
    so.limits.data_structure_nesting_level = 6;
    so.limits.detail.parameter_cbb =
        mms::support_options(mms::parameter_cbb::bit_count, {mms::parameter_cbb::str1, mms::parameter_cbb::vnam,
                                                             mms::parameter_cbb::real});
    so.limits.detail.services = mms::support_options(mms::service_bit::bit_count,
                                                     {mms::service_bit::read, mms::service_bit::identify});
    so.ap_title = openiec61850::ber::oid{1, 3, 9999, 33};
    so.ae_qualifier = 33;
    std::optional<association_request> seen;
    so.authorize = [&seen](const association_request& r, mms::initiate_response& n) {
      seen = r;
      CHECK(n.max_serv_outstanding_calling == 3);
      return association_decision::accepted();
    };
    auto cp = client_params();
    cp.initiate.max_serv_outstanding_called = 2;

    auto [client, server] = co_await connect_pair(cp, so);
    CHECK(client.state() == association_state::established);
    CHECK(server.state() == association_state::established);

    const auto& n = client.info().negotiated;
    CHECK(n.local_detail_calling == 65000);
    CHECK(n.local_detail_called == 32000);
    CHECK(n.max_serv_outstanding_calling == 3);
    CHECK(n.max_serv_outstanding_called == 2);
    CHECK(n.data_structure_nesting_level == 6);
    CHECK(n.version_number == 1);
    CHECK(n.parameter_cbb.test(mms::parameter_cbb::str1));
    CHECK(n.parameter_cbb.test(mms::parameter_cbb::vnam));
    CHECK_FALSE(n.parameter_cbb.test(mms::parameter_cbb::str2));  // not offered by the server
    CHECK_FALSE(n.parameter_cbb.test(mms::parameter_cbb::real));  // not proposed by the client
    CHECK(n.services_supported_called.test(mms::service_bit::read));
    CHECK_FALSE(n.services_supported_called.test(mms::service_bit::write));
    CHECK(n.services_supported_calling == mms::iec61850_services);
    CHECK(client.info().peer_ap_title == openiec61850::ber::oid{1, 3, 9999, 33});
    CHECK(client.info().peer_ae_qualifier == 33);
    CHECK(client.info().remote_endpoint == server.info().local_endpoint);

    const auto& sn = server.info().negotiated;
    CHECK(sn.max_serv_outstanding_calling == 3);
    CHECK(sn.max_serv_outstanding_called == 2);
    CHECK(sn.local_detail_calling == 65000);
    CHECK(server.info().peer_ap_title == default_ap_title);
    CHECK(server.info().peer_ae_qualifier == default_ae_qualifier);

    REQUIRE(seen);
    CHECK(seen->calling_ap_title == default_ap_title);
    CHECK(seen->called_ap_title == default_ap_title);
    CHECK(seen->called_ae_qualifier == 12);
    CHECK_FALSE(seen->password);
    CHECK(seen->initiate.max_serv_outstanding_calling == 5);
    CHECK(seen->initiate.local_detail_calling == 65000);
    CHECK(seen->remote_endpoint == client.info().local_endpoint);
    CHECK(server.peer_request().initiate.max_serv_outstanding_called == 2);

    // A first exchange: Identify.
    std::optional<result<void>> answered;
    asio::co_spawn(
        co_await asio::this_coro::executor,
        [](server_association& s, std::optional<result<void>>& out) -> awaitable<void> {
          auto r = co_await s.next_request();
          REQUIRE(r);
          CHECK(std::holds_alternative<mms::identify_request>(r->service()));
          out.emplace(co_await r->respond(mms::identify_response{"vendor", "model", "1.0", {}}));
        }(server, answered),
        asio::detached);
    auto id = co_await client.request(mms::identify_request{});
    REQUIRE(id);
    const auto& ir = std::get<mms::identify_response>(id->service());
    CHECK(ir.vendor_name == "vendor");
    CHECK(ir.revision == "1.0");
    const auto ok = co_await wait_for(answered);
    CHECK(ok);
  });
}

TEST_CASE("association password authentication", "[association]") {
  run([]() -> awaitable<void> {
    auto so = server_opts();
    so.authorize = [](const association_request& r, mms::initiate_response&) {
      if (r.password != "secret" || r.mechanism_name != acse::oids::password_mechanism) {
        return association_decision::rejected(acse::service_user_diagnostic::authentication_failure);
      }
      return association_decision::accepted();
    };

    auto cp = client_params();
    cp.password = "secret";
    auto good = co_await try_connect(cp, so);
    REQUIRE(good.client);
    REQUIRE(good.server);
    CHECK(good.server->peer_request().password == "secret");

    cp.password = "wrong";
    auto bad = co_await try_connect(cp, so);
    CHECK(bad.client.error() == errc::authentication_failed);
    CHECK(bad.server.error() == errc::authentication_failed);

    cp.password.reset();
    auto none = co_await try_connect(cp, so);
    CHECK(none.client.error() == errc::authentication_failed);

    so.authorize = [](const association_request&, mms::initiate_response&) {
      return association_decision::rejected(acse::service_user_diagnostic::calling_ap_title_not_recognized);
    };
    auto rejected = co_await try_connect(client_params(), so);
    CHECK(rejected.client.error() == errc::association_rejected);
    CHECK(rejected.server.error() == errc::association_rejected);
  });
}

TEST_CASE("pipelined requests answered out of order are correlated", "[association]") {
  run([]() -> awaitable<void> {
    constexpr int count = 120;
    auto cp = client_params();
    cp.initiate.max_serv_outstanding_calling = 200;
    auto so = server_opts();
    so.limits.max_serv_outstanding_calling = 200;
    auto [client, server] = co_await connect_pair(cp, so);
    REQUIRE(client.info().negotiated.max_serv_outstanding_calling == 200);

    // The server collects every request, then answers them in reverse order.
    std::optional<bool> served;
    asio::co_spawn(
        co_await asio::this_coro::executor,
        [](server_association& s, std::optional<bool>& out) -> awaitable<void> {
          std::vector<incoming_request> held;
          while (held.size() < count) {
            auto r = co_await s.next_request();
            REQUIRE(r);
            held.push_back(std::move(*r));
          }
          std::reverse(held.begin(), held.end());
          for (auto& r : held) {
            const auto sent = co_await answer_read(r);
            REQUIRE(sent);
          }
          out = true;
        }(server, served),
        asio::detached);

    int ok = 0;
    for (int i = 0; i < count; ++i) {
      asio::co_spawn(
          co_await asio::this_coro::executor,
          [](client_association& c, int n, int& done) -> awaitable<void> {
            const read_of read(n);
            auto r = co_await c.request(read.request());
            REQUIRE(r);
            CHECK(read_value(*r) == n);
            ++done;
          }(client, i, ok),
          asio::detached);
    }
    (void)co_await wait_for(served);
    while (ok < count) co_await yield();
  });
}

TEST_CASE("requests beyond the negotiated maximum wait for a free slot", "[association]") {
  run([]() -> awaitable<void> {
    auto so = server_opts();
    so.limits.max_serv_outstanding_calling = 2;
    auto [client, server] = co_await connect_pair(client_params(), so);
    REQUIRE(client.info().negotiated.max_serv_outstanding_calling == 2);

    // The server answers only once it holds two requests, and lingers before answering: a third
    // request sent meanwhile would be rejected (max-serv-outstanding-exceeded).
    std::optional<bool> served;
    asio::co_spawn(
        co_await asio::this_coro::executor,
        [](server_association& s, std::optional<bool>& out) -> awaitable<void> {
          for (int round = 0; round < 5; ++round) {
            auto a = co_await s.next_request();
            auto b = co_await s.next_request();
            REQUIRE(a);
            REQUIRE(b);
            co_await sleep(5ms);
            const auto rb = co_await answer_read(*b);
            const auto ra = co_await answer_read(*a);
            REQUIRE(rb);
            REQUIRE(ra);
          }
          out = true;
        }(server, served),
        asio::detached);

    int ok = 0;
    for (int i = 0; i < 10; ++i) {
      asio::co_spawn(
          co_await asio::this_coro::executor,
          [](client_association& c, int n, int& done) -> awaitable<void> {
            const read_of read(n);
            auto r = co_await c.request(read.request());
            REQUIRE(r);
            CHECK(read_value(*r) == n);
            ++done;
          }(client, i, ok),
          asio::detached);
    }
    (void)co_await wait_for(served);
    while (ok < 10) co_await yield();
  });
}

TEST_CASE("confirmed errors and rejects map to request errors", "[association]") {
  run([]() -> awaitable<void> {
    auto [client, server] = co_await connect_pair();
    asio::co_spawn(
        co_await asio::this_coro::executor,
        [](server_association& s) -> awaitable<void> {
          auto r = co_await s.next_request();
          REQUIRE(r);
          mms::service_error e(mms::error_class::access, mms::error_code::access::object_non_existent);
          e.additional_code = 7;
          e.additional_description = "no such variable";
          const auto a = co_await r->respond_error(e, 1U);
          CHECK(a);
          const auto again = co_await r->respond_error(e);
          CHECK(again.error() == openiec61850::errc::invalid_state);

          r = co_await s.next_request();
          REQUIRE(r);
          const auto b = co_await r->reject(mms::reject_code::confirmed_request::invalid_argument);
          CHECK(b);

          // Dropped without an answer: a Confirmed-ErrorPDU service/other.
          r = co_await s.next_request();
          REQUIRE(r);
        }(server),
        asio::detached);

    const read_of read(1);
    auto r = co_await client.request(read.request());
    REQUIRE_FALSE(r);
    CHECK(r.error() == errc::service_error);
    REQUIRE(r.failure().service_error);
    const auto& se = *r.failure().service_error;
    CHECK(se.cls == mms::error_class::access);
    CHECK(se.code == mms::error_code::access::object_non_existent);
    CHECK(se.additional_code == 7);
    CHECK(se.additional_description == "no such variable");
    CHECK(r.failure().modifier_position == 1U);

    r = co_await client.request(read.request());
    REQUIRE_FALSE(r);
    CHECK(r.error() == errc::request_rejected);
    REQUIRE(r.failure().reject);
    CHECK(r.failure().reject->type == mms::reject_type::confirmed_request);
    CHECK(r.failure().reject->reason == mms::reject_code::confirmed_request::invalid_argument);
    CHECK(r.failure().reject->original_invoke_id.has_value());

    r = co_await client.request(read.request());
    REQUIRE_FALSE(r);
    CHECK(r.error() == errc::service_error);
    REQUIRE(r.failure().service_error);
    CHECK(r.failure().service_error->cls == mms::error_class::service);
  });
}

TEST_CASE("request timeout and cancellation abandon the request", "[association]") {
  run([]() -> awaitable<void> {
    auto [client, server] = co_await connect_pair();
    struct script {
      int received = 0;
      bool go = false;
      bool done = false;
    } sc;
    asio::co_spawn(
        co_await asio::this_coro::executor,
        [](server_association& s, script& st) -> awaitable<void> {
          auto timed_out = co_await s.next_request();
          REQUIRE(timed_out);
          ++st.received;
          auto cancelled = co_await s.next_request();
          REQUIRE(cancelled);
          ++st.received;
          while (!st.go) co_await yield();
          // Late answers, then a normal one.
          const auto a = co_await answer_read(*timed_out);
          const auto b = co_await answer_read(*cancelled);
          CHECK(a);
          CHECK(b);
          auto next = co_await s.next_request();
          REQUIRE(next);
          const auto c = co_await answer_read(*next);
          CHECK(c);
          st.done = true;
        }(server, sc),
        asio::detached);

    const read_of first(1);
    auto r = co_await client.request(first.request(), 30ms);
    CHECK(r.error() == errc::request_timed_out);

    asio::cancellation_signal signal;
    std::optional<request_result> cancelled;
    const read_of second(2);
    asio::co_spawn(
        co_await asio::this_coro::executor,
        [](client_association& c, const read_of& rd, std::optional<request_result>& out) -> awaitable<void> {
          out.emplace(co_await c.request(rd.request()));
        }(client, second, cancelled),
        asio::bind_cancellation_slot(signal.slot(), asio::detached));
    while (sc.received < 2) co_await yield();
    signal.emit(asio::cancellation_type::terminal);
    auto c = co_await wait_for(cancelled);
    CHECK(c.error() == asio::error::operation_aborted);
    sc.go = true;

    // The late answers are discarded; correlation keeps working.
    const read_of third(3);
    r = co_await client.request(third.request());
    REQUIRE(r);
    CHECK(read_value(*r) == 3);
    CHECK(client.state() == association_state::established);
    while (!sc.done) co_await yield();
  });
}

TEST_CASE("information reports are queued with a drop-oldest overflow policy", "[association]") {
  run([]() -> awaitable<void> {
    auto cp = client_params();
    cp.unconfirmed_queue_capacity = 3;
    auto [client, server] = co_await connect_pair(cp);
    bool done = false;

    // Five reports precede the Identify response on the same stream.
    asio::co_spawn(
        co_await asio::this_coro::executor,
        [](server_association& s, bool& finished) -> awaitable<void> {
          auto r = co_await s.next_request();
          REQUIRE(r);
          std::vector<mms::access_result> storage;
          for (int i = 1; i <= 5; ++i) {
            const auto v = mms::data::integer(i);
            const auto sent = co_await s.send_unconfirmed(report(v, storage));
            REQUIRE(sent);
          }
          const auto a = co_await r->respond(mms::identify_response{"v", "m", "r", {}});
          REQUIRE(a);
          finished = true;
        }(server, done),
        asio::detached);
    auto id = co_await client.request(mms::identify_request{});
    REQUIRE(id);
    while (!done) co_await yield();

    CHECK(client.unconfirmed_dropped() == 2);
    auto m = co_await client.next_unconfirmed();
    REQUIRE(m);
    CHECK(m->lost_before() == 2);
    CHECK(report_value(*m) == 3);
    const auto* rpt = m->information_report();
    REQUIRE(rpt != nullptr);
    CHECK(rpt->spec.list_name.item_id == "RPT");
    m = co_await client.next_unconfirmed();
    REQUIRE(m);
    CHECK(m->lost_before() == 0);
    CHECK(report_value(*m) == 4);

    // Switching to a handler flushes the queue into it, then delivers new reports directly.
    std::vector<std::int64_t> handled;
    client.set_unconfirmed_handler([&handled](unconfirmed_message msg) { handled.push_back(report_value(msg)); });
    std::vector<mms::access_result> storage;
    const auto six = mms::data::integer(6);
    const auto sent = co_await server.send_unconfirmed(report(six, storage));
    REQUIRE(sent);
    while (handled.size() < 2) co_await yield();
    CHECK(handled == std::vector<std::int64_t>{5, 6});
  });
}

TEST_CASE("orderly release with Conclude and RLRQ/RLRE", "[association]") {
  run([]() -> awaitable<void> {
    auto [client, server] = co_await connect_pair();
    std::optional<std::error_code> server_closed;
    asio::co_spawn(
        co_await asio::this_coro::executor,
        [](server_association& s, std::optional<std::error_code>& out) -> awaitable<void> {
          co_await serve_reads(s);
          const auto next = co_await s.next_request();
          CHECK(next.error() == errc::released);
          out.emplace(co_await s.wait_closed());
        }(server, server_closed),
        asio::detached);

    const read_of read(9);
    auto r = co_await client.request(read.request());
    REQUIRE(r);
    const auto released = co_await client.release();
    REQUIRE(released);
    CHECK(client.state() == association_state::closed);
    const auto closed = co_await client.wait_closed();
    CHECK(closed == errc::released);
    const auto s = co_await wait_for(server_closed);
    CHECK(s == errc::released);
    CHECK(server.state() == association_state::closed);

    r = co_await client.request(read.request());
    CHECK(r.error() == errc::released);
    const auto twice = co_await client.release();
    CHECK(twice.error() == errc::released);
  });
}

TEST_CASE("release waits for outstanding requests", "[association]") {
  run([]() -> awaitable<void> {
    auto [client, server] = co_await connect_pair();
    std::optional<incoming_request> held;
    asio::co_spawn(
        co_await asio::this_coro::executor,
        [](server_association& s, std::optional<incoming_request>& out) -> awaitable<void> {
          auto r = co_await s.next_request();
          REQUIRE(r);
          out.emplace(std::move(*r));
        }(server, held),
        asio::detached);

    std::optional<request_result> answer;
    const read_of read(4);
    asio::co_spawn(
        co_await asio::this_coro::executor,
        [](client_association& c, const read_of& rd, std::optional<request_result>& out) -> awaitable<void> {
          out.emplace(co_await c.request(rd.request()));
        }(client, read, answer),
        asio::detached);
    while (!held) co_await yield();

    std::optional<result<void>> released;
    asio::co_spawn(
        co_await asio::this_coro::executor,
        [](client_association& c, std::optional<result<void>>& out) -> awaitable<void> {
          out.emplace(co_await c.release());
        }(client, released),
        asio::detached);
    co_await sleep(5ms);
    CHECK(client.state() == association_state::releasing);
    CHECK_FALSE(released);
    auto refused = co_await client.request(read.request());
    CHECK(refused.error() == openiec61850::errc::invalid_state);

    const auto sent = co_await answer_read(*held);
    REQUIRE(sent);
    auto a = co_await wait_for(answer);
    REQUIRE(a);
    CHECK(read_value(*a) == 4);
    const auto r = co_await wait_for(released);
    CHECK(r);
    const auto closed = co_await server.wait_closed();
    CHECK(closed == errc::released);
  });
}

TEST_CASE("abort from the client", "[association]") {
  run([]() -> awaitable<void> {
    auto [client, server] = co_await connect_pair();
    std::optional<result<incoming_request>> next;
    asio::co_spawn(
        co_await asio::this_coro::executor,
        [](server_association& s, std::optional<result<incoming_request>>& out) -> awaitable<void> {
          out.emplace(co_await s.next_request());
        }(server, next),
        asio::detached);
    co_await yield();
    client.abort();
    const auto c = co_await client.wait_closed();
    CHECK(c == errc::aborted);
    auto n = co_await wait_for(next);
    CHECK(n.error() == errc::peer_aborted);
    const auto s = co_await server.wait_closed();
    CHECK(s == errc::peer_aborted);
    const read_of read(1);
    auto r = co_await client.request(read.request());
    CHECK(r.error() == errc::aborted);
  });
}

TEST_CASE("abort from the server fails the pending requests", "[association]") {
  run([]() -> awaitable<void> {
    auto [client, server] = co_await connect_pair();
    bool done = false;
    asio::co_spawn(
        co_await asio::this_coro::executor,
        [](server_association& s, bool& finished) -> awaitable<void> {
          auto r = co_await s.next_request();
          REQUIRE(r);
          s.abort();
          const auto answered = co_await r->respond(mms::identify_response{"v", "m", "r", {}});
          CHECK(answered.error() == errc::aborted);
          finished = true;
        }(server, done),
        asio::detached);
    auto r = co_await client.request(mms::identify_request{});
    CHECK(r.error() == errc::peer_aborted);
    while (!done) co_await yield();
    const auto c = co_await client.wait_closed();
    CHECK(c == errc::peer_aborted);
    CHECK(client.state() == association_state::closed);
  });
}

TEST_CASE("server disappearing mid-request", "[association]") {
  run([]() -> awaitable<void> {
    auto [client, server] = co_await connect_pair();
    asio::co_spawn(
        co_await asio::this_coro::executor,
        [](server_association& s) -> awaitable<void> {
          auto r = co_await s.next_request();
          REQUIRE(r);
          s.close();  // TCP closed, no ABRT
        }(server),
        asio::detached);
    std::optional<request_result> unanswered;
    asio::co_spawn(
        co_await asio::this_coro::executor,
        [](client_association& c, std::optional<request_result>& out) -> awaitable<void> {
          out.emplace(co_await c.request(mms::identify_request{}));
        }(client, unanswered),
        asio::detached);
    auto r = co_await client.request(mms::identify_request{});
    REQUIRE_FALSE(r);
    CHECK(r.error() != errc::request_timed_out);
    auto u = co_await wait_for(unanswered);
    CHECK(u.error() == r.error());
    const auto c = co_await client.wait_closed();
    CHECK(c == r.error());
    CHECK((c == asio::error::eof || c == asio::error::connection_reset));
  });
}

TEST_CASE("client association driven from another thread", "[association]") {
  // The association lives on an io_runtime; the request is awaited from a coroutine on a context
  // run by another thread. Results are checked on the test thread.
  struct outcome {
    bool connected = false;
    std::optional<std::int64_t> value;
    std::atomic<bool> requested{false};
    bool released = false;
  } out;
  transport::io_runtime rt;
  rt.start();
  std::promise<void> finished;
  auto fut = finished.get_future();
  asio::co_spawn(
      rt.get_executor(),
      [](outcome& o) -> awaitable<void> {
        auto c = co_await try_connect();
        if (!c.client || !c.server) co_return;
        o.connected = true;
        asio::co_spawn(c.server->get_executor(), serve_reads(*c.server), asio::detached);
        asio::io_context local;
        asio::co_spawn(
            local,
            [](client_association& cl, outcome& oc) -> awaitable<void> {
              const read_of read(42);
              auto r = co_await cl.request(read.request());
              if (r) oc.value = read_value(*r);
              oc.requested = true;
            }(*c.client, o),
            asio::detached);
        std::thread t([&local] { local.run_for(2s); });
        for (int i = 0; i < 2000 && !o.requested; ++i) co_await sleep(1ms);
        t.join();
        o.released = static_cast<bool>(co_await c.client->release());
      }(out),
      [&finished](std::exception_ptr) { finished.set_value(); });
  REQUIRE(fut.wait_for(3s) == std::future_status::ready);
  rt.stop();
  rt.join();
  CHECK(out.connected);
  CHECK(out.value == 42);
  CHECK(out.released);
}
