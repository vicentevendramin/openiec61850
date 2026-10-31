// Peers that stop reading and applications that outrun the server: every queue towards a peer is
// bounded and the one association at fault pays for it (the real server and client on their own
// I/O threads, with a stall_proxy playing the peer that does not read).

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <future>
#include <memory>
#include <string>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#include <asio/use_future.hpp>

#include "openiec61850/transport/io_runtime.hpp"
#include "openiec61850/transport/tls.hpp"
#include "server_test_util.hpp"
#include "stall_proxy.hpp"

#ifdef OPENIEC61850_WITH_TLS
#include "../transport/tls_certs.hpp"
#endif

using namespace server_test;
using asio::awaitable;
namespace transport = openiec61850::transport;
using openiec61850::result;

namespace {

constexpr std::size_t limit = 1024 * 1024;
const char* const urcb02 = "IED1LD0/LLN0.urcb02[RP]";
const char* const brcb01 = "IED1LD0/LLN0.brcb01[BR]";
const char* const ind1 = "IED1LD0/GGIO1.Ind1.stVal[ST]";
const auto no_stall = std::chrono::milliseconds::zero();

template <typename T>
T get(std::future<T> f, std::chrono::seconds within = 30s) {
  REQUIRE(f.wait_for(within) == std::future_status::ready);
  return f.get();
}

// Runs an operation on `ex` and waits for its result, from the test thread.
template <typename T>
T await(asio::any_io_executor ex, awaitable<T> op) {
  auto p = std::make_shared<std::promise<T>>();
  auto f = p->get_future();
  asio::co_spawn(
      ex,
      [](std::shared_ptr<std::promise<T>> out, awaitable<T> a) -> awaitable<void> {
        out->set_value(co_await std::move(a));
      }(p, std::move(op)),
      asio::detached);
  return get(std::move(f));
}

template <typename Predicate>
bool wait_until(Predicate done, std::chrono::seconds within) {
  const auto end = std::chrono::steady_clock::now() + within;
  while (!done()) {
    if (std::chrono::steady_clock::now() >= end) return false;
    std::this_thread::sleep_for(1ms);
  }
  return true;
}

// The highest live_bytes() while it exists, above the value it started from.
class memory_watch {
 public:
  memory_watch() : base_(live_bytes()) {
    thread_ = std::thread([this] {
      while (!stop_.load()) {
        const auto now = live_bytes();
        if (now > peak_.load()) peak_ = now;
        std::this_thread::sleep_for(1ms);
      }
    });
  }
  ~memory_watch() { finish(); }
  memory_watch(const memory_watch&) = delete;
  memory_watch& operator=(const memory_watch&) = delete;

  std::size_t finish() {
    stop_ = true;
    if (thread_.joinable()) thread_.join();
    return peak_.load() > base_ ? peak_.load() - base_ : 0;
  }

 private:
  std::size_t base_;
  std::atomic<std::size_t> peak_{0};
  std::atomic<bool> stop_{false};
  std::thread thread_;
};

// Server and clients, each on its own I/O thread.
struct rig {
  explicit rig(srv::server_options o = {}) {
    server_rt.start();
    client_rt.start();
    o.association.transport.handshake_timeout = 10s;
    o.association.association_timeout = 10s;
    auto s = srv::server::start(server_rt.get_executor(), make_model(), loopback, std::move(o));
    REQUIRE(s);
    server = std::make_unique<srv::server>(std::move(*s));
  }
  ~rig() {
    server->stop();
    client_rt.stop();
    server_rt.stop();
    client_rt.join();
    server_rt.join();
  }
  rig(const rig&) = delete;
  rig& operator=(const rig&) = delete;

  [[nodiscard]] client::client_options client_options(std::uint16_t port) const {
    client::client_options o;
    o.association.port = port;
    o.association.transport.connect_timeout = 10s;
    o.association.transport.handshake_timeout = 10s;
    o.association.association_timeout = 10s;
    o.association.request_timeout = 20s;
    o.association.release_timeout = 2s;
    return o;
  }

  std::shared_ptr<client::client> connect_client(client::client_options o) {
    auto ex = client_rt.get_executor();
    auto c = await(ex, client::client::connect(ex, std::move(o)));
    REQUIRE(c);
    return std::make_shared<client::client>(std::move(*c));
  }

  void enable(client::client& c, const char* rcb, client::report_settings settings = {}) {
    auto r = await(client_rt.get_executor(), c.enable_reporting(oref(rcb), std::move(settings)));
    REQUIRE(r);
  }

  transport::io_runtime server_rt;
  transport::io_runtime client_rt;
  std::unique_ptr<srv::server> server;
};

// Changes the whole big data set: a report of a few KiB.
std::size_t update_big(srv::server& s, std::uint64_t n) {
  std::vector<srv::data_update> batch;
  const std::string text(240, static_cast<char>('a' + n % 26));
  for (std::size_t i = 1; i <= big_members; ++i) {
    batch.push_back({oref("IED1LD0/GGIO1.Str" + std::to_string(i) + ".stVal[ST]"),
                     mms::data::visible_string(text + std::to_string(n)), std::nullopt, std::nullopt});
  }
  const auto size = batch.size();
  return s.update(std::move(batch)) ? size : 0;
}

// Updates until `done`, as fast as the strand applies them.
template <typename Predicate>
bool load_until(srv::server& s, Predicate done, std::chrono::seconds within) {
  std::uint64_t n = 0;
  return wait_until(
      [&] {
        if (done()) return true;
        if (s.pending_updates() < 240) (void)update_big(s, n++);
        return false;
      },
      within);
}

struct reads {
  std::atomic<bool> stop{false};
  std::atomic<std::uint64_t> done{0};
  std::atomic<std::uint64_t> failed{0};
  std::atomic<std::int64_t> slowest_ms{0};
};

awaitable<void> keep_reading(std::shared_ptr<client::client> c, std::shared_ptr<reads> stats) {
  while (!stats->stop.load()) {
    const auto start = std::chrono::steady_clock::now();
    auto r = co_await c->read(oref(ind1));
    const auto took = std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::steady_clock::now() - start)
                          .count();
    if (took > stats->slowest_ms.load()) stats->slowest_ms = took;
    (r ? stats->done : stats->failed).fetch_add(1);
    asio::steady_timer t(co_await asio::this_coro::executor, 1ms);
    (void)co_await t.async_wait(asio::as_tuple(asio::use_awaitable));
  }
}

void stalled_report_consumer(srv::server_options options, client::client_options stalled_options) {
  rig r(std::move(options));
  stall_proxy proxy(r.server->local_endpoint());
  auto healthy_options = stalled_options;
  healthy_options.association.port = r.server->local_endpoint().port();
  stalled_options.association.port = proxy.port();
  auto healthy = r.connect_client(healthy_options);
  auto stalled = r.connect_client(stalled_options);
  r.enable(*stalled, urcb02);
  REQUIRE(r.server->association_count() == 2);

  auto stats = std::make_shared<reads>();
  auto reading = asio::co_spawn(r.client_rt.get_executor(), keep_reading(healthy, stats), asio::use_future);
  proxy.stall();
  memory_watch memory;
  const bool ended =
      load_until(*r.server, [&] { return r.server->association_count() == 1; }, 40s);
  const auto growth = memory.finish();
  stats->stop = true;
  get(std::move(reading));

  CHECK(ended);
  CHECK(r.server->slow_peer_aborts() == 1);
  // One limit in the server's queue, and what is being encoded and sent around it.
  CHECK(growth < 6 * limit);
  // The other association did not notice.
  CHECK(stats->done.load() > 0);
  CHECK(stats->failed.load() == 0);
  CHECK(stats->slowest_ms.load() < 5000);
  CHECK(healthy->state() == client::connection_state::established);
  auto after = await(r.client_rt.get_executor(), healthy->read(oref(ind1)));
  CHECK(after);
}

srv::server_options limited() {
  srv::server_options o;
  o.association.transport.max_output_bytes = limit;
  o.association.transport.write_stall_timeout = no_stall;
  return o;
}

}  // namespace

TEST_CASE("A peer that stops reading reports is aborted at the output limit", "[server][backpressure]") {
  rig defaults;
  stalled_report_consumer(limited(), defaults.client_options(0));
}

#ifdef OPENIEC61850_WITH_TLS
TEST_CASE("The output limit holds over TLS", "[server][backpressure][tls]") {
  tls_test::temp_dir dir;
  tls_test::certificate_authority ca(dir.path, "root");
  const auto server_keys = ca.issue("ied1", {"IP:127.0.0.1"});
  const auto client_keys = ca.issue("hmi");
  const auto context = [&](const tls_test::key_pair& keys, bool server) {
    transport::tls_config c;
    c.ca_file = ca.certificate();
    c.certificate_file = keys.certificate;
    c.private_key_file = keys.private_key;
    c.verify_peer_name = false;
    auto ctx = transport::tls_context::create(c, server);
    REQUIRE(ctx);
    return *ctx;
  };
  auto o = limited();
  o.association.transport.tls = context(server_keys, true);
  rig defaults;
  auto co = defaults.client_options(0);
  co.association.transport.tls = context(client_keys, false);
  stalled_report_consumer(std::move(o), std::move(co));
}
#endif

TEST_CASE("A flood of requests from a peer that does not read is aborted", "[server][backpressure]") {
  rig r(limited());
  stall_proxy proxy(r.server->local_endpoint());
  auto o = r.client_options(proxy.port());
  auto c = r.connect_client(o);
  auto v = await(r.client_rt.get_executor(), c->read(oref(ind1)));
  REQUIRE(v);
  const auto request = proxy.last_request();
  REQUIRE_FALSE(request.empty());

  // Beyond max serv outstanding each copy only gets a reject, the smallest PDU there is, and those
  // bypass the server's queue. The kernel buffers take a few MiB of them first.
  proxy.stall();
  memory_watch memory;
  proxy.flood(request, 1U << 30U);
  const bool ended = wait_until([&] { return r.server->association_count() == 0; }, 40s);
  const auto growth = memory.finish();
  CHECK(ended);
  CHECK(r.server->slow_peer_aborts() == 1);
  CHECK(growth < 6 * limit);
  CHECK(proxy.flooded() > 0);
}

TEST_CASE("A request flood costs the other associations little", "[server][backpressure]") {
  rig r(limited());
  stall_proxy proxy(r.server->local_endpoint());
  auto flooding = r.connect_client(r.client_options(proxy.port()));
  auto healthy = r.connect_client(r.client_options(r.server->local_endpoint().port()));
  auto v = await(r.client_rt.get_executor(), flooding->read(oref(ind1)));
  REQUIRE(v);

  // This peer reads what it provokes, so nothing piles up unless it falls behind, and if it does
  // only it goes.
  auto stats = std::make_shared<reads>();
  auto reading = asio::co_spawn(r.client_rt.get_executor(), keep_reading(healthy, stats), asio::use_future);
  constexpr std::size_t copies = 20000;
  proxy.flood(proxy.last_request(), copies);
  CHECK(wait_until([&] { return proxy.flooded() == copies || proxy.server_gone(); }, 30s));
  stats->stop = true;
  get(std::move(reading));
  CHECK(stats->done.load() > 0);
  CHECK(stats->failed.load() == 0);
  CHECK(stats->slowest_ms.load() < 5000);
  CHECK(healthy->state() == client::connection_state::established);
}

TEST_CASE("A peer that stops reading hits the stall timeout with no output limit", "[server][backpressure]") {
  auto options = limited();
  options.association.transport.max_output_bytes = 0;
  options.association.transport.write_stall_timeout = 200ms;
  rig r(std::move(options));
  stall_proxy proxy(r.server->local_endpoint());
  auto c = r.connect_client(r.client_options(proxy.port()));
  r.enable(*c, urcb02);
  proxy.stall();
  CHECK(load_until(*r.server, [&] { return r.server->association_count() == 0; }, 40s));
  CHECK(r.server->slow_peer_aborts() == 1);
}

TEST_CASE("A slow client that keeps reading stays associated and loses nothing", "[server][backpressure]") {
  auto options = limited();
  options.association.transport.write_stall_timeout = 500ms;
  rig r(std::move(options));
  stall_proxy proxy(r.server->local_endpoint());
  auto c = r.connect_client(r.client_options(proxy.port()));
  auto received = std::make_shared<std::atomic<std::uint64_t>>(0);
  auto gaps = std::make_shared<std::atomic<std::uint64_t>>(0);
  auto last = std::make_shared<std::atomic<int>>(-1);
  c->set_report_handler([=](client::report rpt) {
    const int seq = rpt.seq_num ? static_cast<int>(*rpt.seq_num) : -1;
    const int before = last->exchange(seq);
    if (before >= 0 && seq != (before + 1) % 256) gaps->fetch_add(1);
    received->fetch_add(1);
  });
  r.enable(*c, urcb02);

  // Reads in short bursts with pauses, for a fraction of the time, under a load it can follow.
  const auto end = std::chrono::steady_clock::now() + 2s;
  std::uint64_t n = 0;
  while (std::chrono::steady_clock::now() < end) {
    proxy.stall();
    for (int i = 0; i < 5; ++i) {
      if (r.server->pending_updates() < 240) (void)update_big(*r.server, n++);
      std::this_thread::sleep_for(20ms);
    }
    proxy.resume();
    std::this_thread::sleep_for(20ms);
  }
  CHECK(wait_until([&] { return received->load() >= n; }, 20s));
  CHECK(received->load() == n);
  CHECK(gaps->load() == 0);
  CHECK(r.server->slow_peer_aborts() == 0);
  CHECK(r.server->association_count() == 1);
  CHECK(c->state() == client::connection_state::established);
}

TEST_CASE("A stalled BRCB keeps its entries for the next association", "[server][backpressure]") {
  srv::server_options options;
  // BRCBs alone stop at half the limit: only the stall timeout ends the association.
  options.association.transport.max_output_bytes = 128 * 1024;
  options.association.transport.write_stall_timeout = 300ms;
  options.brcb_buffer_capacity = 1U << 18U;
  rig r(std::move(options));
  stall_proxy proxy(r.server->local_endpoint());
  auto first = r.connect_client(r.client_options(proxy.port()));
  auto seen = std::make_shared<std::atomic<std::uint32_t>>(0);
  first->set_report_handler([seen](client::report rpt) {
    if (rpt.seq_num) seen->store(*rpt.seq_num);
  });
  r.enable(*first, brcb01);
  std::uint32_t value = 0;
  auto set = [&] {
    ++value;
    return r.server->update(oref("IED1LD0/MMXU1.TotW.mag.f[MX]"),
                            mms::data::floating_point(static_cast<float>(value)))
        .has_value();
  };
  REQUIRE(set());
  REQUIRE(wait_until([&] { return first->last_entry_id(oref(brcb01)).has_value(); }, 10s));

  proxy.stall();
  std::this_thread::sleep_for(10ms);  // what was on its way has arrived
  const auto resume_from = first->last_entry_id(oref(brcb01));
  const auto resume_seq = seen->load();
  memory_watch memory;
  CHECK(wait_until(
      [&] {
        if (r.server->association_count() == 0) return true;
        if (r.server->pending_updates() < 256) (void)set();
        return false;
      },
      40s));
  (void)memory.finish();
  CHECK(r.server->slow_peer_aborts() == 1);
  const auto last_value = value;
  CHECK(last_value > 1000);

  // The application goes on while nobody is there, and the entries wait in the buffer.
  REQUIRE(set());
  auto second = r.connect_client(r.client_options(r.server->local_endpoint().port()));
  auto count = std::make_shared<std::atomic<std::uint64_t>>(0);
  auto gaps = std::make_shared<std::atomic<std::uint64_t>>(0);
  auto overflow = std::make_shared<std::atomic<bool>>(false);
  auto previous = std::make_shared<std::atomic<std::uint32_t>>(resume_seq);
  second->set_report_handler([=](client::report rpt) {
    if (rpt.buffer_overflow && *rpt.buffer_overflow) overflow->store(true);
    const auto seq = *rpt.seq_num;
    if (seq != ((previous->exchange(seq) + 1) & 0xFFFFU)) gaps->fetch_add(1);
    count->fetch_add(1);
  });
  client::report_settings settings;
  settings.entry_id = resume_from;
  r.enable(*second, brcb01, settings);
  CHECK(wait_until([&] { return count->load() >= last_value; }, 30s));
  CHECK(gaps->load() == 0);
  CHECK_FALSE(overflow->load());
}

TEST_CASE("stop() does not wait for a peer that does not read", "[server][backpressure]") {
  auto options = limited();
  options.association.transport.max_output_bytes = 0;
  rig r(std::move(options));
  stall_proxy proxy(r.server->local_endpoint());
  auto c = r.connect_client(r.client_options(proxy.port()));
  r.enable(*c, urcb02);
  proxy.stall();
  std::uint64_t n = 0;
  const auto end = std::chrono::steady_clock::now() + 2s;
  while (std::chrono::steady_clock::now() < end) {
    if (r.server->pending_updates() < 240) (void)update_big(*r.server, n++);
  }
  const auto start = std::chrono::steady_clock::now();
  r.server->stop();
  auto stopped = asio::co_spawn(
      r.server_rt.get_executor(),
      [](srv::server* s) -> awaitable<void> { co_await s->wait_stopped(); }(r.server.get()),
      asio::use_future);
  get(std::move(stopped), 20s);
  CHECK(std::chrono::steady_clock::now() - start < 10s);
  CHECK(r.server->association_count() == 0);
}

TEST_CASE("update() reports an overloaded strand and drops nothing it accepted", "[server][backpressure]") {
  srv::server_options options;
  options.max_pending_updates = 4;
  rig r(std::move(options));
  auto& s = *r.server;
  const auto ref = oref("IED1LD0/MMXU1.TotW.mag.f[MX]");
  const auto set = [&](float v) { return s.update(ref, mms::data::floating_point(v)); };

  std::promise<void> entered;
  std::promise<void> release;
  asio::post(s.get_executor(), [&] {
    entered.set_value();
    release.get_future().wait();
  });
  entered.get_future().wait();

  for (int i = 1; i <= 4; ++i) REQUIRE(set(static_cast<float>(i)));
  CHECK(s.pending_updates() == 4);
  const auto refused = set(5.0F);
  REQUIRE_FALSE(refused);
  CHECK(refused.error() == srv::errc::overloaded);
  // A failed check keeps its own error, and an invalid reference is not refused as overload.
  CHECK(s.update(oref("IED1LD0/MMXU1.Nope.mag.f[MX]"), mms::data::floating_point(0.0F)).error() ==
        srv::errc::object_not_found);
  std::vector<srv::data_update> batch;
  batch.push_back({ref, mms::data::floating_point(6.0F), std::nullopt, std::nullopt});
  CHECK(s.update(std::move(batch)).error() == srv::errc::overloaded);
  CHECK(s.pending_updates() == 4);
  release.set_value();

  REQUIRE(wait_until([&] { return s.pending_updates() == 0; }, 10s));
  auto applied = await(r.client_rt.get_executor(), s.read(ref));
  REQUIRE(applied);
  CHECK(*applied == mms::data::floating_point(4.0F));

  // A batch larger than the limit fits an empty queue, so it can always get through.
  std::vector<srv::data_update> large;
  for (int i = 0; i < 16; ++i) {
    large.push_back({ref, mms::data::floating_point(7.0F), std::nullopt, std::nullopt});
  }
  CHECK(s.update(std::move(large)));
}

TEST_CASE("A client whose hostile server does not read is bounded as well", "[client][backpressure]") {
  rig r;
  stall_proxy proxy(r.server->local_endpoint());
  auto o = r.client_options(proxy.port());
  o.association.transport.max_output_bytes = limit;
  auto c = r.connect_client(o);
  auto v = await(r.client_rt.get_executor(), c->read(oref(ind1)));
  REQUIRE(v);
  const auto response = proxy.last_response();
  REQUIRE_FALSE(response.empty());

  // The answer to no request gets a reject every time, and the "server" takes none of them.
  proxy.stall_client();
  memory_watch memory;
  proxy.flood_client(response, 1U << 30U);
  const bool ended = wait_until([&] { return c->state() == client::connection_state::closed; }, 40s);
  const auto growth = memory.finish();
  CHECK(ended);
  CHECK(growth < 6 * limit);
  auto why = await(r.client_rt.get_executor(), c->wait_closed());
  CHECK(why == openiec61850::errc::output_limit_exceeded);
}
