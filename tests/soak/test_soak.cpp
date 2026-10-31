// Soak test: the server and many clients on separate I/O threads, under concurrent reports,
// control, update() from several threads, association churn and abrupt disconnects, plain and
// over TLS. A few seconds by default; OPENIEC61850_SOAK_SECONDS sets the duration of each case:
//
//   OPENIEC61850_SOAK_SECONDS=300 build/tsan/tests/openiec61850_tests '[soak]'
//
// The workers run off the main thread and Catch2 assertions are not thread-safe there, so they
// only count; everything is checked on the main thread. A hang aborts the process with the name
// of what is stuck: the objects involved cannot be destroyed safely by then.

#include <catch2/catch_test_macros.hpp>

#include <dirent.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <deque>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <asio/as_tuple.hpp>
#include <asio/connect.hpp>
#include <asio/detached.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/post.hpp>
#include <asio/use_future.hpp>
#include <asio/write.hpp>

#include "../server/server_test_util.hpp"
#include "../server/stall_proxy.hpp"
#include "openiec61850/transport/io_runtime.hpp"
#include "openiec61850/transport/tls.hpp"

#ifdef OPENIEC61850_WITH_TLS
#include "../transport/tls_certs.hpp"
#endif

using namespace server_test;
using asio::awaitable;
using asio::ip::tcp;
namespace transport = openiec61850::transport;

namespace {

constexpr auto use_tuple = asio::as_tuple(asio::use_awaitable);
constexpr auto hang_limit = 60s;

std::chrono::seconds soak_duration() {
  const char* text = std::getenv("OPENIEC61850_SOAK_SECONDS");
  const int seconds = text != nullptr ? std::atoi(text) : 0;
  return std::chrono::seconds(seconds > 0 ? seconds : 2);
}

std::size_t open_descriptors() {
  std::size_t n = 0;
  if (DIR* d = opendir("/proc/self/fd")) {
    while (readdir(d) != nullptr) ++n;
    closedir(d);
  }
  return n;
}

struct counters {
  std::atomic<std::uint64_t> reads{0};
  std::atomic<std::uint64_t> reports{0};
  std::atomic<std::uint64_t> operates{0};
  std::atomic<std::uint64_t> selects{0};
  std::atomic<std::uint64_t> completions{0};
  std::atomic<std::uint64_t> updates{0};
  std::atomic<std::uint64_t> churned{0};
  std::atomic<std::uint64_t> aborted{0};
  std::atomic<std::uint64_t> raw{0};
  std::atomic<std::uint64_t> server_restarts{0};
  // A request on an established association failed while the server was up.
  std::atomic<std::uint64_t> unexpected{0};
  std::mutex mutex;
  std::string first_error_text;

  void fail(std::string_view where, std::error_code ec) {
    unexpected.fetch_add(1);
    const std::lock_guard lock(mutex);
    if (first_error_text.empty()) first_error_text = std::string(where) + ": " + ec.message();
  }
};

// What the application side of the server shares with the threads completing operations.
struct completions {
  std::mutex mutex;
  std::deque<srv::control_completion> queue;

  void push(srv::control_completion c) {
    const std::lock_guard lock(mutex);
    queue.push_back(std::move(c));
  }
  std::optional<srv::control_completion> pop() {
    const std::lock_guard lock(mutex);
    if (queue.empty()) return std::nullopt;
    auto c = std::move(queue.front());
    queue.pop_front();
    return c;
  }
};

// Clients offered to the thread that aborts them from outside their strand.
struct victims {
  std::mutex mutex;
  std::vector<std::shared_ptr<client::client>> list;

  void offer(std::shared_ptr<client::client> c) {
    const std::lock_guard lock(mutex);
    list.push_back(std::move(c));
  }
  std::vector<std::shared_ptr<client::client>> take() {
    const std::lock_guard lock(mutex);
    return std::exchange(list, {});
  }
};

struct references {
  model::object_reference ind1 = oref("IED1LD0/GGIO1.Ind1.stVal[ST]");
  model::object_reference pos = oref("IED1LD0/XCBR1.Pos.stVal[ST]");
  model::object_reference totw = oref("IED1LD0/MMXU1.TotW.mag.f[MX]");
  model::object_reference str1 = oref("IED1LD0/GGIO1.Str1.stVal[ST]");
  model::object_reference urcb01 = oref("IED1LD0/LLN0.urcb01[RP]");
  model::object_reference urcb02 = oref("IED1LD0/LLN0.urcb02[RP]");
  model::object_reference brcb01 = oref("IED1LD0/LLN0.brcb01[BR]");
  model::object_reference xcbr = oref("IED1LD0/XCBR1.Pos");
  model::object_reference cswi = oref("IED1LD0/CSWI1.Pos");
};

// One association's worth of work: everything the workers need, with no Catch2 in it.
struct context {
  asio::any_io_executor ex;
  client::client_options options;
  references refs;
  counters* stats = nullptr;
  victims* targets = nullptr;
  std::atomic<bool>* running = nullptr;
  std::atomic<int>* live = nullptr;

  [[nodiscard]] bool on() const noexcept { return running->load(); }
};

awaitable<void> pause(std::chrono::milliseconds d) {
  asio::steady_timer t(co_await asio::this_coro::executor, d);
  (void)co_await t.async_wait(use_tuple);
}

// Spawns a worker counted in ctx.live.
template <typename F>
void launch(const context& ctx, F worker) {
  ctx.live->fetch_add(1);
  asio::co_spawn(ctx.ex, std::move(worker), [live = ctx.live](std::exception_ptr e) {
    if (e) {
      std::fprintf(stderr, "soak: a worker threw\n");
      std::abort();
    }
    live->fetch_sub(1);
  });
}

awaitable<void> drain_reports(std::shared_ptr<client::client> c, counters* stats) {
  for (;;) {
    auto r = co_await c->next_report();
    if (!r) co_return;
    stats->reports.fetch_add(1);
  }
}

// A long association holding an RCB, consuming reports through next_report() or a handler.
awaitable<void> reporter(context ctx, model::object_reference rcb, bool use_handler) {
  auto r = co_await client::client::connect(ctx.ex, ctx.options);
  if (!r) {
    ctx.stats->fail("reporter connect", r.error());
    co_return;
  }
  auto c = std::make_shared<client::client>(std::move(*r));
  if (use_handler) {
    c->set_report_handler([stats = ctx.stats](client::report) { stats->reports.fetch_add(1); });
  } else {
    launch(ctx, drain_reports(c, ctx.stats));
  }
  client::report_settings settings;
  settings.general_interrogation = true;
  auto enabled = co_await c->enable_reporting(rcb, settings);
  if (!enabled) ctx.stats->fail("enable_reporting", enabled.error());
  while (ctx.on() && enabled) {
    auto gi = co_await c->trigger_gi(rcb);
    if (!gi) ctx.stats->fail("trigger_gi", gi.error());
    (void)c->reports_dropped();
    co_await pause(10ms);
  }
  // An orderly end half of the time; otherwise the association goes with the reservation held.
  if (rcb == ctx.refs.urcb01) {
    (void)co_await c->release();
  } else {
    c->abort();
    (void)co_await c->wait_closed();
  }
}

// Pipelined reads on one association.
awaitable<void> read_one(std::shared_ptr<client::client> c, model::object_reference ref,
                         counters* stats, std::shared_ptr<std::atomic<int>> pending) {
  auto r = co_await c->read(std::move(ref));
  if (r) {
    stats->reads.fetch_add(1);
  } else {
    stats->fail("read", r.error());
  }
  pending->fetch_sub(1);
}

// Keeps the counters of an abandoned read alive.
awaitable<void> quiet_read(std::shared_ptr<client::client> c, model::object_reference ref,
                           std::shared_ptr<counters> quiet,
                           std::shared_ptr<std::atomic<int>> pending) {
  co_await read_one(std::move(c), std::move(ref), quiet.get(), std::move(pending));
}

awaitable<void> reader(context ctx) {
  auto r = co_await client::client::connect(ctx.ex, ctx.options);
  if (!r) {
    ctx.stats->fail("reader connect", r.error());
    co_return;
  }
  auto c = std::make_shared<client::client>(std::move(*r));
  do {
    auto pending = std::make_shared<std::atomic<int>>(4);
    launch(ctx, read_one(c, ctx.refs.ind1, ctx.stats, pending));
    launch(ctx, read_one(c, ctx.refs.pos, ctx.stats, pending));
    launch(ctx, read_one(c, ctx.refs.totw, ctx.stats, pending));
    launch(ctx, read_one(c, ctx.refs.str1, ctx.stats, pending));
    while (pending->load() > 0) co_await pause(1ms);
  } while (ctx.on());
  (void)co_await c->release();
}

// Direct and SBO control from one association. Refusals are fine: another operator may hold the
// object or an operation may still be pending. Only a broken association is not.
awaitable<void> controller(context ctx) {
  auto r = co_await client::client::connect(ctx.ex, ctx.options);
  if (!r) {
    ctx.stats->fail("controller connect", r.error());
    co_return;
  }
  auto c = std::make_shared<client::client>(std::move(*r));
  auto direct = co_await c->get_control(ctx.refs.xcbr);
  auto sbo = co_await c->get_control(ctx.refs.cswi);
  if (!direct || !sbo) {
    ctx.stats->fail("get_control", !direct ? direct.error() : sbo.error());
    c->abort();
    co_return;
  }
  bool value = false;
  do {  // at least once, however long the setup took on a loaded machine
    value = !value;
    auto done = co_await direct->operate(mms::data::boolean(value));
    if (done) ctx.stats->operates.fetch_add(1);
    (void)direct->last_error();
    auto selected = co_await sbo->select();
    if (selected) {
      ctx.stats->selects.fetch_add(1);
      if (value) {
        auto second = co_await sbo->operate(mms::data::boolean(value));
        if (second) ctx.stats->operates.fetch_add(1);
      } else {
        (void)co_await sbo->cancel();
      }
    }
    if (c->state() != client::connection_state::established) {
      ctx.stats->fail("controller state", openiec61850::errc::invalid_state);
      break;
    }
    co_await pause(2ms);
  } while (ctx.on());
  (void)co_await c->release();
}

// Short associations: connect, one service, orderly release.
awaitable<void> churner(context ctx) {
  do {
    auto r = co_await client::client::connect(ctx.ex, ctx.options);
    if (!r) {
      ctx.stats->fail("churn connect", r.error());
      co_await pause(5ms);
      continue;
    }
    auto v = co_await r->read(ctx.refs.ind1);
    if (!v) ctx.stats->fail("churn read", v.error());
    auto closed = co_await r->release();
    if (!closed) ctx.stats->fail("churn release", closed.error());
    ctx.stats->churned.fetch_add(1);
  } while (ctx.on());
}

// Associations that end abruptly with work in flight, half of them aborted from another thread.
awaitable<void> aborter(context ctx) {
  bool from_outside = false;
  do {
    auto r = co_await client::client::connect(ctx.ex, ctx.options);
    if (!r) {
      ctx.stats->fail("abort connect", r.error());
      co_await pause(5ms);
      continue;
    }
    auto c = std::make_shared<client::client>(std::move(*r));
    auto pending = std::make_shared<std::atomic<int>>(2);
    // Their outcome is unknown by design, so the failures do not count as unexpected.
    auto quiet = std::make_shared<counters>();
    launch(ctx, quiet_read(c, ctx.refs.ind1, quiet, pending));
    launch(ctx, quiet_read(c, ctx.refs.totw, quiet, pending));
    from_outside = !from_outside;
    if (from_outside) {
      ctx.targets->offer(c);
    } else {
      c->abort();
    }
    (void)co_await c->wait_closed();
    while (pending->load() > 0) co_await pause(1ms);
    ctx.stats->aborted.fetch_add(1);
  } while (ctx.on());
}

// TCP peers that never finish: gone at once, garbage, half a TPKT, reset with data unread.
awaitable<void> raw_peer(context ctx, tcp::endpoint server) {
  std::uint8_t step = 0;
  do {
    tcp::socket s(ctx.ex);
    auto [ec] = co_await s.async_connect(server, use_tuple);
    if (!ec) {
      static constexpr std::uint8_t garbage[] = {0x47, 0x45, 0x54, 0x20, 0x2F, 0x00, 0xFF, 0x7E};
      static constexpr std::uint8_t partial[] = {0x03, 0x00, 0xFF, 0xFF, 0x11, 0xE0};
      std::error_code ignored;
      switch (step++ % 4) {
        case 0:
          break;
        case 1:
          (void)co_await asio::async_write(s, asio::buffer(garbage), use_tuple);
          break;
        case 2:
          (void)co_await asio::async_write(s, asio::buffer(partial), use_tuple);
          co_await pause(1ms);
          break;
        default:
          s.set_option(tcp::socket::linger(true, 0), ignored);
          break;
      }
      s.close(ignored);
      ctx.stats->raw.fetch_add(1);
    }
    co_await pause(2ms);
  } while (ctx.on());
}

srv::server_options server_options_for(completions& pending,
                                       const std::shared_ptr<transport::tls_context>& tls) {
  srv::server_options o;
  o.association.transport.tls = tls;
  o.association.transport.handshake_timeout = 20s;
  o.association.association_timeout = 20s;
  o.max_associations = 0;
  o.brcb_buffer_capacity = 64;
  o.operate_timeout = 2s;
  auto count = std::make_shared<std::atomic<std::uint64_t>>(0);
  o.on_control = [&pending, count](const srv::control_request& r) {
    // Every other Operate finishes later, from another thread.
    if (r.action == srv::control_action::operate && r.completion.valid() &&
        count->fetch_add(1) % 2 == 0) {
      pending.push(r.completion);
      return srv::control_result::pending();
    }
    return srv::control_result::ok();
  };
  return o;
}

client::client_options client_options_for(std::uint16_t port,
                                          const std::shared_ptr<transport::tls_context>& tls) {
  client::client_options o;
  o.association.port = port;
  o.association.transport.tls = tls;
  o.association.transport.connect_timeout = 20s;
  o.association.transport.handshake_timeout = 20s;
  o.association.association_timeout = 20s;
  o.association.request_timeout = 30s;
  o.association.release_timeout = 20s;
  o.recovery.enabled = false;
  return o;
}

[[noreturn]] void hang(const char* what);

// Calls update() in a loop, until the server is gone.
void update_loop(srv::server& s, const references& refs, int seed, std::atomic<bool>& stop,
                 counters& stats) {
  std::uint64_t n = static_cast<std::uint64_t>(seed);
  while (!stop.load()) {
    ++n;
    const auto ok = [&] {
      switch (n % 4) {
        case 0:
          return s.update(refs.ind1, mms::data::boolean((n & 8U) != 0)).has_value();
        case 1:
          return s.update(refs.totw, mms::data::floating_point(static_cast<float>(n % 100))).has_value();
        case 2:
          return s.update(refs.str1, mms::data::visible_string(std::to_string(n % 50))).has_value();
        default: {
          std::vector<srv::data_update> batch;
          batch.push_back({refs.pos, model::to_mms(model::dbpos::on), std::nullopt, std::nullopt});
          batch.push_back({refs.ind1, mms::data::boolean((n & 4U) != 0),
                           model::quality{}.set(model::quality_flag::test), std::nullopt});
          return s.update(std::move(batch)).has_value();
        }
      }
    }();
    if (ok) stats.updates.fetch_add(1);
    (void)s.association_count();
    // Paced: this soak is about the churn around the updates. Going as fast as update() lets
    // you is what the slow-reader soak does.
    std::this_thread::sleep_for(2ms);
    if (n % 32 == 0) {
      std::promise<void> drained;
      auto done = drained.get_future();
      asio::post(s.get_executor(), [&drained] { drained.set_value(); });
      if (done.wait_for(hang_limit) != std::future_status::ready) hang("the server strand");
    }
  }
}

[[noreturn]] void hang(const char* what) {
  std::fprintf(stderr, "soak: %s did not finish within %lld s\n", what,
               static_cast<long long>(hang_limit.count()));
  std::abort();
}

template <typename Predicate>
bool wait_until(Predicate done, std::chrono::milliseconds limit) {
  const auto end = std::chrono::steady_clock::now() + limit;
  while (!done()) {
    if (std::chrono::steady_clock::now() >= end) return false;
    std::this_thread::sleep_for(1ms);
  }
  return true;
}

struct sample {
  std::size_t descriptors = 0;
  std::size_t bytes = 0;
};

struct tls_contexts {
  std::shared_ptr<transport::tls_context> server;
  std::shared_ptr<transport::tls_context> client;
};

void soak(const tls_contexts& tls) {
  const auto duration = soak_duration();
  const auto end = std::chrono::steady_clock::now() + duration;
  // One server lives for some rounds, so that what only leaks while it runs shows up as well.
  const auto round = duration >= 60s ? 2000ms : 250ms;
  constexpr int rounds_per_server = 4;

  counters stats;
  completions pending;
  victims targets;
  references refs;
  std::vector<sample> samples;
  std::size_t slow_closes = 0;

  transport::io_runtime server_rt;
  transport::io_runtime client_rt;
  server_rt.start();
  client_rt.start();

  // Threads living across the servers.
  std::atomic<bool> stop_helpers{false};
  std::thread completer([&] {
    bool positive = false;
    while (!stop_helpers.load()) {
      if (auto c = pending.pop()) {
        positive = !positive;
        const auto outcome = positive ? srv::control_result::ok()
                                      : srv::control_result::refused(srv::add_cause::blocked_by_process);
        if (c->complete(outcome)) stats.completions.fetch_add(1);
      } else {
        std::this_thread::sleep_for(500us);
      }
    }
  });
  std::thread killer([&] {
    while (!stop_helpers.load()) {
      for (auto& c : targets.take()) {
        (void)c->association_info();
        (void)c->state();
        (void)c->last_entry_id(refs.brcb01);
        c->abort();
        c->abort();
      }
      std::this_thread::sleep_for(200us);
    }
  });

  bool more = true;
  std::size_t server_count = 0;
  while (more) {
    auto started = srv::server::start(server_rt.get_executor(), make_model(), loopback,
                                      server_options_for(pending, tls.server));
    REQUIRE(started);
    auto server = std::make_unique<srv::server>(std::move(*started));
    ++server_count;
    const auto endpoint = server->local_endpoint();

    std::atomic<bool> stop_updates{false};
    std::vector<std::thread> updaters;
    for (int i = 0; i < 3; ++i) {
      updaters.emplace_back(update_loop, std::ref(*server), std::cref(refs), i,
                            std::ref(stop_updates), std::ref(stats));
    }

    for (int r = 0; r < rounds_per_server && more; ++r) {
      std::atomic<bool> running{true};
      std::atomic<int> live{0};
      context ctx{client_rt.get_executor(), client_options_for(endpoint.port(), tls.client), refs,
                  &stats, &targets, &running, &live};
      launch(ctx, reporter(ctx, refs.urcb01, false));
      launch(ctx, reporter(ctx, refs.urcb02, true));
      launch(ctx, reporter(ctx, refs.brcb01, false));
      for (int i = 0; i < 4; ++i) launch(ctx, reader(ctx));
      for (int i = 0; i < 2; ++i) launch(ctx, controller(ctx));
      for (int i = 0; i < 4; ++i) launch(ctx, churner(ctx));
      for (int i = 0; i < 2; ++i) launch(ctx, aborter(ctx));
      launch(ctx, raw_peer(ctx, endpoint));

      std::this_thread::sleep_for(round);
      running = false;
      if (!wait_until([&] { return live.load() == 0; }, hang_limit)) hang("a worker");
      for (auto& c : targets.take()) c->abort();
      // Every association the server saw has ended, however it ended.
      if (!wait_until([&] { return server->association_count() == 0; }, hang_limit)) {
        std::fprintf(stderr, "soak: %zu associations left\n", server->association_count());
        hang("the end of the associations");
      }
      if (std::chrono::steady_clock::now() >= end) more = false;
      if (r == rounds_per_server - 1 || !more) break;
      // Quiescent, the server still running: sockets close together with their associations. A
      // close held up by a pending read used to take the whole TLS close timeout (1 s), only
      // under load, so this is what guards it. The first sample is taken well past that.
      if (samples.empty()) {
        std::this_thread::sleep_for(1500ms);
      } else {
        const auto settled = samples.front().descriptors;
        if (!wait_until([&] { return open_descriptors() <= settled; }, 700ms)) ++slow_closes;
      }
      samples.push_back({open_descriptors(), live_bytes()});
    }

    // stop() races the updaters and a late association.
    auto late = asio::co_spawn(
        client_rt.get_executor(),
        [](client::client_options o, asio::any_io_executor ex) -> awaitable<void> {
          auto c = co_await client::client::connect(ex, std::move(o));
          if (c) (void)co_await c->wait_closed();
        }(client_options_for(endpoint.port(), tls.client), client_rt.get_executor()),
        asio::use_future);
    std::this_thread::sleep_for(5ms);
    std::thread stopper([&] { server->stop(); });
    server->stop();
    stopper.join();
    auto stopped = asio::co_spawn(
        server_rt.get_executor(),
        [](srv::server* s) -> awaitable<void> { co_await s->wait_stopped(); }(server.get()),
        asio::use_future);
    if (stopped.wait_for(hang_limit) != std::future_status::ready) hang("wait_stopped()");
    if (late.wait_for(hang_limit) != std::future_status::ready) hang("a late association");
    stopped.get();
    late.get();
    stop_updates = true;
    for (auto& t : updaters) t.join();
    CHECK(server->association_count() == 0);
    server.reset();
    stats.server_restarts.fetch_add(1);
  }

  stop_helpers = true;
  completer.join();
  killer.join();
  client_rt.stop();
  server_rt.stop();
  client_rt.join();
  server_rt.join();
  CHECK_FALSE(client_rt.take_exception());
  CHECK_FALSE(server_rt.take_exception());

  std::printf(
      "soak: %zu servers, %llu reads, %llu reports, %llu operates, %llu selects, %llu completions, "
      "%llu updates, %llu churned, %llu aborted, %llu raw, %llu unexpected\n",
      server_count, static_cast<unsigned long long>(stats.reads.load()),
      static_cast<unsigned long long>(stats.reports.load()),
      static_cast<unsigned long long>(stats.operates.load()),
      static_cast<unsigned long long>(stats.selects.load()),
      static_cast<unsigned long long>(stats.completions.load()),
      static_cast<unsigned long long>(stats.updates.load()),
      static_cast<unsigned long long>(stats.churned.load()),
      static_cast<unsigned long long>(stats.aborted.load()),
      static_cast<unsigned long long>(stats.raw.load()),
      static_cast<unsigned long long>(stats.unexpected.load()));

  INFO(stats.first_error_text);
  CHECK(stats.unexpected.load() == 0);
  CHECK(stats.reads.load() > 0);
  CHECK(stats.reports.load() > 0);
  CHECK(stats.operates.load() > 0);
  CHECK(stats.selects.load() > 0);
  CHECK(stats.updates.load() > 0);
  CHECK(stats.churned.load() > 0);
  CHECK(stats.aborted.load() > 0);
  CHECK(stats.raw.load() > 0);
  CHECK(slow_closes == 0);

  // Flat across the churn: past the warm-up (allocator pools, BRCB buffers filling up) descriptors
  // must not move and live memory must not trend. Compares the first and last quarters of the
  // samples, which needs a long enough run.
  if (samples.size() >= 12) {
    const auto quarter = samples.size() / 4;
    const auto average = [&](std::size_t from) {
      std::size_t bytes = 0;
      for (std::size_t i = 0; i < quarter; ++i) bytes += samples[from + i].bytes;
      return bytes / quarter;
    };
    const auto first = average(quarter);  // the first quarter is the warm-up
    const auto last = average(samples.size() - quarter);
    std::printf("soak: %zu samples, descriptors %zu -> %zu, live bytes %zu -> %zu\n", samples.size(),
                samples[quarter].descriptors, samples.back().descriptors, first, last);
    CHECK(samples.back().descriptors == samples[quarter].descriptors);
    CHECK(last < first + first / 10 + 1024 * 1024);
  }
  std::fflush(stdout);
}

// --- Peers that stop reading, with the application updating as fast as update() lets it

struct slow_counters {
  std::atomic<std::uint64_t> stalled{0};
  std::atomic<std::uint64_t> reads{0};
  std::atomic<std::uint64_t> failed_reads{0};
  std::atomic<std::int64_t> slowest_read_ms{0};
  std::atomic<std::uint64_t> applied{0};
  std::atomic<std::uint64_t> overloaded{0};
  std::atomic<std::size_t> highest_pending{0};
};

// A client that enables a report control block and stops reading for good; the server has to get
// rid of it on its own. One at a time on each control block: the aborted association frees it.
awaitable<void> stalling_peer(client::client_options options, tcp::endpoint server,
                              std::string rcb, asio::any_io_executor ex, slow_counters* stats,
                              std::atomic<bool>* running, srv::server* srv_handle) {
  while (running->load()) {
    auto proxy = std::make_unique<stall_proxy>(server);
    options.association.port = proxy->port();
    auto r = co_await client::client::connect(ex, options);
    if (!r) continue;
    client::report_settings settings;
    settings.data_set = oref("IED1LD0/LLN0.DSBIG");
    auto enabled = co_await r->enable_reporting(oref(rcb), settings);
    if (!enabled) {
      // The previous association may not be gone from the server yet.
      r->abort();
      co_await pause(5ms);
      continue;
    }
    proxy->stall();
    const auto before = srv_handle->slow_peer_aborts();
    while (running->load() && srv_handle->slow_peer_aborts() == before) co_await pause(2ms);
    stats->stalled.fetch_add(1);
    r->abort();
    (void)co_await r->wait_closed();
  }
}

awaitable<void> steady_reader(client::client_options options, asio::any_io_executor ex,
                              slow_counters* stats, std::atomic<bool>* running,
                              model::object_reference ref) {
  auto r = co_await client::client::connect(ex, options);
  if (!r) {
    stats->failed_reads.fetch_add(1);
    co_return;
  }
  while (running->load()) {
    const auto start = std::chrono::steady_clock::now();
    auto v = co_await r->read(ref);
    const auto took = std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::steady_clock::now() - start)
                          .count();
    if (took > stats->slowest_read_ms.load()) stats->slowest_read_ms = took;
    (v ? stats->reads : stats->failed_reads).fetch_add(1);
    co_await pause(1ms);
  }
  (void)co_await r->release();
}

// Open loop: the three updaters that used to starve the strand of a sanitizer build for good.
void open_loop(srv::server& s, const references& refs, int seed, std::atomic<bool>& stop,
               slow_counters& stats) {
  std::uint64_t n = static_cast<std::uint64_t>(seed);
  const std::string text(200, 'x');
  while (!stop.load()) {
    ++n;
    const auto done = s.update(refs.str1, mms::data::visible_string(text + std::to_string(n % 1000)));
    if (done) {
      stats.applied.fetch_add(1);
    } else if (done.error() == srv::errc::overloaded) {
      stats.overloaded.fetch_add(1);
      std::this_thread::sleep_for(100us);  // a real producer would do something else meanwhile
    }
    const auto pending = s.pending_updates();
    if (pending > stats.highest_pending.load()) stats.highest_pending = pending;
    std::this_thread::sleep_for(50us);
  }
}

void slow_readers(const tls_contexts& tls) {
  const auto duration = soak_duration() + 2s;
  transport::io_runtime server_rt;
  transport::io_runtime client_rt;
  server_rt.start();
  client_rt.start();
  references refs;
  slow_counters stats;
  completions pending;

  auto options = server_options_for(pending, tls.server);
  constexpr std::size_t output_limit = 512 * 1024;
  options.association.transport.max_output_bytes = output_limit;
  options.association.transport.write_stall_timeout = 500ms;
  auto started = srv::server::start(server_rt.get_executor(), make_model(), loopback, options);
  REQUIRE(started);
  auto server = std::make_unique<srv::server>(std::move(*started));
  const auto endpoint = server->local_endpoint();
  const auto base_bytes = live_bytes();

  std::atomic<bool> running{true};
  std::atomic<int> live{0};
  context ctx{client_rt.get_executor(), client_options_for(endpoint.port(), tls.client), refs,
              nullptr, nullptr, &running, &live};
  launch(ctx, steady_reader(ctx.options, ctx.ex, &stats, &running, refs.ind1));
  launch(ctx, steady_reader(ctx.options, ctx.ex, &stats, &running, refs.str1));
  launch(ctx, stalling_peer(ctx.options, endpoint, "IED1LD0/LLN0.urcb03[RP]", ctx.ex, &stats,
                            &running, server.get()));
  launch(ctx, stalling_peer(ctx.options, endpoint, "IED1LD0/LLN0.urcb02[RP]", ctx.ex, &stats,
                            &running, server.get()));

  std::atomic<bool> stop_updates{false};
  std::vector<std::thread> updaters;
  for (int i = 0; i < 3; ++i) {
    updaters.emplace_back(open_loop, std::ref(*server), std::cref(refs), i, std::ref(stop_updates),
                          std::ref(stats));
  }

  std::size_t highest_bytes = 0;
  const auto end = std::chrono::steady_clock::now() + duration;
  while (std::chrono::steady_clock::now() < end) {
    highest_bytes = std::max(highest_bytes, live_bytes());
    std::this_thread::sleep_for(5ms);
  }

  // The updaters stop first: an association must not be left to outrun for ever.
  stop_updates = true;
  for (auto& t : updaters) t.join();
  running = false;
  if (!wait_until([&] { return live.load() == 0; }, hang_limit)) hang("a slow-reader worker");
  const auto aborted = server->slow_peer_aborts();
  server->stop();
  auto stopped = asio::co_spawn(
      server_rt.get_executor(),
      [](srv::server* s) -> awaitable<void> { co_await s->wait_stopped(); }(server.get()),
      asio::use_future);
  if (stopped.wait_for(hang_limit) != std::future_status::ready) hang("wait_stopped()");
  stopped.get();
  server.reset();
  client_rt.stop();
  server_rt.stop();
  client_rt.join();
  server_rt.join();
  CHECK_FALSE(client_rt.take_exception());
  CHECK_FALSE(server_rt.take_exception());

  const auto growth = highest_bytes > base_bytes ? highest_bytes - base_bytes : 0;
  std::printf(
      "soak: %llu aborts, %llu stalled peers, %llu reads (slowest %lld ms), %llu updates, %llu "
      "overloaded, %zu pending at most, %zu KiB at most\n",
      static_cast<unsigned long long>(aborted),
      static_cast<unsigned long long>(stats.stalled.load()),
      static_cast<unsigned long long>(stats.reads.load()),
      static_cast<long long>(stats.slowest_read_ms.load()),
      static_cast<unsigned long long>(stats.applied.load()),
      static_cast<unsigned long long>(stats.overloaded.load()), stats.highest_pending.load(),
      growth / 1024);
  std::fflush(stdout);

  CHECK(aborted > 0);
  CHECK(stats.reads.load() > 0);
  // Nobody else pays for the stalled peers or the updaters.
  CHECK(stats.failed_reads.load() == 0);
  CHECK(stats.slowest_read_ms.load() < 20000);
  // Plus each updater being refused at that moment, which counts itself for an instant.
  CHECK(stats.highest_pending.load() <= options.max_pending_updates + 3);
  // Two stalled associations, their limits, the pending updates: tens of MiB, not a trend.
  CHECK(growth < 128U * 1024U * 1024U);
}

}  // namespace

TEST_CASE("Soak: plain TCP", "[soak]") { soak({}); }

TEST_CASE("Soak: peers that stop reading", "[soak]") { slow_readers({}); }

#ifdef OPENIEC61850_WITH_TLS
TEST_CASE("Soak: TLS", "[soak]") {
  tls_test::temp_dir dir;
  tls_test::certificate_authority ca(dir.path, "root");
  const auto server_keys = ca.issue("ied1", {"IP:127.0.0.1"});
  const auto client_keys = ca.issue("hmi");
  const auto make = [&](const tls_test::key_pair& keys, bool server) {
    transport::tls_config c;
    c.ca_file = ca.certificate();
    c.certificate_file = keys.certificate;
    c.private_key_file = keys.private_key;
    // Renews the keys under load as well.
    c.key_update_bytes = 64 * 1024;
    auto ctx = transport::tls_context::create(c, server);
    REQUIRE(ctx);
    return *ctx;
  };
  soak({make(server_keys, true), make(client_keys, false)});
  SECTION("slow readers") { slow_readers({make(server_keys, true), make(client_keys, false)}); }
}
#endif
