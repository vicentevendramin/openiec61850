// End-to-end benchmarks over TCP loopback: client::client against the test fake server
// (tests/client/fake_server.cpp, compiled into this executable unchanged).
//
// Both peers run on one I/O thread (the fake server is single-threaded), so the numbers measure
// the CPU cost of the whole stack (MMS + ACSE + presentation + session + COTP + TPKT, both
// directions) plus the kernel loopback, not network latency. The benchmark thread only starts a
// batch and waits for it.

#include <benchmark/benchmark.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <future>
#include <latch>
#include <memory>
#include <optional>
#include <stdexcept>
#include <thread>
#include <utility>

#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/executor_work_guard.hpp>
#include <asio/io_context.hpp>
#include <asio/this_coro.hpp>

#include "fake_server.hpp"
#include "openiec61850/client/client.hpp"
#include "openiec61850/model/object_reference.hpp"

namespace {

namespace client = openiec61850::client;
namespace mms = openiec61850::mms;
namespace model = openiec61850::model;
namespace testing = openiec61850::testing;
using asio::awaitable;
using namespace std::chrono_literals;

model::object_reference ref(std::string_view text) {
  auto r = model::object_reference::parse(text);
  if (!r) throw std::runtime_error("bad reference");
  return *r;
}

// One I/O thread running a fake server and a connected client.
class loopback {
 public:
  loopback() : work_(ctx_.get_executor()), thread_([this] { ctx_.run(); }) {
    try {
      run([this]() -> awaitable<void> {
        server_ = std::make_unique<testing::fake_server>(ctx_.get_executor());
        if (!server_->start()) throw std::runtime_error("fake server did not start");
        client::client_options o;
        o.association.port = server_->port();
        o.association.request_timeout = 10s;
        auto c = co_await client::client::connect(co_await asio::this_coro::executor, o);
        if (!c) throw std::runtime_error("connect failed: " + c.error().message());
        client_.emplace(std::move(*c));
      });
    } catch (...) {
      shutdown();
      throw;
    }
  }
  ~loopback() { shutdown(); }
  loopback(const loopback&) = delete;
  loopback& operator=(const loopback&) = delete;

  client::client& client() { return *client_; }
  testing::fake_server& server() { return *server_; }
  asio::io_context& context() { return ctx_; }

  // Runs a coroutine on the I/O thread and blocks until it completes (rethrowing).
  template <typename F>
  void run(F&& make) {
    std::promise<void> done;
    asio::co_spawn(ctx_, std::forward<F>(make)(), [&done](std::exception_ptr e) {
      if (e) {
        done.set_exception(e);
      } else {
        done.set_value();
      }
    });
    done.get_future().get();
  }

 private:
  void shutdown() {
    if (thread_.joinable()) {
      try {
        run([this]() -> awaitable<void> {
          if (client_) (void)co_await client_->release();
          client_.reset();
          if (server_) server_->stop();
          server_.reset();
        });
      } catch (...) {  // NOLINT(bugprone-empty-catch): best effort during teardown
      }
      work_.reset();
      ctx_.stop();
      thread_.join();
    }
  }

  asio::io_context ctx_;
  asio::executor_work_guard<asio::io_context::executor_type> work_;
  std::unique_ptr<testing::fake_server> server_;
  std::optional<client::client> client_;
  std::thread thread_;
};

// Reads per second with `range(0)` reads in flight: each iteration starts that many concurrent
// client::read() calls and waits for all of them.
void BM_LoopbackRead(benchmark::State& state) {
  const auto in_flight = static_cast<std::size_t>(state.range(0));
  loopback lb;
  const auto target = ref("IED1LD0/MMXU1.TotW[MX]");
  std::atomic<std::size_t> failures{0};
  for (auto _ : state) {
    std::latch done(static_cast<std::ptrdiff_t>(in_flight));
    for (std::size_t i = 0; i < in_flight; ++i) {
      asio::co_spawn(
          lb.context(),
          [&]() -> awaitable<void> {
            auto r = co_await lb.client().read(target);
            if (!r) failures.fetch_add(1, std::memory_order_relaxed);
            done.count_down();
          },
          asio::detached);
    }
    done.wait();
  }
  if (failures.load() != 0) state.SkipWithError("some reads failed");
  state.SetItemsProcessed(state.iterations() * state.range(0));
}
BENCHMARK(BM_LoopbackRead)->ArgName("in_flight")->Arg(1)->Arg(8)->Arg(64)->UseRealTime();

// Reports per second through an enabled URCB: each iteration makes the server emit `range(0)`
// reports (data change of MMXU1.TotW.mag.f, a member of DS1) and waits until the client has
// parsed and queued all of them (client::next_report()).
void BM_LoopbackReports(benchmark::State& state) {
  const auto batch = static_cast<std::size_t>(state.range(0));
  loopback lb;
  bool enabled = false;
  lb.run([&]() -> awaitable<void> {
    client::report_settings s;
    s.opt_flds = model::optional_fields::of({model::optional_field::sequence_number,
                                             model::optional_field::reason_for_inclusion,
                                             model::optional_field::data_set_name});
    auto r = co_await lb.client().enable_reporting(ref("IED1LD0/LLN0.urcb01[RP]"), s);
    enabled = bool(r);
  });
  if (!enabled) {
    state.SkipWithError("enable_reporting failed");
    return;
  }
  std::size_t received = 0;
  std::size_t lost = 0;
  float value = 0;
  for (auto _ : state) {
    lb.run([&]() -> awaitable<void> {
      for (std::size_t i = 0; i < batch; ++i) {
        value += 1.0F;
        lb.server().update("MMXU1$MX$TotW$mag$f", mms::data::floating_point(value));
      }
      for (std::size_t i = 0; i < batch; ++i) {
        auto r = co_await lb.client().next_report();
        if (!r) throw std::runtime_error("next_report failed");
        lost += r->lost_before;
        ++received;
      }
    });
  }
  state.counters["lost"] = static_cast<double>(lost);
  state.SetItemsProcessed(static_cast<std::int64_t>(received));
}
BENCHMARK(BM_LoopbackReports)->ArgName("batch")->Arg(1)->Arg(64)->UseRealTime();

}  // namespace
