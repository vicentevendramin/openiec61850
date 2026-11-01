// Load generator of the Reference benchmark: reads one object through the openiec61850 client
// over loopback and prints a single JSON object. It does not know which server it talks to, so the
// same binary and the same settings measure both peers.
//
//   openiec61850_ref_loadgen --port N --ref REF [--associations A] [--in-flight N] [--threads T]
//                            [--warmup SECONDS] [--duration SECONDS]
//
// Each association runs N closed-loop workers: a worker issues a read, waits for its response and
// issues the next one, so N=1 is sequential and N>1 is pipelined up to the negotiated max serv
// outstanding (further reads wait in the client for a request slot, and that wait counts in their
// latency). Reads finishing in the warm-up are discarded. Exit status 0 when the run produced
// numbers, even with errors: those are reported, and judged by the harness.

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <asio/co_spawn.hpp>
#include <asio/io_context.hpp>
#include <asio/steady_timer.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>

#include "openiec61850/client/client.hpp"
#include "openiec61850/model/object_reference.hpp"

namespace {

namespace client = openiec61850::client;
namespace model = openiec61850::model;
using asio::awaitable;
using clock_type = std::chrono::steady_clock;
using namespace std::chrono_literals;

struct settings {
  std::uint16_t port = 0;
  std::string ref;
  std::size_t associations = 1;
  std::size_t in_flight = 1;
  std::size_t threads = 1;
  double warmup = 1;
  double duration = 5;
};

struct worker_result {
  std::vector<std::uint32_t> latency_ns;
  std::uint64_t errors = 0;
  std::uint64_t value_changes = 0;
  std::size_t value_leaves = 0;
};

// Scalars in a value: both servers must be answering with the same shape to be comparable.
std::size_t leaves(const openiec61850::mms::data& d) {
  const auto children = d.elements();
  if (children.empty()) return 1;
  std::size_t n = 0;
  for (const auto& c : children) n += leaves(c);
  return n;
}

struct run_state {
  explicit run_state(const settings& s) : options(s), io(static_cast<int>(s.threads)) {}
  settings options;
  asio::io_context io;
  std::optional<model::object_reference> ref;
  std::vector<std::optional<client::client>> clients;
  std::vector<worker_result> results;
  std::vector<double> connect_ms;
  std::size_t connect_failures = 0;
  std::string connect_error;
  int negotiated_outstanding = 0;
  bool finished = false;
};

awaitable<void> worker(run_state& st, client::client& c, worker_result& out,
                       clock_type::time_point start, clock_type::time_point end) {
  std::uint32_t last_bits = 0;
  bool have_last = false;
  out.latency_ns.reserve(std::size_t{1} << 20U);
  for (;;) {
    const auto t0 = clock_type::now();
    if (t0 >= end) break;
    auto r = co_await c.read(*st.ref);
    const auto t1 = clock_type::now();
    if (!r) {
      ++out.errors;
      continue;
    }
    if (t1 < start || t1 >= end) continue;
    const auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();
    out.latency_ns.push_back(static_cast<std::uint32_t>(std::min<std::int64_t>(ns, UINT32_MAX)));
    if (out.value_leaves == 0) out.value_leaves = leaves(*r);
    // How often the served value moves: the servers' own update rates are part of the method.
    if (auto f = r->as_float()) {
      std::uint32_t bits = 0;
      std::memcpy(&bits, &*f, sizeof bits);
      if (have_last && bits != last_bits) ++out.value_changes;
      last_bits = bits;
      have_last = true;
    }
  }
}

awaitable<void> run(run_state& st) {
  const auto ex = co_await asio::this_coro::executor;
  const auto& o = st.options;
  // One association at a time: the connect latency is not a thundering-herd measure.
  for (std::size_t i = 0; i < o.associations; ++i) {
    client::client_options co;
    co.association.port = o.port;
    co.association.request_timeout = 30s;
    co.association.initiate.max_serv_outstanding_calling = 64;
    co.association.initiate.max_serv_outstanding_called = 64;
    const auto t0 = clock_type::now();
    auto c = co_await client::client::connect(ex, co);
    const std::chrono::duration<double, std::milli> ms = clock_type::now() - t0;
    if (!c) {
      ++st.connect_failures;
      st.connect_error = c.error().message();
      continue;
    }
    st.connect_ms.push_back(ms.count());
    st.negotiated_outstanding = c->association_info().negotiated.max_serv_outstanding_calling;
    st.clients.emplace_back(std::move(*c));
  }
  st.results.resize(st.clients.size() * o.in_flight);
  const auto to_duration = [](double s) {
    return std::chrono::duration_cast<clock_type::duration>(std::chrono::duration<double>(s));
  };
  const auto start = clock_type::now() + to_duration(o.warmup);
  const auto end = start + to_duration(o.duration);
  auto pending = std::make_shared<std::atomic<std::size_t>>(st.results.size());
  std::size_t slot = 0;
  for (auto& c : st.clients) {
    for (std::size_t i = 0; i < o.in_flight; ++i) {
      asio::co_spawn(ex, worker(st, *c, st.results[slot++], start, end),
                     [pending](const std::exception_ptr&) { pending->fetch_sub(1); });
    }
  }
  asio::steady_timer timer(ex);
  while (pending->load() != 0) {
    timer.expires_after(10ms);
    co_await timer.async_wait(asio::use_awaitable);
  }
  for (auto& c : st.clients) {
    if (auto r = co_await c->release(); !r) c->abort();
  }
  st.clients.clear();
  st.finished = true;
  st.io.stop();
}

double percentile(const std::vector<std::uint32_t>& sorted, double q) {
  if (sorted.empty()) return 0;
  const auto i = static_cast<std::size_t>(q * static_cast<double>(sorted.size() - 1));
  return static_cast<double>(sorted[i]) / 1000.0;
}

}  // namespace

int main(int argc, char** argv) {
  settings s;
  for (int i = 1; i + 1 < argc; i += 2) {
    const std::string_view k = argv[i];
    const char* v = argv[i + 1];
    if (k == "--port") {
      s.port = static_cast<std::uint16_t>(std::strtoul(v, nullptr, 10));
    } else if (k == "--ref") {
      s.ref = v;
    } else if (k == "--associations") {
      s.associations = std::strtoull(v, nullptr, 10);
    } else if (k == "--in-flight") {
      s.in_flight = std::strtoull(v, nullptr, 10);
    } else if (k == "--threads") {
      s.threads = std::strtoull(v, nullptr, 10);
    } else if (k == "--warmup") {
      s.warmup = std::strtod(v, nullptr);
    } else if (k == "--duration") {
      s.duration = std::strtod(v, nullptr);
    } else {
      std::fprintf(stderr, "unknown option %s\n", argv[i]);
      return 2;
    }
  }
  run_state st(s);
  auto parsed = model::object_reference::parse(s.ref);
  if (s.port == 0 || !parsed) {
    std::fputs("--port and a functionally constrained --ref are required\n", stderr);
    return 2;
  }
  st.ref = std::move(*parsed);

  std::string failure;
  asio::co_spawn(st.io, run(st), [&](const std::exception_ptr& e) {
    if (!e) return;
    try {
      std::rethrow_exception(e);
    } catch (const std::exception& x) {
      failure = x.what();
    }
    st.io.stop();
  });
  std::vector<std::thread> extra;
  for (std::size_t i = 1; i < s.threads; ++i) extra.emplace_back([&] { st.io.run(); });
  st.io.run();
  for (auto& t : extra) t.join();
  if (!st.finished) {
    std::fprintf(stderr, "load generator failed: %s\n", failure.c_str());
    return 1;
  }

  std::vector<std::uint32_t> all;
  std::uint64_t errors = 0;
  std::uint64_t changes = 0;
  std::size_t value_leaves = 0;
  for (const auto& r : st.results) {
    value_leaves = std::max(value_leaves, r.value_leaves);
    all.insert(all.end(), r.latency_ns.begin(), r.latency_ns.end());
    errors += r.errors;
    changes += r.value_changes;
  }
  std::sort(all.begin(), all.end());
  std::sort(st.connect_ms.begin(), st.connect_ms.end());
  const double connect_p50 = st.connect_ms.empty() ? 0 : st.connect_ms[st.connect_ms.size() / 2];
  const double connect_max = st.connect_ms.empty() ? 0 : st.connect_ms.back();
  std::printf(
      "{\"reads\":%zu,\"errors\":%llu,\"reads_per_s\":%.1f,\"p50_us\":%.2f,\"p99_us\":%.2f,"
      "\"max_us\":%.2f,\"associations_up\":%zu,\"connect_failures\":%zu,\"connect_p50_ms\":%.3f,"
      "\"connect_max_ms\":%.3f,\"negotiated_outstanding\":%d,\"value_changes\":%llu,\"value_leaves\":%zu}\n",
      all.size(), static_cast<unsigned long long>(errors),
      static_cast<double>(all.size()) / s.duration, percentile(all, 0.50), percentile(all, 0.99),
      percentile(all, 1.0), st.connect_ms.size(), st.connect_failures, connect_p50, connect_max,
      st.negotiated_outstanding, static_cast<unsigned long long>(changes), value_leaves);
  if (st.connect_failures != 0) {
    std::fprintf(stderr, "connect failures: %zu, last: %s\n", st.connect_failures,
                 st.connect_error.c_str());
  }
  return 0;
}
