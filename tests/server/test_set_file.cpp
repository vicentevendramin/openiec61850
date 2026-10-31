// SetFile (MMS obtainFile): the server pulls a file from the client on the same association.

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unistd.h>
#include <utility>
#include <variant>
#include <vector>

#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>

#include "openiec61850/association/association.hpp"
#include "server_test_util.hpp"

using namespace server_test;
using asio::awaitable;
using openiec61850::byte_buffer;

namespace {

namespace assoc = openiec61850::association;
namespace ec = mms::error_code;
namespace reject = mms::reject_code::confirmed_request;

srv::data_model make_small_model() {
  srv::model_builder b;
  auto ld = b.logical_device("IED1LD0");
  ld.logical_node("LLN0").data_object("Mod").attribute("stVal", model::fc::ST, model::basic_type::enumerated);
  auto m = b.build();
  REQUIRE(m);
  return std::move(*m);
}

srv::server start_small(asio::any_io_executor ex, srv::server_options o = {}) {
  o.association.transport.handshake_timeout = 2s;
  o.association.association_timeout = 2s;
  o.association.request_timeout = 2s;
  if (!o.on_obtain_file) {
    o.on_obtain_file = [](const srv::obtain_file_event&) -> std::optional<srv::file_errc> {
      return std::nullopt;
    };
  }
  auto s = srv::server::start(std::move(ex), make_small_model(), loopback, std::move(o));
  REQUIRE(s);
  return std::move(*s);
}

byte_buffer pattern(std::size_t n) {
  byte_buffer b(n);
  for (std::size_t i = 0; i < n; ++i) b[i] = static_cast<std::uint8_t>(i * 13);
  return b;
}

bool same(openiec61850::byte_view a, std::span<const std::uint8_t> b) {
  return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin());
}

void answer(asio::any_io_executor ex, assoc::incoming_request r, mms::confirmed_service_response resp) {
  asio::co_spawn(
      ex,
      [](assoc::incoming_request q, mms::confirmed_service_response p) -> awaitable<void> {
        (void)co_await q.respond(p);
      }(std::move(r), std::move(resp)),
      asio::detached);
}

awaitable<assoc::request_result> raw_obtain(assoc::client_association& a, std::string_view from,
                                            std::string_view to) {
  const std::array<std::string_view, 1> source{from};
  const std::array<std::string_view, 1> destination{to};
  co_return co_await a.request(mms::obtain_file_request{std::nullopt, source, destination});
}

// Runs one obtainFile from a client whose fileRead answers come from `chunks`; a fileOpen
// declares `size`. Returns the ObtainFile outcome and whether the file was closed.
struct hostile_outcome {
  std::optional<assoc::request_result> result;
  bool closed = false;
};

struct chunk {
  byte_buffer data;
  bool more = false;
};

// Outside the coroutines: GCC 13 crashes on braced lists of these inside one.
std::vector<chunk> chunks_of(std::size_t size, bool more = false) {
  std::vector<chunk> v;
  v.push_back({pattern(size), more});
  return v;
}

std::vector<chunk> two_chunks() {
  auto v = chunks_of(1, true);
  v.push_back({pattern(3), false});
  return v;
}

awaitable<hostile_outcome> obtain_from_hostile(srv::server& s, std::uint32_t size, std::vector<chunk> chunks) {
  const auto ex = co_await asio::this_coro::executor;
  auto c = co_await assoc::client_association::connect(ex, options_for(s).association);
  REQUIRE(c);
  auto chunks_left = std::make_shared<std::vector<chunk>>(std::move(chunks));
  auto closed = std::make_shared<bool>(false);
  c->set_request_handler([=](assoc::incoming_request r) {
    if (std::holds_alternative<mms::file_open_request>(r.service())) {
      mms::file_open_response o;
      o.frsm_id = 7;
      o.attributes.size = size;
      answer(ex, std::move(r), o);
    } else if (std::holds_alternative<mms::file_read_request>(r.service())) {
      REQUIRE_FALSE(chunks_left->empty());
      auto next = std::make_shared<chunk>(std::move(chunks_left->front()));
      chunks_left->erase(chunks_left->begin());
      asio::co_spawn(
          ex,
          [](assoc::incoming_request q, std::shared_ptr<chunk> k) -> awaitable<void> {
            (void)co_await q.respond(mms::file_read_response{k->data, k->more});
          }(std::move(r), std::move(next)),
          asio::detached);
    } else {
      *closed = true;
      answer(ex, std::move(r), mms::file_close_response{});
    }
  });
  hostile_outcome out;
  out.result.emplace(co_await raw_obtain(*c, "src", "dst"));
  out.closed = *closed;
  co_return out;
}

void check_file_error(const assoc::request_result& r, std::int64_t code, std::span<const std::uint8_t> which) {
  REQUIRE_FALSE(r);
  REQUIRE(r.failure().service_error);
  const auto& e = *r.failure().service_error;
  CHECK(e.cls == mms::error_class::file);
  CHECK(e.code == code);
  CHECK(same(e.service_specific_info, which));
}

}  // namespace

TEST_CASE("SetFile: the file reaches the store, chunk by chunk", "[server][files]") {
  run([]() -> awaitable<void> {
    auto store = std::make_shared<srv::memory_file_store>();
    std::vector<srv::obtain_file_event> events;
    srv::server_options o;
    o.files = store;
    o.on_obtain_file = [&](const srv::obtain_file_event& e) -> std::optional<srv::file_errc> {
      events.push_back(e);
      return std::nullopt;
    };
    auto s = start_small(co_await asio::this_coro::executor, o);
    auto co = options_for(s);
    co.association.initiate.local_detail_calling = 1024;  // small PDUs both ways
    auto c = co_await connect(co);

    const auto big = pattern(150000);
    auto w = co_await c.set_file("/fw/image.bin", big);
    REQUIRE(w);
    const auto stored = store->get("fw/image.bin");
    REQUIRE(stored);
    CHECK(*stored == big);
    REQUIRE(events.size() == 1);
    CHECK(events[0].source == "/fw/image.bin");
    CHECK(events[0].destination == "fw/image.bin");
    auto back = co_await c.get_file("fw/image.bin");
    REQUIRE(back);
    CHECK(*back == big);

    // An empty file, and a stream with its own source name.
    auto empty = co_await c.set_file("empty", byte_buffer{});
    CHECK(empty);
    CHECK(store->get("empty") == byte_buffer{});
    client::file_source src;
    src.size = 5;
    src.name = "local.bin";
    src.read = [](std::uint64_t offset, std::span<std::uint8_t> out) -> openiec61850::result<std::size_t> {
      static constexpr std::array<std::uint8_t, 5> content{1, 2, 3, 4, 5};
      const auto n = std::min<std::size_t>(out.size(), 5 - static_cast<std::size_t>(offset));
      std::copy_n(content.begin() + static_cast<std::ptrdiff_t>(offset), n, out.begin());
      return n;
    };
    auto stream = co_await c.set_file("copy.bin", src);
    CHECK(stream);
    CHECK(store->get("copy.bin") == byte_buffer{1, 2, 3, 4, 5});
    CHECK(events.back().source == "local.bin");

    // The association stays usable and releases normally.
    auto dir = co_await c.get_file_directory();
    REQUIRE(dir);
    CHECK(dir->size() == 3);
    auto closed = co_await c.release();
    CHECK(closed);
    s.stop();
  });
}

TEST_CASE("SetFile: the client's requests are served during the transfer", "[server][files]") {
  run([]() -> awaitable<void> {
    auto store = std::make_shared<srv::memory_file_store>();
    REQUIRE(store->put("other.txt", {'o', 'k'}));
    srv::server_options o;
    o.files = store;
    auto s = start_small(co_await asio::this_coro::executor, o);
    auto c = co_await connect(options_for(s));

    // The source pauses the server by answering slowly: reads run while obtainFile is outstanding.
    client::file_source src;
    src.size = 3;
    auto reads = std::make_shared<int>(0);
    src.read = [reads](std::uint64_t, std::span<std::uint8_t> out) -> openiec61850::result<std::size_t> {
      ++*reads;
      out[0] = 'x';
      return std::size_t{1};
    };
    auto done = std::make_shared<std::optional<openiec61850::result<void>>>();
    asio::co_spawn(
        co_await asio::this_coro::executor,
        [](client::client& cl, client::file_source fs, std::shared_ptr<std::optional<openiec61850::result<void>>> out)
            -> awaitable<void> { out->emplace(co_await cl.set_file("up.bin", std::move(fs))); }(c, src, done),
        asio::detached);
    for (int i = 0; i < 3; ++i) {
      auto r = co_await c.get_file("other.txt");
      REQUIRE(r);
    }
    while (!*done) co_await sleep(1ms);
    CHECK(**done);
    CHECK(store->get("up.bin") == byte_buffer{'x', 'x', 'x'});
    s.stop();
  });
}

TEST_CASE("SetFile: refused without a usable store", "[server][files]") {
  run([]() -> awaitable<void> {
    const auto ex = co_await asio::this_coro::executor;
    const auto offered = [](const client::client& c) {
      return c.association_info().negotiated.services_supported_called.test(mms::service_bit::obtain_file);
    };
    // No store: rejected and not advertised.
    {
      auto s = start_small(ex);
      auto c = co_await connect(options_for(s));
      CHECK_FALSE(offered(c));
      client::error_details d;
      auto w = co_await c.set_file("a", byte_buffer{1}, d);
      CHECK(w.error() == assoc::errc::request_rejected);
      REQUIRE(d.reject);
      CHECK(d.reject->reason == reject::unrecognized_service);
      s.stop();
    }
    // A read-only store: the same.
    {
      struct read_only final : srv::file_store {
        openiec61850::result<std::vector<srv::file_info>> list(std::string_view) override { return std::vector<srv::file_info>{}; }
        openiec61850::result<srv::file_info> stat(std::string_view) override { return srv::make_error_code(srv::file_errc::not_found); }
        openiec61850::result<std::size_t> read(std::string_view, std::uint64_t, std::span<std::uint8_t>) override { return std::size_t{0}; }
        openiec61850::result<void> remove(std::string_view) override { return srv::make_error_code(srv::file_errc::access_denied); }
        openiec61850::result<void> rename(std::string_view, std::string_view) override { return srv::make_error_code(srv::file_errc::access_denied); }
      };
      srv::server_options o;
      o.files = std::make_shared<read_only>();
      auto s = start_small(ex, o);
      auto c = co_await connect(options_for(s));
      CHECK_FALSE(offered(c));
      auto w = co_await c.set_file("a", byte_buffer{1});
      CHECK(w.error() == assoc::errc::request_rejected);
      s.stop();
    }
    // Disabled by size.
    {
      srv::server_options o;
      o.files = std::make_shared<srv::memory_file_store>();
      o.max_obtain_file_size = 0;
      auto s = start_small(ex, o);
      auto c = co_await connect(options_for(s));
      CHECK_FALSE(offered(c));
      s.stop();
    }
    // Advertised with a writable store, also over a custom list only when usable.
    {
      srv::server_options o;
      o.files = std::make_shared<srv::memory_file_store>();
      auto s = start_small(ex, o);
      auto c = co_await connect(options_for(s));
      CHECK(offered(c));
      s.stop();
    }
    {
      srv::server_options o;
      o.association.limits.detail.services =
          mms::support_options(mms::service_bit::bit_count, {mms::service_bit::read, mms::service_bit::obtain_file});
      auto s = start_small(ex, o);
      auto c = co_await connect(options_for(s));
      CHECK_FALSE(offered(c));
      s.stop();
    }
  });
}

TEST_CASE("SetFile: destination checks and the hook", "[server][files]") {
  run([]() -> awaitable<void> {
    auto store = std::make_shared<srv::memory_file_store>();
    REQUIRE(store->put("exists.txt", {1}));
    int pulled = 0;
    srv::server_options o;
    o.files = store;
    o.max_obtain_file_size = 1000;
    o.on_obtain_file = [&](const srv::obtain_file_event& e) -> std::optional<srv::file_errc> {
      if (e.destination == "locked/a") return srv::file_errc::access_denied;
      if (e.destination == "full/a") return srv::file_errc::no_space;
      return std::nullopt;
    };
    auto s = start_small(co_await asio::this_coro::executor, o);
    auto c = co_await connect(options_for(s));
    const auto reject_code = [&](client::error_details& d) { return d.service_error ? d.service_error->code : -1; };

    client::file_source counted;
    counted.size = 1;
    counted.read = [&](std::uint64_t, std::span<std::uint8_t> out) -> openiec61850::result<std::size_t> {
      ++pulled;
      out[0] = 0;
      return std::size_t{1};
    };

    client::error_details d;
    auto r = co_await c.set_file("exists.txt", counted, d);
    CHECK_FALSE(r);
    CHECK(reject_code(d) == ec::file::duplicate_filename);
    CHECK(store->get("exists.txt") == byte_buffer{1});

    for (const char* bad : {"../etc/passwd", "a/../b", "c:\\x"}) {
      r = co_await c.set_file(bad, counted, d);
      CHECK_FALSE(r);
      CHECK(reject_code(d) == ec::file::filename_syntax_error);
    }
    r = co_await c.set_file("locked/a", counted, d);
    CHECK_FALSE(r);
    CHECK(reject_code(d) == ec::file::file_access_denied);
    REQUIRE(d.service_error);
    CHECK(same(d.service_error->service_specific_info, mms::obtain_file_error::destination_file));
    r = co_await c.set_file("full/a", counted, d);
    CHECK(reject_code(d) == ec::file::insufficient_space_in_filestore);
    CHECK(pulled == 0);  // nothing was read for any of them

    // Too big for the bound: refused from the declared size, without reading it.
    r = co_await c.set_file("big", pattern(1001), d);
    CHECK_FALSE(r);
    CHECK(reject_code(d) == ec::file::insufficient_space_in_filestore);
    CHECK_FALSE(store->get("big"));
    r = co_await c.set_file("fits", pattern(1000), d);
    CHECK(r);

    // A busy destination: open for reading.
    auto opened = co_await assoc::client_association::connect(co_await asio::this_coro::executor,
                                                              options_for(s).association);
    REQUIRE(opened);
    const std::array<std::string_view, 1> fits{"fits"};
    auto open_it = co_await opened->request(mms::file_open_request{fits, 0});
    REQUIRE(open_it);
    REQUIRE(store->remove("fits"));
    r = co_await c.set_file("fits", counted, d);
    CHECK(reject_code(d) == ec::file::file_busy);
    s.stop();
  });
}

TEST_CASE("SetFile: a third party source and an empty source name are refused", "[server][files]") {
  run([]() -> awaitable<void> {
    auto store = std::make_shared<srv::memory_file_store>();
    srv::server_options o;
    o.files = store;
    auto s = start_small(co_await asio::this_coro::executor, o);
    auto a = co_await assoc::client_association::connect(co_await asio::this_coro::executor,
                                                         options_for(s).association);
    REQUIRE(a);
    const std::array<std::string_view, 1> name{"a"};
    const byte_buffer ref{0xA2, 0x00};
    auto r = co_await a->request(mms::obtain_file_request{openiec61850::byte_view(ref), name, name});
    check_file_error(r, ec::file::other, mms::obtain_file_error::source_file);
    const std::array<std::string_view, 1> nothing{""};
    r = co_await a->request(mms::obtain_file_request{std::nullopt, nothing, name});
    check_file_error(r, ec::file::filename_syntax_error, mms::obtain_file_error::source_file);
    r = co_await a->request(mms::obtain_file_request{std::nullopt, name, nothing});
    check_file_error(r, ec::file::filename_syntax_error, mms::obtain_file_error::destination_file);
    s.stop();
  });
}

TEST_CASE("SetFile: a client that misbehaves stores nothing", "[server][files]") {
  run([]() -> awaitable<void> {
    auto store = std::make_shared<srv::memory_file_store>();
    srv::server_options o;
    o.files = store;
    o.max_obtain_file_size = 100;
    auto s = start_small(co_await asio::this_coro::executor, o);
    const auto source = mms::obtain_file_error::source_file;

    // More than declared.
    auto r = co_await obtain_from_hostile(s, 2, chunks_of(3));
    check_file_error(*r.result, ec::file::other, source);
    CHECK(r.closed);
    // Ends early.
    r = co_await obtain_from_hostile(s, 5, chunks_of(3));
    check_file_error(*r.result, ec::file::other, source);
    CHECK(r.closed);
    // moreFollows without progress.
    r = co_await obtain_from_hostile(s, 5, chunks_of(0, true));
    check_file_error(*r.result, ec::file::other, source);
    CHECK(r.closed);
    // The declared size is above the bound: closed without a read.
    r = co_await obtain_from_hostile(s, 101, std::vector<chunk>{});
    check_file_error(*r.result, ec::file::insufficient_space_in_filestore, mms::obtain_file_error::destination_file);
    CHECK(r.closed);
    CHECK_FALSE(store->get("dst"));
    // A well-behaved one for comparison.
    r = co_await obtain_from_hostile(s, 4, two_chunks());
    REQUIRE(*r.result);
    CHECK(r.closed);
    CHECK(store->get("dst").has_value());
    s.stop();
  });
}

TEST_CASE("SetFile: the client refusing FileOpen or failing a read fails the request", "[server][files]") {
  run([]() -> awaitable<void> {
    auto store = std::make_shared<srv::memory_file_store>();
    srv::server_options o;
    o.files = store;
    auto s = start_small(co_await asio::this_coro::executor, o);

    // A client that serves nothing: the default handler rejects the reverse request.
    auto a = co_await assoc::client_association::connect(co_await asio::this_coro::executor,
                                                         options_for(s).association);
    REQUIRE(a);
    auto r = co_await raw_obtain(*a, "src", "dst");
    check_file_error(r, ec::file::other, mms::obtain_file_error::source_file);

    // A local read error reaches the caller as a file error about the source.
    auto c = co_await connect(options_for(s));
    client::file_source src;
    src.size = 10;
    src.read = [](std::uint64_t, std::span<std::uint8_t>) -> openiec61850::result<std::size_t> {
      return openiec61850::errc::invalid_state;
    };
    client::error_details d;
    auto w = co_await c.set_file("x", src, d);
    CHECK_FALSE(w);
    REQUIRE(d.service_error);
    CHECK(d.service_error->cls == mms::error_class::file);
    CHECK(same(d.service_error->service_specific_info, mms::obtain_file_error::source_file));
    CHECK_FALSE(store->get("x"));

    // So does a source shorter than announced.
    src.read = [](std::uint64_t, std::span<std::uint8_t>) -> openiec61850::result<std::size_t> {
      return std::size_t{0};
    };
    w = co_await c.set_file("y", src, d);
    CHECK_FALSE(w);
    CHECK_FALSE(store->get("y"));

    // And misuse fails locally.
    auto no_name = co_await c.set_file("", byte_buffer{1});
    CHECK(no_name.error() == openiec61850::errc::invalid_state);
    client::file_source huge;
    huge.size = std::uint64_t{1} << 32;
    huge.read = src.read;
    auto too_big = co_await c.set_file("z", huge);
    CHECK(too_big.error() == openiec61850::errc::value_out_of_range);
    s.stop();
  });
}

TEST_CASE("SetFile: the server stops while waiting for the client", "[server][files]") {
  run([]() -> awaitable<void> {
    auto store = std::make_shared<srv::memory_file_store>();
    srv::server_options o;
    o.files = store;
    auto s = start_small(co_await asio::this_coro::executor, o);
    const auto ex = co_await asio::this_coro::executor;
    auto a = co_await assoc::client_association::connect(ex, options_for(s).association);
    REQUIRE(a);
    // Held unanswered, so the server's fileOpen stays outstanding.
    auto held = std::make_shared<std::vector<assoc::incoming_request>>();
    a->set_request_handler([held](assoc::incoming_request r) { held->push_back(std::move(r)); });
    auto done = std::make_shared<bool>(false);
    asio::co_spawn(
        ex,
        [](assoc::client_association& c, std::shared_ptr<bool> flag) -> awaitable<void> {
          auto r = co_await raw_obtain(c, "src", "dst");
          CHECK_FALSE(r);
          *flag = true;
        }(*a, done),
        asio::detached);
    while (held->empty()) co_await sleep(1ms);
    s.stop();
    co_await s.wait_stopped();
    while (!*done) co_await sleep(1ms);
    CHECK_FALSE(store->get("dst"));
    held->clear();
  });
}

TEST_CASE("SetFile: one transfer per association, one per destination", "[server][files]") {
  run([]() -> awaitable<void> {
    auto store = std::make_shared<srv::memory_file_store>();
    srv::server_options o;
    o.files = store;
    auto s = start_small(co_await asio::this_coro::executor, o);
    const auto ex = co_await asio::this_coro::executor;
    auto a = co_await assoc::client_association::connect(ex, options_for(s).association);
    REQUIRE(a);
    auto held = std::make_shared<std::vector<assoc::incoming_request>>();
    a->set_request_handler([held](assoc::incoming_request r) { held->push_back(std::move(r)); });
    asio::co_spawn(
        ex,
        [](assoc::client_association& c) -> awaitable<void> {
          auto r = co_await raw_obtain(c, "src", "dst");
          CHECK_FALSE(r);
        }(*a),
        asio::detached);
    while (held->empty()) co_await sleep(1ms);

    // The same association.
    auto second = co_await raw_obtain(*a, "src2", "dst2");
    REQUIRE_FALSE(second);
    REQUIRE(second.failure().service_error);
    CHECK(second.failure().service_error->cls == mms::error_class::resource);
    CHECK(second.failure().service_error->code == ec::resource::capability_unavailable);

    // Another association, the same destination.
    auto b = co_await assoc::client_association::connect(ex, options_for(s).association);
    REQUIRE(b);
    auto third = co_await raw_obtain(*b, "src3", "dst");
    check_file_error(third, ec::file::file_busy, mms::obtain_file_error::destination_file);

    held->clear();  // the unanswered fileOpen fails, and with it the first transfer
    co_await sleep(20ms);
    s.stop();
  });
}

namespace {

awaitable<client::client> connect_scripted(assoc::association_listener& l) {
  client::client_options co;
  co.association.host = "127.0.0.1";
  co.association.port = l.local_endpoint().port();
  co.association.request_timeout = 2s;
  co.file_transfer_timeout = 300ms;
  auto c = co_await client::client::connect(co_await asio::this_coro::executor, std::move(co));
  REQUIRE(c);
  co_return std::move(*c);
}

}  // namespace

TEST_CASE("SetFile: the client offers that file and nothing else", "[client][files]") {
  run([]() -> awaitable<void> {
    const auto ex = co_await asio::this_coro::executor;
    auto l = assoc::association_listener::listen(ex, loopback);
    REQUIRE(l);
    asio::co_spawn(
        ex,
        [](assoc::association_listener& lst) -> awaitable<void> {
          auto a = co_await lst.accept();
          REQUIRE(a);
          co_await sleep(20ms);  // until the client has its handler
          // Nothing is on offer yet.
          const std::array<std::string_view, 1> early{"file"};
          auto none = co_await a->request(mms::file_open_request{early, 0});
          REQUIRE_FALSE(none);
          CHECK(none.failure().service_error->code == ec::file::file_non_existent);

          auto req = co_await a->next_request();
          REQUIRE(req);
          const auto& ob = std::get<mms::obtain_file_request>(req->service());
          // Another name, an unknown FRSM and a service the client does not offer.
          const std::array<std::string_view, 1> other{"/etc/passwd"};
          auto r = co_await a->request(mms::file_open_request{other, 0});
          REQUIRE_FALSE(r);
          CHECK(r.failure().service_error->code == ec::file::file_non_existent);
          r = co_await a->request(mms::file_read_request{99});
          REQUIRE_FALSE(r);
          CHECK(r.failure().service_error->cls == mms::error_class::file);
          r = co_await a->request(mms::file_close_request{99});
          REQUIRE_FALSE(r);
          r = co_await a->request(mms::identify_request{});
          REQUIRE_FALSE(r);
          REQUIRE(r.failure().reject);
          CHECK(r.failure().reject->reason == reject::unrecognized_service);
          // A position past the end, then a read from the middle.
          r = co_await a->request(mms::file_open_request{ob.source_file, 5});
          REQUIRE_FALSE(r);
          CHECK(r.failure().service_error->code == ec::file::position_invalid);
          r = co_await a->request(mms::file_open_request{ob.source_file, 2});
          REQUIRE(r);
          const auto* o = std::get_if<mms::file_open_response>(&r->service());
          REQUIRE(o != nullptr);
          CHECK(o->attributes.size == 4);
          const auto frsm = o->frsm_id;
          r = co_await a->request(mms::file_read_request{frsm});
          REQUIRE(r);
          const auto* d = std::get_if<mms::file_read_response>(&r->service());
          REQUIRE(d != nullptr);
          CHECK(byte_buffer(d->data.begin(), d->data.end()) == byte_buffer{3, 4});
          CHECK_FALSE(d->more_follows);
          r = co_await a->request(mms::file_close_request{frsm});
          CHECK(r);
          (void)co_await req->respond(mms::obtain_file_response{});
          (void)co_await a->wait_closed();
        }(*l),
        asio::detached);
    auto c = co_await connect_scripted(*l);
    co_await sleep(50ms);
    auto w = co_await c.set_file("file", byte_buffer{1, 2, 3, 4});
    CHECK(w);
    c.abort();
    co_await sleep(5ms);
  });
}

TEST_CASE("SetFile: the transfer timeout withdraws the file", "[client][files]") {
  run([]() -> awaitable<void> {
    const auto ex = co_await asio::this_coro::executor;
    auto l = assoc::association_listener::listen(ex, loopback);
    REQUIRE(l);
    auto late_code = std::make_shared<std::int64_t>(-1);
    asio::co_spawn(
        ex,
        [](assoc::association_listener& lst, std::shared_ptr<std::int64_t> code) -> awaitable<void> {
          auto a = co_await lst.accept();
          REQUIRE(a);
          auto req = co_await a->next_request();
          REQUIRE(req);
          co_await sleep(500ms);  // past file_transfer_timeout
          const auto& ob = std::get<mms::obtain_file_request>(req->service());
          auto r = co_await a->request(mms::file_open_request{ob.source_file, 0});
          REQUIRE_FALSE(r);
          *code = r.failure().service_error->code;
          (void)co_await a->wait_closed();
        }(*l, late_code),
        asio::detached);
    auto c = co_await connect_scripted(*l);
    auto w = co_await c.set_file("file", byte_buffer{1});
    CHECK(w.error() == assoc::errc::request_timed_out);
    while (*late_code < 0) co_await sleep(5ms);
    CHECK(*late_code == ec::file::file_non_existent);
    c.abort();
    co_await sleep(5ms);
  });
}

TEST_CASE("SetFile: concurrent calls need distinct source names", "[client][files]") {
  run([]() -> awaitable<void> {
    auto store = std::make_shared<srv::memory_file_store>();
    srv::server_options o;
    o.files = store;
    auto s = start_small(co_await asio::this_coro::executor, o);
    auto c = co_await connect(options_for(s));
    const auto ex = co_await asio::this_coro::executor;
    auto first = std::make_shared<std::optional<openiec61850::result<void>>>();
    client::file_source src;
    src.size = 1;
    src.name = "same";
    src.read = [](std::uint64_t, std::span<std::uint8_t> out) -> openiec61850::result<std::size_t> {
      out[0] = 1;
      return std::size_t{1};
    };
    asio::co_spawn(
        ex,
        [](client::client& cl, client::file_source f, std::shared_ptr<std::optional<openiec61850::result<void>>> out)
            -> awaitable<void> { out->emplace(co_await cl.set_file("one", std::move(f))); }(c, src, first),
        asio::detached);
    auto second = co_await c.set_file("two", src);
    while (!*first) co_await sleep(1ms);
    CHECK(**first);
    if (second) {
      // The first finished before the second started: both are fine then.
      CHECK(store->get("two").has_value());
    } else {
      CHECK(second.error() == openiec61850::errc::invalid_state);
    }
    s.stop();
  });
}

TEST_CASE("Directory store: write", "[server][files]") {
  namespace fs = std::filesystem;
  const auto base = fs::temp_directory_path() / ("oiec_write_" + std::to_string(::getpid()));
  fs::remove_all(base);
  fs::create_directories(base / "root");
  auto opened = srv::directory_file_store::open(base / "root");
  REQUIRE(opened);
  auto& store = **opened;
  CHECK(store.writable());
  const byte_buffer content{1, 2, 3};

  REQUIRE(store.write("a/b/c.bin", content));
  auto back = store.stat("a/b/c.bin");
  REQUIRE(back);
  CHECK(back->size == 3);
  CHECK(store.write("a/b/c.bin", content).error() == srv::file_errc::exists);
  CHECK(store.write("../out", content).error() == srv::file_errc::invalid_name);
  CHECK(store.write("a", content).error() == srv::file_errc::exists);  // a directory
  CHECK_FALSE(fs::exists(base / "out"));

  // A link out of the root is not followed, whether or not its target exists.
  std::error_code ec_link;
  fs::create_symlink(base / "outside", base / "root" / "dangling", ec_link);
  if (!ec_link) {
    CHECK_FALSE(store.write("dangling", content));
    CHECK_FALSE(fs::exists(base / "outside"));
    fs::create_directories(base / "outside_dir");
    fs::create_directory_symlink(base / "outside_dir", base / "root" / "linkdir");
    CHECK(store.write("linkdir/x", content).error() == srv::file_errc::access_denied);
    CHECK_FALSE(fs::exists(base / "outside_dir" / "x"));
  }

  // No temporary file stays behind.
  std::size_t entries = 0;
  for (const auto& e : fs::recursive_directory_iterator(base / "root")) {
    if (e.is_regular_file()) ++entries;
  }
  CHECK(entries == 1);
  fs::remove_all(base);

  srv::memory_file_store memory;
  CHECK(memory.writable());
  REQUIRE(memory.write("x", content));
  CHECK(memory.write("x", content).error() == srv::file_errc::exists);
  CHECK(memory.write("/x/", content).error() == srv::file_errc::exists);
  CHECK(memory.write("../y", content).error() == srv::file_errc::invalid_name);
  CHECK(memory.get("x") == content);
  auto info = memory.stat("x");
  REQUIRE(info);
  CHECK(info->last_modified.has_value());

  struct plain final : srv::file_store {
    openiec61850::result<std::vector<srv::file_info>> list(std::string_view) override { return std::vector<srv::file_info>{}; }
    openiec61850::result<srv::file_info> stat(std::string_view) override { return srv::make_error_code(srv::file_errc::not_found); }
    openiec61850::result<std::size_t> read(std::string_view, std::uint64_t, std::span<std::uint8_t>) override { return std::size_t{0}; }
    openiec61850::result<void> remove(std::string_view) override { return {}; }
    openiec61850::result<void> rename(std::string_view, std::string_view) override { return {}; }
  } p;
  CHECK_FALSE(p.writable());
  CHECK(p.write("x", content).error() == srv::file_errc::access_denied);
}

TEST_CASE("SetFile is off without on_obtain_file", "[server][files]") {
  run([]() -> awaitable<void> {
    srv::server_options o;
    o.files = std::make_shared<srv::memory_file_store>();
    o.association.request_timeout = 2s;
    auto s = srv::server::start(co_await asio::this_coro::executor, make_small_model(), loopback, o);
    REQUIRE(s);
    auto c = co_await connect(options_for(*s));
    const auto support = c.association_info().negotiated.services_supported_called;
    CHECK_FALSE(support.test(mms::service_bit::obtain_file));
    auto r = co_await c.set_file("a", pattern(4));
    CHECK_FALSE(r);
    s->stop();
    co_await s->wait_stopped();
  });
}
