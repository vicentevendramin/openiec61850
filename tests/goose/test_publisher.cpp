#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <vector>

#include "goose_test_util.hpp"
#include "openiec61850/goose/pdu.hpp"
#include "openiec61850/goose/publisher.hpp"

namespace goose = openiec61850::goose;
namespace mms = openiec61850::mms;
namespace model = openiec61850::model;
using namespace std::chrono_literals;
using openiec61850::errc;

TEST_CASE("Retransmission intervals double from MinTime up to MaxTime", "[goose]") {
  const auto f = [](std::uint32_t n) { return goose::retransmission_interval(n, 4ms, 1000ms); };
  CHECK(f(1) == 4ms);
  CHECK(f(2) == 8ms);
  CHECK(f(3) == 16ms);
  CHECK(f(8) == 512ms);
  CHECK(f(9) == 1000ms);
  CHECK(f(10) == 1000ms);
  CHECK(f(0xFFFFFFFF) == 1000ms);
  CHECK(goose::retransmission_interval(1, 10ms, 10ms) == 10ms);
  CHECK(goose::retransmission_interval(5, 10ms, 10ms) == 10ms);
}

TEST_CASE("Publisher configuration is validated", "[goose]") {
  asio::io_context ctx;
  auto net = goose::loopback_network::create();
  auto l = net->attach(ctx.get_executor(), goose_test::mac_a);
  goose::publisher_config c;
  CHECK(goose::publisher::create(l, c, {}).error() == errc::invalid_state);  // no gocbRef
  c.gocb_ref = "LD/LLN0$GO$g";
  c.dat_set = "LD/LLN0$DS";
  c.max_time = 1ms;
  CHECK(goose::publisher::create(l, c, {}).error() == errc::invalid_state);  // max < min
  c.max_time = 100ms;
  CHECK(goose::publisher::create(l, c, {mms::data{}}).error() == errc::invalid_state);
  CHECK(goose::publisher::create(l, c, {}));
}

TEST_CASE("Publisher sends events and retransmissions on a loopback link", "[goose]") {
  asio::io_context ctx;
  auto net = goose::loopback_network::create();
  auto tx = net->attach(ctx.get_executor(), goose_test::mac_a);
  auto rx = net->attach(ctx.get_executor(), goose_test::mac_b);
  auto cap = goose_test::start_capture(ctx, rx);
  // Taken when sending: on a loaded machine a frame can wait before the capture sees it, which
  // would shorten the gap to the next one.
  std::vector<std::chrono::steady_clock::time_point> sent;
  net->set_filter([&sent](openiec61850::byte_view, const goose::mac_address& to) {
    if (to == goose_test::mac_b) sent.push_back(std::chrono::steady_clock::now());
    return true;
  });

  goose::publisher_config c;
  c.gocb_ref = "IED1LD0/LLN0$GO$gcb01";
  c.dat_set = "IED1LD0/LLN0$DS1";
  c.go_id = "gcb01";
  c.app_id = 0x0101;
  c.min_time = 4ms;
  c.max_time = 32ms;
  auto pub = goose::publisher::create(tx, c, {mms::data::boolean(false)});
  REQUIRE(pub);
  (*pub)->start();
  REQUIRE(goose_test::run_until(ctx, [&] { return cap->frames.size() >= 6; }));

  std::uint32_t expected_sq = 0;
  for (std::size_t i = 0; i < cap->frames.size(); ++i) {
    auto m = goose::decode(cap->frames[i]);
    REQUIRE(m);
    CHECK(m->frame.source == goose_test::mac_a);
    CHECK(m->frame.app_id == 0x0101);
    REQUIRE(m->frame.vlan);
    CHECK(m->frame.vlan->priority == 4);
    CHECK(m->pdu.gocb_ref == "IED1LD0/LLN0$GO$gcb01");
    CHECK(m->pdu.st_num == 1);
    CHECK(m->pdu.sq_num == expected_sq);
    // TAL = 2 x the interval until the next message.
    const auto next = goose::retransmission_interval(expected_sq + 1, 4ms, 32ms);
    CHECK(m->pdu.time_allowed_to_live == 2 * next.count());
    if (i > 0) {
      // Never earlier than scheduled.
      REQUIRE(i < sent.size());
      const auto gap = sent[i] - sent[i - 1];
      const auto planned = goose::retransmission_interval(expected_sq, 4ms, 32ms);
      CHECK(gap >= planned - 1ms);
    }
    ++expected_sq;
  }

  // A new state.
  cap->frames.clear();
  const auto when = model::timestamp::from_time_point(
      std::chrono::sys_seconds{std::chrono::seconds{1'700'000'000}});
  REQUIRE((*pub)->publish({mms::data::boolean(true)}, *when));
  REQUIRE(goose_test::run_until(ctx, [&] { return cap->frames.size() >= 2; }));
  auto first = goose::decode(cap->frames[0]);
  REQUIRE(first);
  CHECK(first->pdu.st_num == 2);
  CHECK(first->pdu.sq_num == 0);
  CHECK(first->pdu.t.seconds == 1'700'000'000U);
  CHECK(first->pdu.time_allowed_to_live == 8);
  CHECK(*first->pdu.all_data.begin()->as_boolean());
  auto second = goose::decode(cap->frames[1]);
  REQUIRE(second);
  CHECK(second->pdu.st_num == 2);
  CHECK(second->pdu.sq_num == 1);
  CHECK(second->pdu.t == first->pdu.t);  // t is the time of the event

  // update() with the same values is not an event.
  auto same = (*pub)->update({mms::data::boolean(true)});
  REQUIRE(same);
  CHECK_FALSE(*same);
  auto changed = (*pub)->update({mms::data::boolean(false)});
  REQUIRE(changed);
  CHECK(*changed);
  CHECK((*pub)->stats().st_num == 3);
  CHECK((*pub)->publish({mms::data{}}).error() == errc::invalid_state);

  // Stop ends the retransmissions.
  (*pub)->stop();
  goose_test::run_for(ctx, 5ms);
  const auto count = cap->frames.size();
  goose_test::run_for(ctx, 50ms);
  CHECK(cap->frames.size() == count);
  CHECK((*pub)->stats().send_errors == 0);
  CHECK((*pub)->stats().messages_sent >= 9);
}

TEST_CASE("Publisher simulation, ndsCom and fixed TAL", "[goose]") {
  asio::io_context ctx;
  auto net = goose::loopback_network::create();
  auto tx = net->attach(ctx.get_executor(), goose_test::mac_a);
  auto rx = net->attach(ctx.get_executor(), goose_test::mac_b);
  auto cap = goose_test::start_capture(ctx, rx);

  goose::publisher_config c;
  c.gocb_ref = "LD/LLN0$GO$g";
  c.dat_set = "LD/LLN0$DS";
  c.simulation = true;
  c.vlan.reset();
  c.source = goose_test::mac_b;
  c.tal_override = 3000ms;
  c.min_time = 50ms;
  c.max_time = 50ms;
  auto pub = goose::publisher::create(tx, c, {});
  REQUIRE(pub);
  (*pub)->set_nds_com(true);
  (*pub)->start();
  goose_test::run_for(ctx, 10ms);
  REQUIRE(cap->frames.size() == 1);
  auto m = goose::decode(cap->frames[0]);
  REQUIRE(m);
  CHECK_FALSE(m->frame.vlan);
  CHECK(m->frame.source == goose_test::mac_b);
  CHECK(m->frame.simulation());
  CHECK(m->pdu.simulation);
  CHECK(m->pdu.nds_com);
  CHECK(m->pdu.time_allowed_to_live == 3000);
  CHECK(m->pdu.num_dat_set_entries == 0);
  CHECK_FALSE(m->pdu.go_id);
}
