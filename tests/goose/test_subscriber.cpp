#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <string>
#include <vector>

#include "goose_test_util.hpp"
#include "openiec61850/goose/pdu.hpp"
#include "openiec61850/goose/publisher.hpp"
#include "openiec61850/goose/receiver.hpp"
#include "openiec61850/goose/subscriber.hpp"

namespace goose = openiec61850::goose;
namespace mms = openiec61850::mms;
using namespace std::chrono_literals;
using goose::sequence_status;
using openiec61850::byte_buffer;
using openiec61850::errc;

namespace {

using clock = std::chrono::steady_clock;

struct frame_spec {
  std::uint16_t app_id = 1;
  std::string gocb_ref = "LD/LLN0$GO$g";
  std::string dat_set = "LD/LLN0$DS";
  std::string go_id = "G";
  std::uint32_t st = 1;
  std::uint32_t sq = 0;
  std::uint32_t tal = 1000;
  std::uint32_t conf_rev = 1;
  bool simulation = false;
  bool nds_com = false;
  std::vector<mms::data> values{mms::data::boolean(true)};
};

byte_buffer make_frame(const frame_spec& s) {
  goose::frame_header h;
  h.destination = goose::goose_multicast_base;
  h.source = goose_test::mac_a;
  h.app_id = s.app_id;
  goose::pdu_fields f;
  f.gocb_ref = s.gocb_ref;
  f.dat_set = s.dat_set;
  f.go_id = s.go_id;
  f.st_num = s.st;
  f.sq_num = s.sq;
  f.time_allowed_to_live = s.tal;
  f.conf_rev = s.conf_rev;
  f.simulation = s.simulation;
  f.nds_com = s.nds_com;
  byte_buffer out;
  REQUIRE(goose::encode(h, f, s.values, out));
  return out;
}

}  // namespace

TEST_CASE("Sequence tracker follows stNum and sqNum", "[goose]") {
  goose::sequence_tracker t;
  const auto t0 = clock::now();
  CHECK(t.on_message(5, 3, 100, t0).status == sequence_status::first);
  CHECK(t.on_message(5, 4, 100, t0).status == sequence_status::retransmission);
  auto gap = t.on_message(5, 7, 100, t0);
  CHECK(gap.status == sequence_status::sq_gap);
  CHECK(gap.lost == 2);
  CHECK(t.on_message(5, 7, 100, t0).status == sequence_status::duplicate);
  CHECK(t.on_message(5, 6, 100, t0).status == sequence_status::out_of_order);
  CHECK(t.on_message(6, 0, 100, t0).status == sequence_status::new_state);
  auto stg = t.on_message(9, 0, 100, t0);
  CHECK(stg.status == sequence_status::st_gap);
  CHECK(stg.lost == 2);
  CHECK(t.on_message(8, 1, 100, t0).status == sequence_status::out_of_order);
  CHECK(t.st_num() == 9);
  // Publisher restart.
  CHECK(t.on_message(1, 0, 100, t0).status == sequence_status::first);
  CHECK(t.st_num() == 1);

  // Counter wrap: 2^32-1 -> 1 (0 is skipped).
  goose::sequence_tracker w;
  CHECK(w.on_message(0xFFFFFFFF, 0xFFFFFFFF, 100, t0).status == sequence_status::first);
  CHECK(w.on_message(0xFFFFFFFF, 1, 100, t0).status == sequence_status::retransmission);
  CHECK(w.on_message(1, 0, 100, t0).status == sequence_status::new_state);
  CHECK(w.on_message(0xFFFFFFFF, 5, 100, t0).status == sequence_status::out_of_order);

  // TAL supervision.
  goose::sequence_tracker tal;
  tal.margin = 5ms;
  CHECK_FALSE(tal.expired(t0));
  (void)tal.on_message(1, 0, 20, t0);
  CHECK_FALSE(tal.expired(t0 + 25ms));
  CHECK(tal.expired(t0 + 26ms));
  (void)tal.on_message(1, 1, 20, t0 + 20ms);  // refreshed
  CHECK_FALSE(tal.expired(t0 + 40ms));
  tal.reset();
  CHECK_FALSE(tal.has_state());
  CHECK_FALSE(tal.deadline());
}

TEST_CASE("Subscriber filters, checks and supervises GOOSE messages", "[goose]") {
  asio::io_context ctx;
  auto net = goose::loopback_network::create();
  auto tx = net->attach(ctx.get_executor(), goose_test::mac_a);
  auto rx = net->attach(ctx.get_executor(), goose_test::mac_b);
  auto recv = goose::receiver::create(rx);
  recv->start();

  goose::subscriber_config cfg;
  cfg.app_id = 1;
  cfg.gocb_ref = "LD/LLN0$GO$g";
  cfg.dat_set = "LD/LLN0$DS";
  cfg.go_id = "G";
  cfg.conf_rev = 1;
  cfg.num_entries = 1;
  auto sub = recv->subscribe(cfg);
  goose_test::run_for(ctx, 1ms);

  auto next = [&] {
    auto e = goose_test::run(ctx, sub->next_event());
    REQUIRE(e);
    REQUIRE(*e);
    return std::move(**e);
  };

  frame_spec s;
  s.tal = 60;
  REQUIRE(tx->send(make_frame(s)));
  auto e = next();
  CHECK(e.kind == goose::event_kind::message);
  CHECK(e.msg.sequence.status == sequence_status::first);
  CHECK(e.msg.gocb_ref == "LD/LLN0$GO$g");
  CHECK(e.msg.go_id == "G");
  CHECK(e.msg.source == goose_test::mac_a);
  REQUIRE(e.msg.values.size() == 1);
  CHECK(*e.msg.values[0].as_boolean());

  // Other APPID, other gocbRef, simulation: filtered out.
  frame_spec other = s;
  other.app_id = 2;
  REQUIRE(tx->send(make_frame(other)));
  other = s;
  other.gocb_ref = "LD/LLN0$GO$x";
  REQUIRE(tx->send(make_frame(other)));
  other = s;
  other.simulation = true;
  REQUIRE(tx->send(make_frame(other)));
  // A lost retransmission.
  s.sq = 2;
  REQUIRE(tx->send(make_frame(s)));
  e = next();
  CHECK(e.msg.sequence.status == sequence_status::sq_gap);
  CHECK(e.msg.sequence.lost == 1);
  CHECK(sub->stats().simulated_ignored == 1);
  CHECK(recv->stats().unmatched == 2);

  // Configuration mismatches.
  s.sq = 3;
  s.conf_rev = 2;
  REQUIRE(tx->send(make_frame(s)));
  e = next();
  CHECK(e.kind == goose::event_kind::mismatch);
  CHECK(e.reason == goose::mismatch_reason::conf_rev);
  s.conf_rev = 1;
  s.sq = 4;
  s.values.push_back(mms::data::integer(1));
  REQUIRE(tx->send(make_frame(s)));
  e = next();
  CHECK(e.reason == goose::mismatch_reason::num_entries);
  s.values.pop_back();
  s.sq = 5;
  s.nds_com = true;
  REQUIRE(tx->send(make_frame(s)));
  e = next();
  CHECK(e.reason == goose::mismatch_reason::nds_com);
  s.nds_com = false;

  // New state, then silence: TAL (60 ms) expires.
  s.st = 2;
  s.sq = 0;
  s.values = {mms::data::boolean(false)};
  REQUIRE(tx->send(make_frame(s)));
  e = next();
  CHECK(e.kind == goose::event_kind::message);
  CHECK(e.msg.sequence.status == sequence_status::new_state);
  const auto before = clock::now();
  e = next();
  CHECK(e.kind == goose::event_kind::timeout);
  CHECK(clock::now() - before >= 50ms);
  CHECK(e.msg.st_num == 2);
  CHECK(e.msg.values.empty());
  CHECK(sub->stats().timeouts == 1);

  // After a timeout the next message is "first" again.
  s.sq = 1;
  REQUIRE(tx->send(make_frame(s)));
  e = next();
  CHECK(e.msg.sequence.status == sequence_status::first);

  // Malformed frames are counted.
  auto bad = make_frame(s);
  bad[22] = 0x62;  // [APPLICATION 2] instead of goosePdu
  REQUIRE(tx->send(bad));
  goose_test::run_for(ctx, 5ms);
  CHECK(recv->stats().malformed == 1);

  sub->close();
  auto closed = goose_test::run(ctx, sub->next_event());
  REQUIRE(closed);
  CHECK(closed->error() == errc::invalid_state);
  recv->stop();
  goose_test::run_for(ctx, 5ms);
}

TEST_CASE("Publisher to subscriber with loss injection and a handler", "[goose]") {
  asio::io_context ctx;
  auto net = goose::loopback_network::create();
  auto tx = net->attach(ctx.get_executor(), goose_test::mac_a);
  auto rx = net->attach(ctx.get_executor(), goose_test::mac_b);
  // Drop the third frame.
  int n = 0;
  net->set_filter([&n](openiec61850::byte_view, const goose::mac_address&) { return ++n != 3; });

  auto recv = goose::receiver::create(rx);
  recv->start();
  goose::subscriber_config cfg;
  cfg.gocb_ref = "LD/LLN0$GO$g";
  cfg.destination = goose::goose_multicast_base;
  auto sub = recv->subscribe(cfg);
  std::vector<goose::event> events;
  sub->set_handler([&events](const goose::event& e) { events.push_back(e); });
  goose_test::run_for(ctx, 1ms);

  goose::publisher_config pc;
  pc.gocb_ref = "LD/LLN0$GO$g";
  pc.dat_set = "LD/LLN0$DS";
  pc.min_time = 2ms;
  pc.max_time = 8ms;
  pc.tal_multiplier = 4;  // tolerates one lost fast retransmission (see publisher.hpp)
  auto pub = goose::publisher::create(tx, pc, {mms::data::integer(1)});
  REQUIRE(pub);
  (*pub)->start();
  goose_test::run_for(ctx, 40ms);
  REQUIRE((*pub)->publish({mms::data::integer(2)}));
  goose_test::run_for(ctx, 20ms);
  (*pub)->stop();
  goose_test::run_for(ctx, 5ms);

  REQUIRE(events.size() >= 6);
  CHECK(events[0].msg.sequence.status == sequence_status::first);
  CHECK(events[1].msg.sequence.status == sequence_status::retransmission);
  CHECK(events[2].msg.sequence.status == sequence_status::sq_gap);
  CHECK(events[2].msg.sequence.lost == 1);
  bool saw_new_state = false;
  for (const auto& e : events) {
    CHECK(e.kind == goose::event_kind::message);
    if (e.msg.sequence.status == sequence_status::new_state) {
      saw_new_state = true;
      CHECK(e.msg.st_num == 2);
      CHECK(*e.msg.values.at(0).as_int64() == 2);
    }
  }
  CHECK(saw_new_state);
  CHECK(sub->stats().lost == 1);
  recv->stop();
  goose_test::run_for(ctx, 5ms);
}

TEST_CASE("Event queue overflow drops the oldest events", "[goose]") {
  asio::io_context ctx;
  auto net = goose::loopback_network::create();
  auto tx = net->attach(ctx.get_executor(), goose_test::mac_a);
  auto rx = net->attach(ctx.get_executor(), goose_test::mac_b);
  auto recv = goose::receiver::create(rx);
  recv->start();
  goose::subscriber_config cfg;
  cfg.queue_capacity = 2;
  auto sub = recv->subscribe(cfg);
  goose_test::run_for(ctx, 1ms);
  frame_spec s;
  for (std::uint32_t i = 0; i < 5; ++i) {
    s.sq = i;
    REQUIRE(tx->send(make_frame(s)));
  }
  goose_test::run_for(ctx, 5ms);
  auto a = goose_test::run(ctx, sub->next_event());
  REQUIRE(a);
  REQUIRE(*a);
  CHECK((*a)->msg.sq_num == 3);
  CHECK((*a)->dropped_before == 3);
  CHECK(sub->stats().dropped == 3);
  recv->stop();
  goose_test::run_for(ctx, 5ms);
}
