#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <vector>

#include "goose_test_util.hpp"
#include "openiec61850/goose/receiver.hpp"
#include "openiec61850/goose/sv_publisher.hpp"
#include "openiec61850/goose/sv_subscriber.hpp"

namespace goose = openiec61850::goose;
namespace sv = openiec61850::sv;
using namespace std::chrono_literals;
using openiec61850::byte_buffer;
using openiec61850::errc;
using sv::continuity;

TEST_CASE("smpCnt continuity", "[sv]") {
  sv::smp_cnt_tracker t{4000};
  CHECK(t.on_sample(3998).status == continuity::first);
  CHECK(t.on_sample(3999).status == continuity::in_sequence);
  CHECK(t.on_sample(0).status == continuity::in_sequence);  // wrap
  auto g = t.on_sample(5);
  CHECK(g.status == continuity::gap);
  CHECK(g.lost == 4);
  CHECK(t.on_sample(5).status == continuity::duplicate);
  CHECK(t.on_sample(3).status == continuity::out_of_order);
  auto wrap_gap = sv::smp_cnt_tracker{4000};
  (void)wrap_gap.on_sample(3990);
  auto wg = wrap_gap.on_sample(2);
  CHECK(wg.status == continuity::gap);
  CHECK(wg.lost == 11);
  CHECK(t.on_sample(4500).status == continuity::out_of_order);  // beyond the range

  // Unknown range: 65536, and a drop to 0 is a wrap.
  sv::smp_cnt_tracker u;
  (void)u.on_sample(4799);
  CHECK(u.on_sample(0).status == continuity::in_sequence);
  CHECK(u.on_sample(65535).status == continuity::out_of_order);
  (void)u.on_sample(1);
  CHECK(u.on_sample(2).status == continuity::in_sequence);
}

TEST_CASE("SV publisher frames ASDUs and wraps smpCnt", "[sv]") {
  asio::io_context ctx;
  auto net = goose::loopback_network::create();
  auto tx = net->attach(ctx.get_executor(), goose_test::mac_a);
  auto rx = net->attach(ctx.get_executor(), goose_test::mac_b);
  auto cap = goose_test::start_capture(ctx, rx);

  CHECK(sv::publisher::create(tx, {}).error() == errc::invalid_state);
  sv::publisher_config c;
  c.sv_id = "MU01";
  c.dat_set = "MU/LLN0$PhsMeas1";
  c.smp_cnt_wrap = 5;
  c.asdus_per_frame = 2;
  c.smp_rate = 80;
  c.refresh_time = true;
  c.smp_synch = sv::smp_synch::global;
  auto pub = sv::publisher::create(tx, c);
  REQUIRE(pub);
  sv::le::samples s;
  for (int i = 0; i < 7; ++i) {
    s.set_current(0, i);
    auto cnt = (*pub)->push(s);
    REQUIRE(cnt);
    CHECK(*cnt == i % 5);
  }
  goose_test::run_for(ctx, 5ms);
  REQUIRE(cap->frames.size() == 3);  // the 7th sample waits for its pair
  std::vector<std::uint16_t> counts;
  for (const auto& f : cap->frames) {
    auto m = sv::decode(f);
    REQUIRE(m);
    CHECK(m->frame.ether_type == goose::ethertype_sv);
    CHECK(m->frame.app_id == 0x4000);
    CHECK(m->frame.destination == goose::sv_multicast_base);
    CHECK(m->pdu.no_asdu == 2);
    for (const auto& a : m->pdu.asdus) {
      CHECK(a.sv_id == "MU01");
      CHECK(a.dat_set == "MU/LLN0$PhsMeas1");
      CHECK(a.smp_rate == 80);
      CHECK(a.refr_tm);
      CHECK(a.smp_synch == 2);
      CHECK_FALSE(a.smp_mod);
      auto v = sv::le::decode(a.seq_data);
      REQUIRE(v);
      CHECK(v->channels[0].value == 1000 * static_cast<int>(counts.size()));
      counts.push_back(a.smp_cnt);
    }
  }
  CHECK(counts == std::vector<std::uint16_t>{0, 1, 2, 3, 4, 0});
  CHECK((*pub)->stats().frames_sent == 3);
  CHECK((*pub)->stats().samples == 7);
}

TEST_CASE("SV subscriber detects lost samples", "[sv]") {
  asio::io_context ctx;
  auto net = goose::loopback_network::create();
  auto tx = net->attach(ctx.get_executor(), goose_test::mac_a);
  auto rx = net->attach(ctx.get_executor(), goose_test::mac_b);
  int n = 0;
  net->set_filter([&n](openiec61850::byte_view, const goose::mac_address&) { return ++n != 4; });
  auto recv = goose::receiver::create(rx);
  recv->start();
  sv::subscriber_config sc;
  sc.sv_id = "MU01";
  sc.smp_cnt_wrap = 4000;
  sc.conf_rev = 1;
  auto sub = recv->subscribe(sc);
  sv::subscriber_config other;
  other.sv_id = "MU02";
  auto sub2 = recv->subscribe(other);
  goose_test::run_for(ctx, 1ms);

  sv::publisher_config c;
  c.sv_id = "MU01";
  auto pub = sv::publisher::create(tx, c);
  REQUIRE(pub);
  for (int i = 0; i < 6; ++i) {
    sv::le::samples s;
    s.set_voltage(1, 230.0 * i);
    REQUIRE((*pub)->push(s));
  }
  goose_test::run_for(ctx, 5ms);

  std::vector<sv::sample_event> got;
  for (int i = 0; i < 5; ++i) {
    auto e = goose_test::run(ctx, sub->next_sample());
    REQUIRE(e);
    REQUIRE(*e);
    got.push_back(std::move(**e));
  }
  CHECK(got[0].status == continuity::first);
  CHECK(got[1].status == continuity::in_sequence);
  CHECK(got[2].status == continuity::in_sequence);
  CHECK(got[3].smp_cnt == 4);
  CHECK(got[3].status == continuity::gap);
  CHECK(got[3].lost == 1);
  CHECK_FALSE(got[3].conf_rev_mismatch);
  auto v = sv::le::decode(got[4].seq_data);
  REQUIRE(v);
  CHECK(v->channels[sv::le::vb].value == 115000);
  CHECK(sub->stats().lost == 1);
  CHECK(sub2->stats().samples == 0);

  // Low-latency handler.
  std::vector<std::uint16_t> seen;
  sub->set_handler([&seen](const sv::frame_view&, const sv::asdu_view& a,
                           const sv::smp_cnt_tracker::check& chk) {
    seen.push_back(a.smp_cnt);
    CHECK(chk.status == continuity::in_sequence);
  });
  goose_test::run_for(ctx, 1ms);
  REQUIRE((*pub)->push(sv::le::samples{}));
  goose_test::run_for(ctx, 5ms);
  CHECK(seen == std::vector<std::uint16_t>{6});
  recv->stop();
  goose_test::run_for(ctx, 5ms);
}

TEST_CASE("SV publisher driven by a timer", "[sv]") {
  asio::io_context ctx;
  auto net = goose::loopback_network::create();
  auto tx = net->attach(ctx.get_executor(), goose_test::mac_a);
  auto rx = net->attach(ctx.get_executor(), goose_test::mac_b);
  auto cap = goose_test::start_capture(ctx, rx);
  sv::publisher_config c;
  c.sv_id = "MU01";
  auto pub = sv::publisher::create(tx, c);
  REQUIRE(pub);
  CHECK((*pub)->start(0ns, [](std::uint16_t, byte_buffer&) {}).error() == errc::invalid_state);
  REQUIRE((*pub)->start(1ms, [](std::uint16_t cnt, byte_buffer& out) {
    sv::le::samples s;
    s.channels[0].value = cnt;
    const auto b = sv::le::encode(s);
    out.assign(b.begin(), b.end());
  }));
  goose_test::run_for(ctx, 50ms);
  (*pub)->stop();
  goose_test::run_for(ctx, 5ms);
  const auto sent = cap->frames.size();
  CHECK(sent >= 30);  // ~50, catching up when late
  CHECK(sent <= 60);
  std::uint16_t expected = 0;
  for (const auto& f : cap->frames) {
    auto m = sv::decode(f);
    REQUIRE(m);
    const auto a = *m->pdu.asdus.begin();
    CHECK(a.smp_cnt == expected);
    CHECK(sv::load_int32(a.seq_data, 0) == expected);
    ++expected;
  }
}
