#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <variant>

#include "openiec61850/iso/presentation/connection.hpp"

using openiec61850::byte_buffer;
using openiec61850::byte_view;
using openiec61850::errc;
namespace ps = openiec61850::iso::presentation;
namespace ss = openiec61850::iso::session;

namespace {

bool same(byte_view a, byte_view b) { return std::equal(a.begin(), a.end(), b.begin(), b.end()); }

const byte_buffer selector{0x00, 0x00, 0x00, 0x01};
const byte_buffer aarq{0x60, 0x03, 0x80, 0x01, 0x00};
const byte_buffer aare{0x61, 0x03, 0x80, 0x01, 0x00};
const byte_buffer mms_pdu{0xA0, 0x03, 0x02, 0x01, 0x01};

ps::pdv single(std::uint32_t id, byte_view data) {
  return {std::nullopt, id, ps::pdv_encoding::single_asn1_type, data, 0};
}

ps::connection_options initiator_options() {
  ps::connection_options o;
  o.session.local_selector = {0x00, 0x01};
  o.session.remote_selector = {0x00, 0x01};
  o.local_selector = selector;
  o.remote_selector = selector;
  o.contexts = {{1, ps::acse_abstract_syntax}, {3, ps::mms_abstract_syntax}};
  return o;
}

ps::connection_options responder_options() {
  ps::connection_options o;
  o.session.local_selector = {0x00, 0x01};
  o.local_selector = selector;
  o.supported_abstract_syntaxes = {ps::acse_abstract_syntax, ps::mms_abstract_syntax};
  return o;
}

template <typename T>
T deliver(ps::connection& c, const byte_buffer& tsdu, byte_buffer& out) {
  auto r = c.on_tsdu(tsdu, out);
  REQUIRE(r);
  REQUIRE(std::holds_alternative<T>(*r));
  return std::get<T>(*r);
}

struct pair_fixture {
  ps::connection initiator;
  ps::connection responder;

  explicit pair_fixture(ps::connection_options i = initiator_options(),
                        ps::connection_options r = responder_options())
      : initiator(ps::role::initiator, std::move(i)), responder(ps::role::responder, std::move(r)) {}

  void establish() {
    byte_buffer cn, ac, none;
    const auto request = single(1, aarq);
    REQUIRE(initiator.connect({&request, 1}, cn));
    CHECK(initiator.current_state() == ps::state::awaiting_accept);

    const auto ind = deliver<ps::connect_indication>(responder, cn, none);
    CHECK(none.empty());
    CHECK(same(ind.calling_selector, selector));
    CHECK(same(ind.called_selector, selector));
    REQUIRE(ind.contexts.size() == 2);
    CHECK(ind.contexts[0].accepted);
    CHECK(ind.contexts[1].accepted);
    REQUIRE(ind.user_data.size() == 1);
    CHECK(ind.user_data[0].context_id == 1);
    CHECK(same(ind.user_data[0].data, aarq));

    const auto response = single(1, aare);
    REQUIRE(responder.accept({&response, 1}, ac));
    CHECK(responder.current_state() == ps::state::data_transfer);
    const auto conf = deliver<ps::connect_confirm>(initiator, ac, none);
    CHECK(none.empty());
    CHECK(same(conf.responding_selector, selector));
    REQUIRE(conf.contexts.size() == 2);
    CHECK(conf.contexts[1].accepted);
    REQUIRE(conf.user_data.size() == 1);
    CHECK(same(conf.user_data[0].data, aare));
    CHECK(initiator.current_state() == ps::state::data_transfer);
    CHECK(initiator.is_accepted(3));
    CHECK_FALSE(initiator.is_accepted(5));
  }
};

}  // namespace

TEST_CASE("connection, data transfer and orderly release over two sessions", "[presentation]") {
  pair_fixture p;
  p.establish();

  byte_buffer tsdu, none;
  REQUIRE(p.initiator.send_data(3, mms_pdu, tsdu));
  // GT + DT, then the TD-PPDU.
  CHECK(tsdu == byte_buffer{0x01, 0x00, 0x01, 0x00, 0x61, 0x0C, 0x30, 0x0A, 0x02, 0x01, 0x03,
                            0xA0, 0x05, 0xA0, 0x03, 0x02, 0x01, 0x01});
  auto data = deliver<ps::data_indication>(p.responder, tsdu, none);
  REQUIRE(data.user_data.size() == 1);
  CHECK(data.user_data[0].context_id == 3);
  CHECK(same(data.user_data[0].data, mms_pdu));
  CHECK(data.user_data[0].data.data() == tsdu.data() + tsdu.size() - mms_pdu.size());

  tsdu.clear();
  const ps::pdv two[] = {single(3, mms_pdu), single(1, aarq)};
  REQUIRE(p.responder.send_data(two, tsdu));
  data = deliver<ps::data_indication>(p.initiator, tsdu, none);
  REQUIRE(data.user_data.size() == 2);
  CHECK(same(data.user_data[1].data, aarq));

  const byte_buffer rlrq{0x62, 0x00}, rlre{0x63, 0x00};
  const auto rq = single(1, rlrq);
  byte_buffer fn, dn;
  REQUIRE(p.initiator.release({&rq, 1}, fn));
  CHECK(p.initiator.current_state() == ps::state::awaiting_disconnect);
  const auto rel = deliver<ps::release_indication>(p.responder, fn, none);
  CHECK_FALSE(rel.collision);
  REQUIRE(rel.user_data.size() == 1);
  CHECK(same(rel.user_data[0].data, rlrq));

  const auto re = single(1, rlre);
  REQUIRE(p.responder.release_response({&re, 1}, dn));
  CHECK(p.responder.current_state() == ps::state::closed);
  const auto conf = deliver<ps::release_confirm>(p.initiator, dn, none);
  REQUIRE(conf.user_data.size() == 1);
  CHECK(same(conf.user_data[0].data, rlre));
  CHECK(p.initiator.current_state() == ps::state::closed);
  CHECK(none.empty());
  CHECK(p.initiator.on_transport_disconnect());
}

TEST_CASE("release without user data", "[presentation]") {
  pair_fixture p;
  p.establish();
  byte_buffer fn, dn, none;
  REQUIRE(p.initiator.release({}, fn));
  CHECK(deliver<ps::release_indication>(p.responder, fn, none).user_data.empty());
  REQUIRE(p.responder.release_response({}, dn));
  CHECK(deliver<ps::release_confirm>(p.initiator, dn, none).user_data.empty());
}

TEST_CASE("the responder rejects unsupported contexts", "[presentation]") {
  auto ro = responder_options();
  ro.supported_abstract_syntaxes = {ps::mms_abstract_syntax};
  auto io = initiator_options();
  io.contexts.push_back({5, openiec61850::ber::oid{1, 2, 3}});
  pair_fixture p{io, ro};

  byte_buffer cn, ac, none;
  const auto request = single(1, aarq);
  REQUIRE(p.initiator.connect({&request, 1}, cn));
  const auto ind = deliver<ps::connect_indication>(p.responder, cn, none);
  REQUIRE(ind.contexts.size() == 3);
  CHECK_FALSE(ind.contexts[0].accepted);
  CHECK(ind.contexts[0].reason == ps::context_reason::abstract_syntax_not_supported);
  CHECK(ind.contexts[1].accepted);
  CHECK_FALSE(ind.contexts[2].accepted);
  // User data may only use accepted contexts.
  const auto on_acse = single(1, aare);
  CHECK(p.responder.accept({&on_acse, 1}, ac).error() == errc::invalid_state);
  CHECK(ac.empty());
  REQUIRE(p.responder.accept({}, ac));

  const auto conf = deliver<ps::connect_confirm>(p.initiator, ac, none);
  CHECK_FALSE(conf.contexts[0].accepted);
  CHECK(conf.contexts[0].reason == ps::context_reason::abstract_syntax_not_supported);
  CHECK(conf.contexts[1].accepted);
  CHECK(p.initiator.is_accepted(3));
  CHECK_FALSE(p.initiator.is_accepted(1));

  byte_buffer tsdu;
  CHECK(p.initiator.send_data(1, mms_pdu, tsdu).error() == errc::invalid_state);
  CHECK(p.initiator.send_data(7, mms_pdu, tsdu).error() == errc::invalid_state);
  CHECK(tsdu.empty());
  REQUIRE(p.initiator.send_data(3, mms_pdu, tsdu));
}

TEST_CASE("a context without BER is rejected", "[presentation]") {
  ps::connection responder{ps::role::responder, responder_options()};
  ps::connect_ppdu cp;
  cp.contexts.push_back({1, ps::acse_abstract_syntax, {openiec61850::ber::oid{1, 2, 3}}});
  byte_buffer ppdu, cn, none;
  REQUIRE(ps::encode(cp, ppdu));
  ss::connection peer{ss::role::initiator, {}};
  REQUIRE(peer.connect(ppdu, cn));
  const auto ind = deliver<ps::connect_indication>(responder, cn, none);
  REQUIRE(ind.contexts.size() == 1);
  CHECK(ind.contexts[0].reason == ps::context_reason::proposed_transfer_syntaxes_not_supported);
}

TEST_CASE("the responder's user refuses the connection", "[presentation]") {
  pair_fixture p;
  byte_buffer cn, rf, none;
  const auto request = single(1, aarq);
  REQUIRE(p.initiator.connect({&request, 1}, cn));
  (void)deliver<ps::connect_indication>(p.responder, cn, none);
  const auto reject = single(1, aare);
  REQUIRE(p.responder.refuse({&reject, 1}, rf));
  CHECK(p.responder.current_state() == ps::state::closed);
  const auto refused = deliver<ps::connect_refused>(p.initiator, rf, none);
  CHECK(refused.session_reason == ss::refuse_reason::rejected_by_user);
  CHECK_FALSE(refused.provider_reason);
  REQUIRE(refused.user_data.size() == 1);
  CHECK(same(refused.user_data[0].data, aare));
  CHECK(p.initiator.current_state() == ps::state::closed);
}

TEST_CASE("the responder refuses an unacceptable CP-type", "[presentation]") {
  ps::connection responder{ps::role::responder, responder_options()};
  ss::connection peer{ss::role::initiator, {}};
  ps::connect_ppdu cp;
  std::uint8_t expected = 0;
  std::error_code error;

  SECTION("even context identifier") {
    cp.contexts.push_back({2, ps::acse_abstract_syntax, {ps::ber_transfer_syntax}});
    expected = ps::provider_reason::not_specified;
    error = errc::protocol_violation;
  }
  SECTION("duplicate context identifier") {
    cp.contexts.push_back({1, ps::acse_abstract_syntax, {ps::ber_transfer_syntax}});
    cp.contexts.push_back({1, ps::mms_abstract_syntax, {ps::ber_transfer_syntax}});
    expected = ps::provider_reason::not_specified;
    error = errc::protocol_violation;
  }
  SECTION("user data on an undefined context") {
    cp.contexts.push_back({1, ps::acse_abstract_syntax, {ps::ber_transfer_syntax}});
    cp.user_data.push_back(single(3, aarq));
    expected = ps::provider_reason::user_data_not_readable;
    error = errc::protocol_violation;
  }
  SECTION("unsupported protocol version") {
    cp.protocol_version = 0x02;
    expected = ps::provider_reason::protocol_version_not_supported;
    error = errc::unsupported;
  }
  SECTION("default context") {
    cp.default_context = ps::default_context_name{ps::mms_abstract_syntax, ps::ber_transfer_syntax};
    expected = ps::provider_reason::default_context_not_supported;
    error = errc::unsupported;
  }

  byte_buffer ppdu, cn, rf;
  REQUIRE(ps::encode(cp, ppdu));
  REQUIRE(peer.connect(ppdu, cn));
  const auto failed = deliver<ps::provider_abort>(responder, cn, rf);
  CHECK(failed.error == error);
  CHECK(responder.current_state() == ps::state::closed);

  auto ev = peer.on_tsdu(rf, ppdu);
  REQUIRE(ev);
  REQUIRE(std::holds_alternative<ss::connect_refused>(*ev));
  const auto& refused = std::get<ss::connect_refused>(*ev);
  CHECK(refused.reason == ss::refuse_reason::rejected_by_user);
  auto cpr = ps::decode_refuse(refused.user_data);
  REQUIRE(cpr);
  CHECK(cpr->provider_reason == expected);
}

TEST_CASE("the responder refuses an undecodable or x410-mode CP", "[presentation]") {
  ps::connection responder{ps::role::responder, responder_options()};
  ss::connection peer{ss::role::initiator, {}};
  byte_buffer cn, rf;
  const byte_buffer x410{0x31, 0x05, 0xA0, 0x03, 0x80, 0x01, 0x00};
  REQUIRE(peer.connect(x410, cn));
  CHECK(deliver<ps::provider_abort>(responder, cn, rf).error == errc::unsupported);
  CHECK_FALSE(rf.empty());
  CHECK(responder.on_tsdu(cn, rf).error() == errc::invalid_state);
}

TEST_CASE("the initiator refused with a provider reason", "[presentation]") {
  ps::connection initiator{ps::role::initiator, initiator_options()};
  ss::connection peer{ss::role::responder, {}};
  byte_buffer cn, rf, none;
  REQUIRE(initiator.connect({}, cn));
  REQUIRE(peer.on_tsdu(cn, none));
  ps::refuse_ppdu cpr;
  cpr.provider_reason = ps::provider_reason::temporary_congestion;
  byte_buffer ppdu;
  REQUIRE(ps::encode(cpr, ppdu));
  REQUIRE(peer.refuse(ss::refuse_reason::rejected_by_user, ppdu, rf));
  const auto refused = deliver<ps::connect_refused>(initiator, rf, none);
  CHECK(refused.provider_reason == ps::provider_reason::temporary_congestion);
}

TEST_CASE("the initiator aborts on a bad CPA", "[presentation]") {
  ps::connection initiator{ps::role::initiator, initiator_options()};
  ss::connection peer{ss::role::responder, {}};
  byte_buffer cn, ac, ab, none;
  REQUIRE(initiator.connect({}, cn));
  REQUIRE(peer.on_tsdu(cn, none));

  ps::accept_ppdu cpa;
  cpa.results.push_back({ps::context_result_code::acceptance, ps::ber_transfer_syntax, std::nullopt});
  std::error_code expected = errc::protocol_violation;
  SECTION("too few results") {}
  SECTION("unproposed transfer syntax") {
    cpa.results.push_back(
        {ps::context_result_code::acceptance, openiec61850::ber::oid{1, 2, 3}, std::nullopt});
  }
  SECTION("user data on a rejected context") {
    cpa.results.push_back({ps::context_result_code::provider_rejection, std::nullopt, std::nullopt});
    cpa.user_data.push_back(single(3, aare));
  }
  SECTION("presentation requirements not proposed") {
    cpa.results.push_back({ps::context_result_code::acceptance, std::nullopt, std::nullopt});
    cpa.presentation_requirements = ps::requirements::context_management;
  }
  byte_buffer ppdu;
  REQUIRE(ps::encode(cpa, ppdu));
  REQUIRE(peer.accept(ppdu, ac));
  CHECK(deliver<ps::provider_abort>(initiator, ac, ab).error == expected);
  CHECK(initiator.current_state() == ps::state::closed);

  // The peer gets an AB carrying an ARP-PPDU.
  auto ev = peer.on_tsdu(ab, none);
  REQUIRE(ev);
  REQUIRE(std::holds_alternative<ss::abort_indication>(*ev));
  auto arp = ps::decode_abort(std::get<ss::abort_indication>(*ev).user_data);
  REQUIRE(arp);
  REQUIRE(std::holds_alternative<ps::provider_abort_ppdu>(*arp));
  CHECK(std::get<ps::provider_abort_ppdu>(*arp).event == ps::event_id::cpa_ppdu);
}

TEST_CASE("a TD on an unaccepted context is a provider abort", "[presentation]") {
  pair_fixture p;
  p.establish();
  byte_buffer td, ab, none;
  ps::pdv bad = single(5, mms_pdu);
  byte_buffer ppdu;
  REQUIRE(ps::encode_user_data({&bad, 1}, ppdu));
  ss::encode_data_tsdu(ppdu, td);
  CHECK(deliver<ps::provider_abort>(p.responder, td, ab).error == errc::protocol_violation);
  CHECK(p.responder.current_state() == ps::state::closed);

  const auto ind = deliver<ps::provider_abort_indication>(p.initiator, ab, none);
  CHECK(ind.reason == ps::abort_reason::invalid_ppdu_parameter_value);
  CHECK(p.initiator.current_state() == ps::state::closed);
}

TEST_CASE("malformed TDs are provider aborts", "[presentation]") {
  pair_fixture p;
  p.establish();
  byte_buffer td, ab, none;
  SECTION("empty") { ss::encode_data_tsdu({}, td); }
  SECTION("truncated") {
    const byte_buffer ppdu{0x61, 0x0C, 0x30, 0x0A, 0x02, 0x01, 0x03};
    ss::encode_data_tsdu(ppdu, td);
  }
  SECTION("simply-encoded") {
    const byte_buffer ppdu{0x40, 0x01, 0x00};
    ss::encode_data_tsdu(ppdu, td);
  }
  const auto failed = deliver<ps::provider_abort>(p.responder, td, ab);
  CHECK(failed.error);
  const auto ind = deliver<ps::provider_abort_indication>(p.initiator, ab, none);
  CHECK(ind.reason);
}

TEST_CASE("user abort carries an ARU-PPDU", "[presentation]") {
  pair_fixture p;
  p.establish();
  const byte_buffer abrt{0x64, 0x03, 0x80, 0x01, 0x01};
  const auto a = single(1, abrt);
  byte_buffer ab, none;
  REQUIRE(p.initiator.abort({&a, 1}, ab));
  CHECK(p.initiator.current_state() == ps::state::closed);
  const auto ind = deliver<ps::user_abort_indication>(p.responder, ab, none);
  REQUIRE(ind.user_data.size() == 1);
  CHECK(same(ind.user_data[0].data, abrt));
  CHECK(p.responder.current_state() == ps::state::closed);
  CHECK(p.initiator.abort({}, ab).error() == errc::invalid_state);
}

TEST_CASE("abort while awaiting the CPA", "[presentation]") {
  pair_fixture p;
  byte_buffer cn, ab, none;
  REQUIRE(p.initiator.connect({}, cn));
  (void)deliver<ps::connect_indication>(p.responder, cn, none);
  REQUIRE(p.initiator.abort({}, ab));
  CHECK(deliver<ps::user_abort_indication>(p.responder, ab, none).user_data.empty());
}

TEST_CASE("local requests are checked against the state and the context set", "[presentation]") {
  byte_buffer out;
  ps::connection responder{ps::role::responder, responder_options()};
  CHECK(responder.connect({}, out).error() == errc::invalid_state);
  CHECK(responder.accept({}, out).error() == errc::invalid_state);
  CHECK(responder.send_data(1, mms_pdu, out).error() == errc::invalid_state);
  CHECK(responder.release({}, out).error() == errc::invalid_state);
  CHECK(responder.abort({}, out).error() == errc::invalid_state);

  auto io = initiator_options();
  io.contexts.push_back({4, ps::mms_abstract_syntax});
  ps::connection even{ps::role::initiator, io};
  CHECK(even.connect({}, out).error() == errc::invalid_state);

  ps::connection initiator{ps::role::initiator, initiator_options()};
  const auto stray = single(9, aarq);
  CHECK(initiator.connect({&stray, 1}, out).error() == errc::invalid_state);
  CHECK(out.empty());
  CHECK(initiator.contexts().empty());

  pair_fixture p;
  p.establish();
  CHECK(p.initiator.send_data({}, out).error() == errc::invalid_state);
  CHECK(p.initiator.release_response({}, out).error() == errc::invalid_state);
  CHECK(out.empty());
}
