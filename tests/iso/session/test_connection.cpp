#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <variant>

#include "openiec61850/iso/session/connection.hpp"

using openiec61850::byte_buffer;
using openiec61850::byte_view;
using openiec61850::errc;
namespace ss = openiec61850::iso::session;

namespace {

bool same(byte_view a, byte_view b) { return std::equal(a.begin(), a.end(), b.begin(), b.end()); }

ss::connection_options initiator_options(std::uint8_t versions = ss::version_1 | ss::version_2) {
  ss::connection_options o;
  o.local_selector = {0x00, 0x01};
  o.remote_selector = {0x00, 0x02};
  o.versions = versions;
  return o;
}

ss::connection_options responder_options(std::uint8_t versions = ss::version_1 | ss::version_2) {
  ss::connection_options o;
  o.local_selector = {0x00, 0x02};
  o.versions = versions;
  return o;
}

// Delivers `tsdu` to `c` and returns the event, expecting it to be of type T.
template <typename T>
T deliver(ss::connection& c, const byte_buffer& tsdu, byte_buffer& out) {
  auto r = c.on_tsdu(tsdu, out);
  REQUIRE(r);
  REQUIRE(std::holds_alternative<T>(*r));
  return std::get<T>(*r);
}

struct pair_fixture {
  ss::connection initiator{ss::role::initiator, initiator_options()};
  ss::connection responder{ss::role::responder, responder_options()};
  byte_buffer request{0xA0, 0x01};
  byte_buffer response{0xA1, 0x02};

  void establish() {
    byte_buffer cn, ac, none;
    REQUIRE(initiator.connect(request, cn));
    CHECK(initiator.current_state() == ss::state::awaiting_accept);
    const auto ind = deliver<ss::connect_indication>(responder, cn, none);
    CHECK(none.empty());
    CHECK(same(ind.calling_selector, byte_buffer{0x00, 0x01}));
    CHECK(same(ind.called_selector, byte_buffer{0x00, 0x02}));
    CHECK(ind.version == ss::version_2);
    CHECK(same(ind.user_data, request));
    CHECK(responder.current_state() == ss::state::awaiting_connect_response);

    REQUIRE(responder.accept(response, ac));
    const auto conf = deliver<ss::connect_confirm>(initiator, ac, none);
    CHECK(none.empty());
    CHECK(same(conf.responding_selector, byte_buffer{0x00, 0x02}));
    CHECK(conf.version == ss::version_2);
    CHECK(same(conf.user_data, response));
    CHECK(initiator.current_state() == ss::state::data_transfer);
    CHECK(responder.current_state() == ss::state::data_transfer);
    CHECK(initiator.version() == ss::version_2);
  }
};

}  // namespace

TEST_CASE("connect, data transfer and orderly release", "[session]") {
  pair_fixture p;
  p.establish();

  byte_buffer tsdu, none;
  const byte_buffer payload{1, 2, 3};
  REQUIRE(p.initiator.send_data(payload, tsdu));
  CHECK(tsdu == byte_buffer{0x01, 0x00, 0x01, 0x00, 1, 2, 3});
  CHECK(same(deliver<ss::data_indication>(p.responder, tsdu, none).user_data, payload));

  tsdu.clear();
  REQUIRE(p.responder.send_data(payload, tsdu));
  CHECK(same(deliver<ss::data_indication>(p.initiator, tsdu, none).user_data, payload));

  const byte_buffer rlrq{0x62}, rlre{0x63};
  byte_buffer fn, dn;
  REQUIRE(p.initiator.release(rlrq, fn));
  CHECK(fn == byte_buffer{0x09, 0x06, 0x11, 0x01, 0x01, 0xC1, 0x01, 0x62});
  CHECK(p.initiator.current_state() == ss::state::awaiting_disconnect);
  // No more local data after FN.
  CHECK(p.initiator.send_data(payload, tsdu).error() == errc::invalid_state);

  // The peer may still send data until it has seen FN.
  tsdu.clear();
  REQUIRE(p.responder.send_data(payload, tsdu));
  CHECK(same(deliver<ss::data_indication>(p.initiator, tsdu, none).user_data, payload));

  const auto rel = deliver<ss::release_indication>(p.responder, fn, none);
  CHECK_FALSE(rel.collision);
  CHECK(same(rel.user_data, rlrq));
  CHECK(p.responder.current_state() == ss::state::awaiting_release_response);
  CHECK(p.responder.send_data(payload, tsdu).error() == errc::invalid_state);

  REQUIRE(p.responder.release_response(rlre, dn));
  CHECK(dn == byte_buffer{0x0A, 0x03, 0xC1, 0x01, 0x63});
  CHECK(p.responder.current_state() == ss::state::closed);

  CHECK(same(deliver<ss::release_confirm>(p.initiator, dn, none).user_data, rlre));
  CHECK(p.initiator.current_state() == ss::state::closed);
  CHECK(none.empty());
  CHECK(p.initiator.on_transport_disconnect());
  CHECK(p.responder.on_transport_disconnect());
}

TEST_CASE("responder refuses the connection", "[session]") {
  pair_fixture p;
  byte_buffer cn, rf, none;
  REQUIRE(p.initiator.connect(p.request, cn));
  (void)deliver<ss::connect_indication>(p.responder, cn, none);
  const byte_buffer reason_data{0x7E};
  REQUIRE(p.responder.refuse(ss::refuse_reason::rejected_by_user, reason_data, rf));
  CHECK(p.responder.current_state() == ss::state::closed);
  const auto refused = deliver<ss::connect_refused>(p.initiator, rf, none);
  CHECK(refused.reason == ss::refuse_reason::rejected_by_user);
  CHECK(same(refused.user_data, reason_data));
  CHECK(p.initiator.current_state() == ss::state::closed);
}

TEST_CASE("version negotiation selects the highest common version", "[session]") {
  byte_buffer cn, ac, none;

  SECTION("initiator proposes version 1 only") {
    ss::connection init{ss::role::initiator, initiator_options(ss::version_1)};
    ss::connection resp{ss::role::responder, responder_options()};
    REQUIRE(init.connect({}, cn));
    CHECK(deliver<ss::connect_indication>(resp, cn, none).version == ss::version_1);
    REQUIRE(resp.accept({}, ac));
    CHECK(deliver<ss::connect_confirm>(init, ac, none).version == ss::version_1);
  }

  SECTION("no common version: the responder refuses") {
    ss::connection init{ss::role::initiator, initiator_options(ss::version_1)};
    ss::connection resp{ss::role::responder, responder_options(ss::version_2)};
    REQUIRE(init.connect({}, cn));
    byte_buffer rf;
    const auto failed = deliver<ss::provider_abort>(resp, cn, rf);
    CHECK(failed.error == errc::unsupported);
    CHECK(resp.current_state() == ss::state::closed);
    const auto refused = deliver<ss::connect_refused>(init, rf, none);
    CHECK(refused.reason == ss::refuse_reason::version_not_supported);
  }
}

TEST_CASE("responder refuses a proposal without duplex", "[session]") {
  ss::connection resp{ss::role::responder, responder_options()};
  // CN with version 2 and requirements = half-duplex.
  const byte_buffer cn{0x0D, 0x0C, 0x05, 0x06, 0x13, 0x01, 0x00, 0x16,
                       0x01, 0x02, 0x14, 0x02, 0x00, 0x01};
  byte_buffer out;
  CHECK(deliver<ss::provider_abort>(resp, cn, out).error == errc::unsupported);
  CHECK(out == byte_buffer{0x0C, 0x06, 0x11, 0x01, 0x01, 0x32, 0x01, 0x86});
}

TEST_CASE("initiator aborts on an invalid AC", "[session]") {
  ss::connection init{ss::role::initiator, initiator_options()};
  byte_buffer cn, out;
  REQUIRE(init.connect({}, cn));

  SECTION("functional units not proposed") {
    // AC selecting half-duplex.
    const byte_buffer ac{0x0E, 0x0C, 0x05, 0x06, 0x13, 0x01, 0x00, 0x16,
                         0x01, 0x02, 0x14, 0x02, 0x00, 0x01};
    CHECK(deliver<ss::provider_abort>(init, ac, out).error == errc::protocol_violation);
    CHECK(out == byte_buffer{0x19, 0x03, 0x11, 0x01, 0x05});
  }
  SECTION("more than one version selected") {
    const byte_buffer ac{0x0E, 0x0C, 0x05, 0x06, 0x13, 0x01, 0x00, 0x16,
                         0x01, 0x03, 0x14, 0x02, 0x00, 0x02};
    CHECK(deliver<ss::provider_abort>(init, ac, out).error == errc::protocol_violation);
  }
  SECTION("AC without requirements implies the default set") {
    const byte_buffer ac{0x0E, 0x08, 0x05, 0x06, 0x13, 0x01, 0x00, 0x16, 0x01, 0x02};
    CHECK(deliver<ss::provider_abort>(init, ac, out).error == errc::protocol_violation);
  }
  CHECK(init.current_state() == ss::state::closed);
}

TEST_CASE("user abort", "[session]") {
  pair_fixture p;
  p.establish();
  byte_buffer ab, out;
  const byte_buffer abrt{0x64};
  REQUIRE(p.initiator.abort(abrt, ab));
  CHECK(ab == byte_buffer{0x19, 0x06, 0x11, 0x01, 0x03, 0xC1, 0x01, 0x64});
  CHECK(p.initiator.current_state() == ss::state::closed);
  const auto ind = deliver<ss::abort_indication>(p.responder, ab, out);
  CHECK(ind.transport_disconnect == 0x03);
  CHECK(same(ind.user_data, abrt));
  CHECK(out.empty());  // transport released: no AA
  CHECK(p.responder.current_state() == ss::state::closed);
}

TEST_CASE("AB keeping the transport is answered with AA", "[session]") {
  pair_fixture p;
  p.establish();
  byte_buffer out;
  (void)deliver<ss::abort_indication>(p.initiator, byte_buffer{0x19, 0x03, 0x11, 0x01, 0x02}, out);
  CHECK(out == byte_buffer{0x1A, 0x00});
}

TEST_CASE("AB is accepted while awaiting AC", "[session]") {
  ss::connection init{ss::role::initiator, initiator_options()};
  byte_buffer cn, out;
  REQUIRE(init.connect({}, cn));
  (void)deliver<ss::abort_indication>(init, byte_buffer{0x19, 0x03, 0x11, 0x01, 0x03}, out);
  CHECK(init.current_state() == ss::state::closed);
}

TEST_CASE("release collision", "[session]") {
  pair_fixture p;
  p.establish();
  byte_buffer fn_i, fn_r, dn_i, dn_r, none;
  REQUIRE(p.initiator.release({}, fn_i));
  REQUIRE(p.responder.release({}, fn_r));

  CHECK(deliver<ss::release_indication>(p.initiator, fn_r, none).collision);
  CHECK(deliver<ss::release_indication>(p.responder, fn_i, none).collision);

  REQUIRE(p.initiator.release_response({}, dn_i));
  CHECK(p.initiator.current_state() == ss::state::awaiting_disconnect);

  // The responder sees the initiator's DN before answering.
  (void)deliver<ss::release_confirm>(p.responder, dn_i, none);
  CHECK(p.responder.current_state() == ss::state::awaiting_release_response);
  REQUIRE(p.responder.release_response({}, dn_r));
  CHECK(p.responder.current_state() == ss::state::closed);

  (void)deliver<ss::release_confirm>(p.initiator, dn_r, none);
  CHECK(p.initiator.current_state() == ss::state::closed);
  CHECK(none.empty());
}

TEST_CASE("protocol violations abort the session", "[session]") {
  pair_fixture p;
  p.establish();
  byte_buffer out;

  SECTION("malformed TSDU") {
    CHECK(deliver<ss::provider_abort>(p.responder, byte_buffer{0x01, 0x00, 0x01, 0x09}, out).error ==
          errc::length_overflow);
    CHECK(out == byte_buffer{0x19, 0x03, 0x11, 0x01, 0x05});
  }
  SECTION("unknown SI") {
    CHECK(deliver<ss::provider_abort>(p.responder, byte_buffer{0x63, 0x00}, out).error ==
          errc::malformed_encoding);
  }
  SECTION("CN during data transfer") {
    CHECK(deliver<ss::provider_abort>(p.responder, byte_buffer{0x0D, 0x00}, out).error ==
          errc::protocol_violation);
  }
  SECTION("DN without FN") {
    CHECK(deliver<ss::provider_abort>(p.initiator, byte_buffer{0x0A, 0x00}, out).error ==
          errc::protocol_violation);
  }
  SECTION("NF without negotiated release") {
    byte_buffer fn;
    REQUIRE(p.initiator.release({}, fn));
    CHECK(deliver<ss::provider_abort>(p.initiator, byte_buffer{0x08, 0x00}, out).error ==
          errc::protocol_violation);
  }
  SECTION("segmented DT") {
    const byte_buffer dt{0x01, 0x00, 0x01, 0x03, 0x19, 0x01, 0x01, 0xAA};
    CHECK(deliver<ss::provider_abort>(p.responder, dt, out).error == errc::unsupported);
    CHECK(out == byte_buffer{0x19, 0x03, 0x11, 0x01, 0x11});
  }
  SECTION("GT carrying tokens") {
    CHECK(deliver<ss::provider_abort>(p.responder, byte_buffer{0x01, 0x03, 0x10, 0x01, 0x01}, out)
              .error == errc::protocol_violation);
  }
  CHECK((p.initiator.current_state() == ss::state::closed ||
         p.responder.current_state() == ss::state::closed));
}

TEST_CASE("empty GT during data transfer is ignored", "[session]") {
  pair_fixture p;
  p.establish();
  byte_buffer out;
  (void)deliver<ss::no_event>(p.responder, byte_buffer{0x01, 0x00}, out);
  CHECK(out.empty());
  CHECK(p.responder.current_state() == ss::state::data_transfer);
}

TEST_CASE("wrong-state inputs", "[session]") {
  byte_buffer out;
  const byte_buffer data_tsdu{0x01, 0x00, 0x01, 0x00, 0xAA};

  SECTION("responder receives data before CN") {
    ss::connection resp{ss::role::responder, responder_options()};
    CHECK(deliver<ss::provider_abort>(resp, data_tsdu, out).error == errc::protocol_violation);
    CHECK(out.empty());  // no session connection: nothing to abort
  }
  SECTION("initiator receives CN") {
    ss::connection init{ss::role::initiator, initiator_options()};
    CHECK(deliver<ss::provider_abort>(init, byte_buffer{0x0D, 0x00}, out).error ==
          errc::protocol_violation);
  }
  SECTION("initiator receives data while awaiting AC") {
    ss::connection init{ss::role::initiator, initiator_options()};
    byte_buffer cn;
    REQUIRE(init.connect({}, cn));
    CHECK(deliver<ss::provider_abort>(init, data_tsdu, out).error == errc::protocol_violation);
    CHECK(out == byte_buffer{0x19, 0x03, 0x11, 0x01, 0x05});
  }
  SECTION("local requests in the wrong state") {
    ss::connection init{ss::role::initiator, initiator_options()};
    ss::connection resp{ss::role::responder, responder_options()};
    CHECK(init.send_data({}, out).error() == errc::invalid_state);
    CHECK(init.release({}, out).error() == errc::invalid_state);
    CHECK(init.abort({}, out).error() == errc::invalid_state);
    CHECK(init.accept({}, out).error() == errc::invalid_state);
    CHECK(resp.connect({}, out).error() == errc::invalid_state);
    CHECK(resp.release_response({}, out).error() == errc::invalid_state);
    CHECK(out.empty());
    REQUIRE(init.connect({}, out));
    CHECK(init.connect({}, out).error() == errc::invalid_state);
  }
  SECTION("TSDU after close") {
    pair_fixture p;
    p.establish();
    REQUIRE(p.initiator.abort({}, out));
    CHECK(p.initiator.on_tsdu(data_tsdu, out).error() == errc::invalid_state);
  }
}

TEST_CASE("unexpected transport disconnect", "[session]") {
  pair_fixture p;
  p.establish();
  CHECK_FALSE(p.initiator.on_transport_disconnect());
  CHECK(p.initiator.current_state() == ss::state::closed);
}

TEST_CASE("connect user data above 512 octets", "[session]") {
  const byte_buffer big(1000, 0x55);
  byte_buffer cn, none;

  SECTION("version 2 uses Extended User Data") {
    pair_fixture p;
    REQUIRE(p.initiator.connect(big, cn));
    CHECK(same(deliver<ss::connect_indication>(p.responder, cn, none).user_data, big));
  }
  SECTION("version 1 only fails without changing state") {
    ss::connection init{ss::role::initiator, initiator_options(ss::version_1)};
    CHECK(init.connect(big, cn).error() == errc::length_overflow);
    CHECK(cn.empty());
    CHECK(init.current_state() == ss::state::idle);
  }
}
