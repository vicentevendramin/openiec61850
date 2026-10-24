#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstdint>
#include <exception>
#include <optional>
#include <variant>

#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/io_context.hpp>
#include <asio/this_coro.hpp>

#include "../../src/association/handshake.hpp"
#include "../mms/mms_test_util.hpp"
#include "openiec61850/association/association.hpp"

using openiec61850::byte_buffer;
using openiec61850::byte_view;
using openiec61850::result;
using namespace openiec61850::association;
namespace detail = openiec61850::association::detail;
namespace mms = openiec61850::mms;
namespace acse = openiec61850::iso::acse;
namespace ps = openiec61850::iso::presentation;
namespace transport = openiec61850::transport;
using asio::awaitable;
using mms_test::hex;
using namespace std::chrono_literals;

namespace {

// The CP TSDU sent by client_association::connect() with default association_params (no
// password), annotated. Derived from the standards (not from any implementation):
//
// S-CONNECT (X.225 §8.3.1), CN SPDU:
//   0D B5                    SI 13 (CN), LI 181
//   05 06 13 01 00 16 01 02  Connect/Accept Item: protocol options 0, version number {2}
//   14 02 00 02              Session User Requirements: duplex only (the kernel is implicit)
//   33 02 00 01              Calling Session Selector 0x0001
//   34 02 00 01              Called Session Selector 0x0001
//   C1 9F                    User Data (PGI 193), 159 octets: the CP-type
// CP-type (X.226 §8.2):
//   31 81 9C                 SET
//   A0 03 80 01 01           mode-selector: normal-mode
//   A2 81 94                 normal-mode-parameters (protocol-version omitted = DEFAULT {version-1})
//   81 04 00 00 00 01        calling-presentation-selector 0x00000001
//   82 04 00 00 00 01        called-presentation-selector 0x00000001
//   A4 23                    presentation-context-definition-list:
//     30 0F 02 01 01 06 04 52 01 00 01 30 04 06 02 51 01      1: acse-as-id {2 2 1 0 1}, BER {2 1 1}
//     30 10 02 01 03 06 05 28 CA 22 02 01 30 04 06 02 51 01   3: MMS {1 0 9506 2 1}, BER {2 1 1}
//   (no presentation-requirements: kernel only; no user-session-requirements)
//   61 61 30 5F 02 01 01 A0 5A   fully-encoded-data, PDV of context 1, single-ASN1-type
// AARQ (X.227 §9, explicit tags):
//   60 58                    [APPLICATION 0]
//   80 02 07 80              protocol-version {version1}
//   A1 07 06 05 28 CA 22 02 03   application-context-name {1 0 9506 2 3} (ISO 9506-2 / 61850-8-1)
//   A2 06 06 04 29 87 67 01  called-AP-title {1 1 999 1} (form 2)
//   A3 03 02 01 0C           called-AE-qualifier 12 (form 2)
//   A6 06 06 04 29 87 67 01  calling-AP-title {1 1 999 1}
//   A7 03 02 01 0C           calling-AE-qualifier 12
//   BE 2F 28 2D 02 01 03 A0 28   user-information: EXTERNAL, indirect-reference 3 (the MMS
//                            context; no direct-reference), single-ASN1-type
// Initiate-RequestPDU (ISO 9506-2 §8.2):
//   A8 26                    [8]
//   80 03 00 FD E8           localDetailCalling 65000
//   81 01 05 82 01 05        proposedMaxServOutstandingCalling 5, -Called 5
//   83 01 0A                 proposedDataStructureNestingLevel 10
//   A4 16 80 01 01           initRequestDetail: proposedVersionNumber 1
//   81 03 05 F1 00           proposedParameterCBB: str1 str2 vnam valt vlis (11 bits)
//   82 0C 03 6E 1C 00 .. 01 18   servicesSupportedCalling (85 bits): getNameList identify read
//                            write getVariableAccessAttributes defineNVL getNVLAttributes
//                            deleteNVL informationReport conclude cancel
//
// Against what IEC 61850-8-1 servers commonly expect (8-1 §6 / A-profile, and the defaults used
// for IEC 61850 tooling): TSAPs 0x0001 (checked on the CR below), session selectors 0x0001,
// presentation selectors 0x00000001, presentation contexts 1 = ACSE and 3 = MMS with BER only,
// normal mode with the kernel functional units, the MMS application context {1 0 9506 2 3}
// and AP-title {1 1 999 1} / AE-qualifier 12 all match. Points that a strict peer could treat
// differently, all permitted by the standards: the CN proposes session version 2 only (some
// servers drop a CN that proposes versions 1 and 2 together), the CP omits the DEFAULT
// protocol-version, the AARQ carries an explicit protocol-version, and the EXTERNAL identifies
// the MMS PDU by indirect-reference only (X.227 §7.1.4 with a presentation context identifier).
// servicesSupportedCalling lists the services this codec handles; peers that test individual
// bits (e.g. the file services, which are not proposed here) may restrict what they offer.
const byte_buffer cp_vector = hex(
    "0D B5 05 06 13 01 00 16 01 02 14 02 00 02 33 02 00 01 34 02 00 01 C1 9F 31 81 9C A0 03 80 01 01 "
    "A2 81 94 81 04 00 00 00 01 82 04 00 00 00 01 A4 23 30 0F 02 01 01 06 04 52 01 00 01 30 04 06 02 "
    "51 01 30 10 02 01 03 06 05 28 CA 22 02 01 30 04 06 02 51 01 61 61 30 5F 02 01 01 A0 5A 60 58 80 "
    "02 07 80 A1 07 06 05 28 CA 22 02 03 A2 06 06 04 29 87 67 01 A3 03 02 01 0C A6 06 06 04 29 87 67 "
    "01 A7 03 02 01 0C BE 2F 28 2D 02 01 03 A0 28 A8 26 80 03 00 FD E8 81 01 05 82 01 05 83 01 0A A4 "
    "16 80 01 01 81 03 05 F1 00 82 0C 03 6E 1C 00 00 00 00 00 00 00 01 18");

ps::pdv single(std::uint32_t context, byte_view data) {
  return {std::nullopt, context, ps::pdv_encoding::single_asn1_type, data, 0};
}

// An initiator and a responder presentation connection wired back to back, in memory.
struct stack_pair {
  association_params params;
  server_options options;
  ps::connection initiator;
  ps::connection responder;
  byte_buffer request;  // the CP TSDU

  explicit stack_pair(association_params p = {}, server_options o = {})
      : params(std::move(p)),
        options(std::move(o)),
        initiator(ps::role::initiator, detail::initiator_options(params)),
        responder(ps::role::responder, detail::responder_options(options)) {
    REQUIRE(detail::connect_request(initiator, params, request));
  }

  detail::associate_indication indication() {
    byte_buffer none;
    auto ev = responder.on_tsdu(request, none);
    REQUIRE(ev);
    REQUIRE(std::holds_alternative<ps::connect_indication>(*ev));
    return detail::parse_associate_request(std::get<ps::connect_indication>(*ev), {});
  }

  detail::associate_response answer(const byte_buffer& tsdu) {
    byte_buffer none;
    auto ev = initiator.on_tsdu(tsdu, none);
    REQUIRE(ev);
    return detail::parse_associate_response(*ev, params.initiate, {});
  }
};

}  // namespace

TEST_CASE("the CP(AARQ(Initiate-Request)) matches the known-answer vector", "[association]") {
  // Offline, through the sans-I/O path.
  stack_pair s;
  CHECK(s.request == cp_vector);

  // And on the wire: a bare COTP listener captures what client_association::connect() sends.
  asio::io_context ctx;
  std::exception_ptr failure;
  bool done = false;
  asio::co_spawn(
      ctx,
      []() -> awaitable<void> {
        const auto ex = co_await asio::this_coro::executor;
        auto l = transport::cotp_listener::listen(ex, {asio::ip::address_v4::loopback(), 0});
        REQUIRE(l);
        std::optional<byte_buffer> got;
        std::optional<transport::cotp_channel> peer;  // kept open: the client must time out
        asio::co_spawn(
            ex,
            [](transport::cotp_listener& li, std::optional<byte_buffer>& out,
               std::optional<transport::cotp_channel>& keep) -> awaitable<void> {
              auto ch = co_await li.accept();
              REQUIRE(ch);
              auto t = co_await ch->receive();
              REQUIRE(t);
              out = std::move(*t);
              keep.emplace(std::move(*ch));
            }(*l, got, peer),
            asio::detached);
        association_params p;
        p.port = l->local_endpoint().port();
        p.association_timeout = 50ms;
        auto c = co_await client_association::connect(ex, p);
        CHECK(c.error() == asio::error::timed_out);
        REQUIRE(got);
        CHECK(*got == cp_vector);
        REQUIRE(peer);
        CHECK(peer->connection_info().calling_tsap == byte_buffer{0x00, 0x01});
        CHECK(peer->connection_info().called_tsap == byte_buffer{0x00, 0x01});
      }(),
      [&](std::exception_ptr e) {
        failure = e;
        done = true;
      });
  ctx.run_for(2s);
  REQUIRE(done);
  if (failure) std::rethrow_exception(failure);
}

TEST_CASE("negotiate takes the minimum of proposal and local limits", "[association]") {
  mms::initiate_request p;
  p.max_serv_outstanding_calling = 10;
  p.max_serv_outstanding_called = 1;
  p.data_structure_nesting_level = 4;
  p.detail.version_number = 2;
  mms::initiate_response local;
  local.local_detail_called = 8000;
  local.max_serv_outstanding_calling = 6;
  local.max_serv_outstanding_called = 6;
  local.data_structure_nesting_level = 8;
  local.detail.parameter_cbb = mms::support_options(mms::parameter_cbb::bit_count, {mms::parameter_cbb::str1});
  const auto n = negotiate(p, local);
  CHECK(n.local_detail_called == 8000);
  CHECK(n.max_serv_outstanding_calling == 6);
  CHECK(n.max_serv_outstanding_called == 1);
  CHECK(n.data_structure_nesting_level == 4);
  CHECK(n.detail.version_number == 1);
  CHECK(n.detail.parameter_cbb.test(mms::parameter_cbb::str1));
  CHECK_FALSE(n.detail.parameter_cbb.test(mms::parameter_cbb::str2));
  CHECK(n.detail.services == local.detail.services);

  p.data_structure_nesting_level.reset();
  p.max_serv_outstanding_called = 0;
  const auto m = negotiate(p, local);
  CHECK_FALSE(m.data_structure_nesting_level);
  CHECK(m.max_serv_outstanding_called == 1);
}

TEST_CASE("handshake: accepted association", "[association]") {
  association_params p;
  p.password = "pw";
  stack_pair s(p);
  const auto ind = s.indication();
  REQUIRE(ind.request);
  CHECK(ind.acse_context == 1U);
  CHECK(ind.mms_context == 3U);
  CHECK(ind.request->password == "pw");
  CHECK(ind.request->mechanism_name == acse::oids::password_mechanism);
  CHECK(ind.request->called_presentation_selector == byte_buffer{0, 0, 0, 1});
  CHECK(ind.request->initiate.local_detail_calling == 65000);

  mms::initiate_response local;
  local.max_serv_outstanding_calling = 2;
  byte_buffer tsdu;
  REQUIRE(detail::accept_association(s.responder, ind, s.options, negotiate(ind.request->initiate, local), tsdu));
  const auto r = s.answer(tsdu);
  CHECK_FALSE(r.error);
  CHECK(r.negotiated.max_serv_outstanding_calling == 2);
  CHECK(r.responding_ap_title == default_ap_title);
  CHECK(r.responding_ae_qualifier == default_ae_qualifier);
}

TEST_CASE("handshake: rejections map to association errors", "[association]") {
  SECTION("authentication") {
    stack_pair s;
    const auto ind = s.indication();
    byte_buffer tsdu;
    REQUIRE(detail::refuse_association(s.responder, ind, s.options,
                                       acse::service_user_diagnostic::authentication_required, tsdu));
    CHECK(s.answer(tsdu).error == errc::authentication_failed);
  }
  SECTION("other diagnostic") {
    stack_pair s;
    const auto ind = s.indication();
    byte_buffer tsdu;
    REQUIRE(detail::refuse_association(s.responder, ind, s.options,
                                       acse::service_user_diagnostic::no_reason_given, tsdu));
    CHECK(s.answer(tsdu).error == errc::association_rejected);
  }
  SECTION("CPR without AARE") {
    stack_pair s;
    (void)s.indication();
    byte_buffer tsdu;
    REQUIRE(s.responder.refuse({}, tsdu));
    CHECK(s.answer(tsdu).error == errc::connection_refused);
  }
  SECTION("abort") {
    stack_pair s;
    (void)s.indication();
    byte_buffer tsdu;
    REQUIRE(s.responder.abort({}, tsdu));
    CHECK(s.answer(tsdu).error == errc::peer_aborted);
  }
  SECTION("Initiate-Error") {
    // An AARQ whose user information is not an Initiate-RequestPDU (a Conclude-RequestPDU).
    association_params p;
    stack_pair s(p);
    const byte_buffer conclude{0x8B, 0x00};
    acse::mms_aarq_params a;
    a.initiate_request = conclude;
    auto aarq = detail::encode_acse(acse::make_mms_aarq(a));
    REQUIRE(aarq);
    ps::connection initiator(ps::role::initiator, detail::initiator_options(p));
    byte_buffer cp;
    const auto pdv = single(1, *aarq);
    REQUIRE(initiator.connect({&pdv, 1}, cp));
    byte_buffer none;
    auto ev = s.responder.on_tsdu(cp, none);
    REQUIRE(ev);
    const auto ind = detail::parse_associate_request(std::get<ps::connect_indication>(*ev), {});
    CHECK_FALSE(ind.request);
    CHECK(ind.initiate_failed);
    byte_buffer tsdu;
    REQUIRE(detail::refuse_association(s.responder, ind, s.options, ind.diagnostic, tsdu));
    auto ev2 = initiator.on_tsdu(tsdu, none);
    REQUIRE(ev2);
    const auto r = detail::parse_associate_response(*ev2, p.initiate, {});
    CHECK(r.error == errc::initiate_error);
    REQUIRE(r.initiate_error);
    CHECK(r.initiate_error->cls == mms::error_class::initiate);
  }
  SECTION("wrong application context") {
    stack_pair s;
    const byte_buffer conclude{0x8B, 0x00};
    acse::mms_aarq_params params;
    params.initiate_request = conclude;
    acse::aarq_apdu a = acse::make_mms_aarq(params);
    a.application_context_name = openiec61850::ber::oid{1, 2, 3};
    auto aarq = detail::encode_acse(a);
    REQUIRE(aarq);
    ps::connection initiator(ps::role::initiator, detail::initiator_options(s.params));
    byte_buffer cp, none;
    const auto pdv = single(1, *aarq);
    REQUIRE(initiator.connect({&pdv, 1}, cp));
    auto ev = s.responder.on_tsdu(cp, none);
    REQUIRE(ev);
    const auto ind = detail::parse_associate_request(std::get<ps::connect_indication>(*ev), {});
    CHECK_FALSE(ind.request);
    CHECK(ind.diagnostic == acse::service_user_diagnostic::application_context_name_not_supported);
  }
}

TEST_CASE("association error category", "[association]") {
  std::error_code ec = errc::authentication_failed;
  CHECK(ec.category().name() == std::string_view{"openiec61850.association"});
  CHECK(ec.message() == "authentication failed");
  CHECK(ec != openiec61850::errc::protocol_violation);
}
