#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <vector>

#include "openiec61850/iso/presentation/ppdu.hpp"

using openiec61850::byte_buffer;
using openiec61850::byte_view;
using openiec61850::errc;
namespace ps = openiec61850::iso::presentation;

namespace {

bool same(byte_view a, byte_view b) { return std::equal(a.begin(), a.end(), b.begin(), b.end()); }

const byte_buffer selector{0x00, 0x00, 0x00, 0x01};
const byte_buffer aarq{0x60, 0x03, 0x80, 0x01, 0x00};  // dummy ACSE APDUs
const byte_buffer aare{0x61, 0x03, 0x80, 0x01, 0x00};
const byte_buffer abrt{0x64, 0x03, 0x80, 0x01, 0x01};
const byte_buffer mms_pdu{0xA0, 0x03, 0x02, 0x01, 0x01};

ps::pdv single(std::uint32_t id, byte_view data) {
  return {std::nullopt, id, ps::pdv_encoding::single_asn1_type, data, 0};
}

// CP-type of an MMS association: normal mode, selectors 0x00000001, contexts 1 = ACSE and 3 = MMS
// (both BER), user data = AARQ on context 1.
const byte_buffer cp_vector{
    0x31, 0x46,                                                  // CP-type SET
    0xA0, 0x03, 0x80, 0x01, 0x01,                                // mode-selector: normal-mode
    0xA2, 0x3F,                                                  // normal-mode-parameters
    0x81, 0x04, 0x00, 0x00, 0x00, 0x01,                          // calling-presentation-selector
    0x82, 0x04, 0x00, 0x00, 0x00, 0x01,                          // called-presentation-selector
    0xA4, 0x23,                                                  // context-definition-list
    0x30, 0x0F, 0x02, 0x01, 0x01, 0x06, 0x04, 0x52, 0x01, 0x00, 0x01,  // 1, {2 2 1 0 1}
    0x30, 0x04, 0x06, 0x02, 0x51, 0x01,                                //    {2 1 1}
    0x30, 0x10, 0x02, 0x01, 0x03, 0x06, 0x05, 0x28, 0xCA, 0x22, 0x02, 0x01,  // 3, {1 0 9506 2 1}
    0x30, 0x04, 0x06, 0x02, 0x51, 0x01,                                      //    {2 1 1}
    0x61, 0x0C, 0x30, 0x0A, 0x02, 0x01, 0x01,                    // fully-encoded-data, context 1
    0xA0, 0x05, 0x60, 0x03, 0x80, 0x01, 0x00};                   // single-ASN1-type: AARQ

const byte_buffer cpa_vector{
    0x31, 0x2F,                                                  // CPA-PPDU SET
    0xA0, 0x03, 0x80, 0x01, 0x01,                                // mode-selector
    0xA2, 0x28,                                                  // normal-mode-parameters
    0x83, 0x04, 0x00, 0x00, 0x00, 0x01,                          // responding-presentation-selector
    0xA5, 0x12,                                                  // result list
    0x30, 0x07, 0x80, 0x01, 0x00, 0x81, 0x02, 0x51, 0x01,        // acceptance, {2 1 1}
    0x30, 0x07, 0x80, 0x01, 0x00, 0x81, 0x02, 0x51, 0x01,        // acceptance, {2 1 1}
    0x61, 0x0C, 0x30, 0x0A, 0x02, 0x01, 0x01, 0xA0, 0x05, 0x61, 0x03, 0x80, 0x01, 0x00};

// TD-PPDU: an MMS PDU on context 3.
const byte_buffer data_vector{0x61, 0x0C, 0x30, 0x0A, 0x02, 0x01, 0x03,
                              0xA0, 0x05, 0xA0, 0x03, 0x02, 0x01, 0x01};

// ARU-PPDU carrying an ABRT on context 1.
const byte_buffer aru_vector{0xA0, 0x0E, 0x61, 0x0C, 0x30, 0x0A, 0x02, 0x01, 0x01,
                             0xA0, 0x05, 0x64, 0x03, 0x80, 0x01, 0x01};

ps::connect_ppdu mms_cp() {
  ps::connect_ppdu cp;
  cp.calling_selector = selector;
  cp.called_selector = selector;
  cp.contexts.push_back({1, ps::acse_abstract_syntax, {ps::ber_transfer_syntax}});
  cp.contexts.push_back({3, ps::mms_abstract_syntax, {ps::ber_transfer_syntax}});
  cp.user_data.push_back(single(1, aarq));
  return cp;
}

}  // namespace

TEST_CASE("CP-type encodes to the known-answer vector", "[presentation]") {
  byte_buffer out;
  REQUIRE(ps::encode(mms_cp(), out));
  CHECK(out == cp_vector);
}

TEST_CASE("CP-type decodes from the known-answer vector", "[presentation]") {
  auto cp = ps::decode_connect(cp_vector);
  REQUIRE(cp);
  CHECK_FALSE(cp->protocol_version);
  CHECK(same(cp->calling_selector, selector));
  CHECK(same(cp->called_selector, selector));
  REQUIRE(cp->contexts.size() == 2);
  CHECK(cp->contexts[0].id == 1);
  CHECK(cp->contexts[0].abstract_syntax == ps::acse_abstract_syntax);
  CHECK(cp->contexts[0].transfer_syntaxes == std::vector<openiec61850::ber::oid>{ps::ber_transfer_syntax});
  CHECK(cp->contexts[1].id == 3);
  CHECK(cp->contexts[1].abstract_syntax == ps::mms_abstract_syntax);
  CHECK_FALSE(cp->default_context);
  CHECK_FALSE(cp->presentation_requirements);
  REQUIRE(cp->user_data.size() == 1);
  CHECK(cp->user_data[0].context_id == 1);
  CHECK(cp->user_data[0].encoding == ps::pdv_encoding::single_asn1_type);
  CHECK(same(cp->user_data[0].data, aarq));
  // Zero-copy: the PDV points into the input.
  CHECK(cp->user_data[0].data.data() == cp_vector.data() + cp_vector.size() - aarq.size());
}

TEST_CASE("CP-type with every optional field round-trips", "[presentation]") {
  auto cp = mms_cp();
  cp.protocol_version = ps::protocol_version_1;
  cp.default_context = ps::default_context_name{ps::mms_abstract_syntax, ps::ber_transfer_syntax};
  cp.presentation_requirements = 0;
  cp.user_session_requirements = 0x02;  // duplex
  cp.contexts[1].transfer_syntaxes.push_back({1, 2, 3});
  const byte_buffer octets{1, 2, 3};
  cp.user_data.push_back({ps::ber_transfer_syntax, 3, ps::pdv_encoding::octet_aligned, octets, 0});
  const byte_buffer bits{0x01, 0x08};  // padding bits are zero
  cp.user_data.push_back({std::nullopt, 3, ps::pdv_encoding::arbitrary, bits, 3});

  byte_buffer out;
  REQUIRE(ps::encode(cp, out));
  // protocol-version {version-1} is the usual "80 02 07 80".
  const byte_buffer version{0x80, 0x02, 0x07, 0x80};
  CHECK(std::search(out.begin(), out.end(), version.begin(), version.end()) != out.end());

  auto d = ps::decode_connect(out);
  REQUIRE(d);
  CHECK(d->protocol_version == ps::protocol_version_1);
  REQUIRE(d->default_context);
  CHECK(d->default_context->abstract_syntax == ps::mms_abstract_syntax);
  CHECK(d->presentation_requirements == 0U);
  CHECK(d->user_session_requirements == 0x02U);
  CHECK(d->contexts[1].transfer_syntaxes.size() == 2);
  REQUIRE(d->user_data.size() == 3);
  CHECK(d->user_data[1].transfer_syntax == ps::ber_transfer_syntax);
  CHECK(d->user_data[1].encoding == ps::pdv_encoding::octet_aligned);
  CHECK(same(d->user_data[1].data, octets));
  CHECK(d->user_data[2].encoding == ps::pdv_encoding::arbitrary);
  CHECK(d->user_data[2].unused_bits == 3);
  CHECK(same(d->user_data[2].data, bits));
}

TEST_CASE("CP-type SET members may come in any order", "[presentation]") {
  // normal-mode-parameters before mode-selector.
  const byte_buffer v{0x31, 0x0A, 0xA2, 0x03, 0x88, 0x01, 0x00, 0xA0, 0x03, 0x80, 0x01, 0x01};
  auto cp = ps::decode_connect(v);
  REQUIRE(cp);
  CHECK(cp->presentation_requirements == 0U);
  CHECK(cp->contexts.empty());
}

TEST_CASE("CPA-PPDU encodes and decodes the known-answer vector", "[presentation]") {
  ps::accept_ppdu cpa;
  cpa.responding_selector = selector;
  cpa.results.push_back({ps::context_result_code::acceptance, ps::ber_transfer_syntax, std::nullopt});
  cpa.results.push_back({ps::context_result_code::acceptance, ps::ber_transfer_syntax, std::nullopt});
  cpa.user_data.push_back(single(1, aare));
  byte_buffer out;
  REQUIRE(ps::encode(cpa, out));
  CHECK(out == cpa_vector);

  auto d = ps::decode_accept(cpa_vector);
  REQUIRE(d);
  CHECK(same(d->responding_selector, selector));
  REQUIRE(d->results.size() == 2);
  CHECK(d->results[0].result == ps::context_result_code::acceptance);
  CHECK(d->results[0].transfer_syntax == ps::ber_transfer_syntax);
  CHECK_FALSE(d->results[0].provider_reason);
  REQUIRE(d->user_data.size() == 1);
  CHECK(same(d->user_data[0].data, aare));
}

TEST_CASE("CPA-PPDU with a provider rejection round-trips", "[presentation]") {
  ps::accept_ppdu cpa;
  cpa.results.push_back({ps::context_result_code::acceptance, ps::ber_transfer_syntax, std::nullopt});
  cpa.results.push_back({ps::context_result_code::provider_rejection, std::nullopt,
                         ps::context_reason::abstract_syntax_not_supported});
  byte_buffer out;
  REQUIRE(ps::encode(cpa, out));
  auto d = ps::decode_accept(out);
  REQUIRE(d);
  CHECK(d->responding_selector.empty());
  REQUIRE(d->results.size() == 2);
  CHECK(d->results[1].result == ps::context_result_code::provider_rejection);
  CHECK_FALSE(d->results[1].transfer_syntax);
  CHECK(d->results[1].provider_reason == ps::context_reason::abstract_syntax_not_supported);
  CHECK(d->user_data.empty());
}

TEST_CASE("CPR-PPDU round-trips", "[presentation]") {
  ps::refuse_ppdu cpr;
  cpr.responding_selector = selector;
  cpr.results.push_back({ps::context_result_code::user_rejection, std::nullopt, std::nullopt});
  cpr.default_context_result = ps::context_result_code::provider_rejection;
  cpr.provider_reason = ps::provider_reason::protocol_version_not_supported;
  cpr.user_data.push_back(single(1, aare));
  byte_buffer out;
  REQUIRE(ps::encode(cpr, out));
  CHECK(out[0] == 0x30);
  auto d = ps::decode_refuse(out);
  REQUIRE(d);
  CHECK(same(d->responding_selector, selector));
  REQUIRE(d->results.size() == 1);
  CHECK(d->results[0].result == ps::context_result_code::user_rejection);
  CHECK(d->default_context_result == ps::context_result_code::provider_rejection);
  CHECK(d->provider_reason == ps::provider_reason::protocol_version_not_supported);
  REQUIRE(d->user_data.size() == 1);
  CHECK(same(d->user_data[0].data, aare));

  const byte_buffer minimal{0x30, 0x03, 0x8A, 0x01, 0x06};
  auto m = ps::decode_refuse(minimal);
  REQUIRE(m);
  CHECK(m->provider_reason == ps::provider_reason::user_data_not_readable);
}

TEST_CASE("TD user data encodes and decodes the known-answer vector", "[presentation]") {
  const ps::pdv p = single(3, mms_pdu);
  byte_buffer out;
  REQUIRE(ps::encode_user_data({&p, 1}, out));
  CHECK(out == data_vector);

  std::vector<ps::pdv> pdvs{single(9, aarq)};  // cleared by the decoder
  REQUIRE(ps::decode_user_data(data_vector, pdvs));
  REQUIRE(pdvs.size() == 1);
  CHECK(pdvs[0].context_id == 3);
  CHECK_FALSE(pdvs[0].transfer_syntax);
  CHECK(same(pdvs[0].data, mms_pdu));
  CHECK(pdvs[0].data.data() == data_vector.data() + 9);

  CHECK(ps::encode_user_data({}, out).error() == errc::malformed_encoding);
}

TEST_CASE("ARU-PPDU encodes and decodes the known-answer vector", "[presentation]") {
  ps::user_abort_ppdu aru;
  aru.user_data.push_back(single(1, abrt));
  byte_buffer out;
  REQUIRE(ps::encode(aru, out));
  CHECK(out == aru_vector);

  auto d = ps::decode_abort(aru_vector);
  REQUIRE(d);
  REQUIRE(std::holds_alternative<ps::user_abort_ppdu>(*d));
  const auto& u = std::get<ps::user_abort_ppdu>(*d);
  CHECK(u.context_ids.empty());
  REQUIRE(u.user_data.size() == 1);
  CHECK(same(u.user_data[0].data, abrt));

  ps::user_abort_ppdu with_list;
  with_list.context_ids.push_back({1, ps::ber_transfer_syntax});
  out.clear();
  REQUIRE(ps::encode(with_list, out));
  CHECK(out == byte_buffer{0xA0, 0x0B, 0xA0, 0x09, 0x30, 0x07, 0x02, 0x01, 0x01, 0x06, 0x02, 0x51, 0x01});
  auto l = ps::decode_abort(out);
  REQUIRE(l);
  REQUIRE(std::get<ps::user_abort_ppdu>(*l).context_ids.size() == 1);
  CHECK(std::get<ps::user_abort_ppdu>(*l).context_ids[0].transfer_syntax == ps::ber_transfer_syntax);
}

TEST_CASE("ARP-PPDU round-trips", "[presentation]") {
  byte_buffer out;
  REQUIRE(ps::encode(ps::provider_abort_ppdu{ps::abort_reason::unrecognized_ppdu, ps::event_id::td_ppdu},
                     out));
  CHECK(out == byte_buffer{0x30, 0x06, 0x80, 0x01, 0x01, 0x81, 0x01, 0x07});
  auto d = ps::decode_abort(out);
  REQUIRE(d);
  REQUIRE(std::holds_alternative<ps::provider_abort_ppdu>(*d));
  CHECK(std::get<ps::provider_abort_ppdu>(*d).reason == ps::abort_reason::unrecognized_ppdu);
  CHECK(std::get<ps::provider_abort_ppdu>(*d).event == ps::event_id::td_ppdu);

  auto empty = ps::decode_abort(byte_buffer{0x30, 0x00});
  REQUIRE(empty);
  CHECK_FALSE(std::get<ps::provider_abort_ppdu>(*empty).reason);
}

TEST_CASE("truncated PPDUs are rejected", "[presentation]") {
  for (std::size_t n = 0; n < cp_vector.size(); ++n) {
    CHECK_FALSE(ps::decode_connect(byte_view{cp_vector}.first(n)));
  }
  for (std::size_t n = 0; n < cpa_vector.size(); ++n) {
    CHECK_FALSE(ps::decode_accept(byte_view{cpa_vector}.first(n)));
  }
  std::vector<ps::pdv> pdvs;
  for (std::size_t n = 0; n < data_vector.size(); ++n) {
    CHECK_FALSE(ps::decode_user_data(byte_view{data_vector}.first(n), pdvs));
    CHECK(pdvs.empty());
  }
  for (std::size_t n = 0; n < aru_vector.size(); ++n) {
    CHECK_FALSE(ps::decode_abort(byte_view{aru_vector}.first(n)));
  }
}

TEST_CASE("malformed and unsupported PPDUs are rejected", "[presentation]") {
  std::vector<ps::pdv> pdvs;

  SECTION("x410 mode") {
    const byte_buffer v{0x31, 0x05, 0xA0, 0x03, 0x80, 0x01, 0x00};
    CHECK(ps::decode_connect(v).error() == errc::unsupported);
  }
  SECTION("unknown mode") {
    const byte_buffer v{0x31, 0x05, 0xA0, 0x03, 0x80, 0x01, 0x02};
    CHECK(ps::decode_connect(v).error() == errc::malformed_encoding);
  }
  SECTION("missing mode-selector") {
    const byte_buffer v{0x31, 0x02, 0xA2, 0x00};
    CHECK(ps::decode_connect(v).error() == errc::malformed_encoding);
  }
  SECTION("duplicate mode-selector") {
    const byte_buffer v{0x31, 0x0A, 0xA0, 0x03, 0x80, 0x01, 0x01, 0xA0, 0x03, 0x80, 0x01, 0x01};
    CHECK(ps::decode_connect(v).error() == errc::malformed_encoding);
  }
  SECTION("x410-mode-parameters") {
    const byte_buffer v{0x31, 0x07, 0xA0, 0x03, 0x80, 0x01, 0x01, 0xA1, 0x00};
    CHECK(ps::decode_connect(v).error() == errc::unsupported);
  }
  SECTION("normal-mode parameters out of order") {
    const byte_buffer v{0x31, 0x0D, 0xA0, 0x03, 0x80, 0x01, 0x01, 0xA2, 0x06,
                        0x82, 0x01, 0x01, 0x81, 0x01, 0x01};
    CHECK(ps::decode_connect(v).error() == errc::malformed_encoding);
  }
  SECTION("unknown context-specific parameters are skipped") {
    const byte_buffer v{0x31, 0x0D, 0xA0, 0x03, 0x80, 0x01, 0x01, 0xA2, 0x06,
                        0x81, 0x01, 0x07, 0x8B, 0x01, 0x00};
    auto cp = ps::decode_connect(v);
    REQUIRE(cp);
    CHECK(cp->calling_selector.size() == 1);
  }
  SECTION("parameters of another PPDU type") {
    CHECK(ps::decode_accept(cp_vector).error() == errc::malformed_encoding);
    CHECK(ps::decode_connect(cpa_vector).error() == errc::malformed_encoding);
  }
  SECTION("trailing octets") {
    byte_buffer v = cp_vector;
    v.push_back(0x00);
    CHECK(ps::decode_connect(v).error() == errc::malformed_encoding);
    byte_buffer d = data_vector;
    d.push_back(0x00);
    CHECK(ps::decode_user_data(d, pdvs).error() == errc::malformed_encoding);
  }
  SECTION("context identifier zero") {
    const byte_buffer v{0x61, 0x0C, 0x30, 0x0A, 0x02, 0x01, 0x00,
                        0xA0, 0x05, 0xA0, 0x03, 0x02, 0x01, 0x01};
    CHECK(ps::decode_user_data(v, pdvs).error() == errc::malformed_encoding);
  }
  SECTION("negative context identifier") {
    const byte_buffer v{0x61, 0x0C, 0x30, 0x0A, 0x02, 0x01, 0xFF,
                        0xA0, 0x05, 0xA0, 0x03, 0x02, 0x01, 0x01};
    CHECK_FALSE(ps::decode_user_data(v, pdvs));
  }
  SECTION("simply-encoded-data") {
    const byte_buffer v{0x40, 0x02, 0x01, 0x02};
    CHECK(ps::decode_user_data(v, pdvs).error() == errc::unsupported);
  }
  SECTION("empty fully-encoded-data") {
    const byte_buffer v{0x61, 0x00};
    CHECK(ps::decode_user_data(v, pdvs).error() == errc::malformed_encoding);
  }
  SECTION("single-ASN1-type holding two values") {
    const byte_buffer v{0x61, 0x0B, 0x30, 0x09, 0x02, 0x01, 0x03, 0xA0, 0x04, 0x05, 0x00, 0x05, 0x00};
    CHECK(ps::decode_user_data(v, pdvs).error() == errc::malformed_encoding);
  }
  SECTION("single-ASN1-type in primitive form") {
    const byte_buffer v{0x61, 0x09, 0x30, 0x07, 0x02, 0x01, 0x03, 0x80, 0x02, 0x05, 0x00};
    CHECK(ps::decode_user_data(v, pdvs).error() == errc::malformed_encoding);
  }
  SECTION("context definition without transfer syntaxes") {
    const byte_buffer v{0x31, 0x16, 0xA0, 0x03, 0x80, 0x01, 0x01, 0xA2, 0x0F, 0xA4, 0x0D,
                        0x30, 0x0B, 0x02, 0x01, 0x01, 0x06, 0x04, 0x52, 0x01, 0x00, 0x01, 0x30, 0x00};
    CHECK(ps::decode_connect(v).error() == errc::malformed_encoding);
  }
  SECTION("result out of range") {
    const byte_buffer v{0x31, 0x0E, 0xA0, 0x03, 0x80, 0x01, 0x01, 0xA2, 0x07, 0xA5, 0x05,
                        0x30, 0x03, 0x80, 0x01, 0x03};
    CHECK(ps::decode_accept(v).error() == errc::malformed_encoding);
  }
  SECTION("x400-mode CPR and ARU") {
    CHECK(ps::decode_refuse(byte_buffer{0x31, 0x00}).error() == errc::unsupported);
    CHECK(ps::decode_abort(byte_buffer{0x31, 0x00}).error() == errc::unsupported);
  }
  SECTION("unknown abort type") {
    CHECK(ps::decode_abort(byte_buffer{0xA1, 0x00}).error() == errc::malformed_encoding);
  }
  SECTION("encoders reject invalid values and leave the output unchanged") {
    byte_buffer out{0xEE};
    auto cp = mms_cp();
    cp.contexts[0].abstract_syntax = {};
    CHECK_FALSE(ps::encode(cp, out));
    cp = mms_cp();
    cp.user_data[0].context_id = 0;
    CHECK_FALSE(ps::encode(cp, out));
    CHECK(out == byte_buffer{0xEE});
  }
}
