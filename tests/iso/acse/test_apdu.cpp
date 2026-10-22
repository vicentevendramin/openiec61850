#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <string_view>
#include <variant>

#include "openiec61850/iso/acse/apdu.hpp"

using openiec61850::byte_buffer;
using openiec61850::byte_view;
using openiec61850::errc;
namespace acse = openiec61850::iso::acse;
namespace ber = openiec61850::ber;

namespace {

bool same(byte_view a, byte_view b) { return std::equal(a.begin(), a.end(), b.begin(), b.end()); }

template <typename T>
T decode_as(byte_view data) {
  auto r = acse::decode(data);
  REQUIRE(r);
  REQUIRE(std::holds_alternative<T>(*r));
  return std::get<T>(*r);
}

template <typename T>
byte_buffer encoded(const T& a) {
  byte_buffer out;
  REQUIRE(acse::encode(a, out));
  return out;
}

// Re-encoding a decoded APDU reproduces the input.
void check_reencodes(const byte_buffer& data) {
  auto r = acse::decode(data);
  REQUIRE(r);
  byte_buffer again;
  REQUIRE(acse::encode(*r, again));
  CHECK(again == data);
}

const ber::oid called_title{1, 1, 999, 1};
const byte_buffer initiate{0xA8, 0x03, 0x80, 0x01, 0x7F};  // dummy single-ASN1-type payload

// AARQ: protocol-version {version1}, application context {1 0 9506 2 3}, called AP-title {1 1 999 1},
// called AE-qualifier 12, user-information = EXTERNAL {indirect-reference 3, single-ASN1-type}.
const byte_buffer aarq_vector{
    0x60, 0x28,                                                  // AARQ
    0x80, 0x02, 0x07, 0x80,                                      // protocol-version
    0xA1, 0x07, 0x06, 0x05, 0x28, 0xCA, 0x22, 0x02, 0x03,        // application-context-name
    0xA2, 0x06, 0x06, 0x04, 0x29, 0x87, 0x67, 0x01,              // called-AP-title
    0xA3, 0x03, 0x02, 0x01, 0x0C,                                // called-AE-qualifier
    0xBE, 0x0C, 0x28, 0x0A, 0x02, 0x01, 0x03,                    // user-information, EXTERNAL
    0xA0, 0x05, 0xA8, 0x03, 0x80, 0x01, 0x7F};                   // single-ASN1-type

// Same plus password authentication (mechanism {2 2 3 1}, charstring "password").
const byte_buffer aarq_password_vector{
    0x60, 0x3D,
    0x80, 0x02, 0x07, 0x80,
    0xA1, 0x07, 0x06, 0x05, 0x28, 0xCA, 0x22, 0x02, 0x03,
    0xA2, 0x06, 0x06, 0x04, 0x29, 0x87, 0x67, 0x01,
    0xA3, 0x03, 0x02, 0x01, 0x0C,
    0x8A, 0x02, 0x07, 0x80,                                      // sender-acse-requirements
    0x8B, 0x03, 0x52, 0x03, 0x01,                                // mechanism-name
    0xAC, 0x0A, 0x80, 0x08, 'p', 'a', 's', 's', 'w', 'o', 'r', 'd',  // calling-authentication-value
    0xBE, 0x0C, 0x28, 0x0A, 0x02, 0x01, 0x03, 0xA0, 0x05, 0xA8, 0x03, 0x80, 0x01, 0x7F};

// AARE accepted, result-source-diagnostic acse-service-user null(0).
const byte_buffer aare_vector{
    0x61, 0x23,
    0xA1, 0x07, 0x06, 0x05, 0x28, 0xCA, 0x22, 0x02, 0x03,        // application-context-name
    0xA2, 0x03, 0x02, 0x01, 0x00,                                // result accepted
    0xA3, 0x05, 0xA1, 0x03, 0x02, 0x01, 0x00,                    // acse-service-user null
    0xBE, 0x0C, 0x28, 0x0A, 0x02, 0x01, 0x03, 0xA0, 0x05, 0xA9, 0x03, 0x80, 0x01, 0x7F};

const byte_buffer rlrq_vector{0x62, 0x03, 0x80, 0x01, 0x00};
const byte_buffer rlre_vector{0x63, 0x03, 0x80, 0x01, 0x00};
const byte_buffer abrt_vector{0x64, 0x03, 0x80, 0x01, 0x00};
const byte_buffer abrt_diagnostic_vector{0x64, 0x06, 0x80, 0x01, 0x01, 0x81, 0x01, 0x02};

acse::aarq_apdu reference_aarq() {
  acse::aarq_apdu a;
  a.protocol_version = acse::protocol_version::version1;
  a.application_context_name = acse::oids::mms_application_context;
  a.called_ap_title = called_title;
  a.called_ae_qualifier = std::int64_t{12};
  a.user_information.push_back(acse::single_asn1_external(3, initiate));
  return a;
}

}  // namespace

TEST_CASE("AARQ encodes to the known-answer vector", "[acse]") {
  CHECK(encoded(reference_aarq()) == aarq_vector);
}

TEST_CASE("AARQ decodes from the known-answer vector", "[acse]") {
  const auto a = decode_as<acse::aarq_apdu>(aarq_vector);
  CHECK(a.protocol_version == acse::protocol_version::version1);
  CHECK(a.application_context_name == acse::oids::mms_application_context);
  REQUIRE(a.called_ap_title);
  CHECK(std::get<ber::oid>(*a.called_ap_title) == called_title);
  REQUIRE(a.called_ae_qualifier);
  CHECK(std::get<std::int64_t>(*a.called_ae_qualifier) == 12);
  CHECK_FALSE(a.calling_ap_title);
  CHECK_FALSE(a.acse_requirements);
  CHECK_FALSE(a.authentication);
  REQUIRE(a.user_information.size() == 1);
  const auto& x = a.user_information[0];
  CHECK_FALSE(x.direct_reference);
  CHECK(x.indirect_reference == 3);
  CHECK(x.encoding == acse::external_encoding::single_asn1_type);
  CHECK(same(x.data, initiate));
  // Zero-copy: the payload points into the input.
  CHECK(x.data.data() == aarq_vector.data() + 37);
  REQUIRE(acse::find_by_context(a.user_information, 3) == &x);
  CHECK(acse::find_by_context(a.user_information, 1) == nullptr);
}

TEST_CASE("make_mms_aarq builds the IEC 61850-8-1 AARQ", "[acse]") {
  acse::mms_aarq_params p;
  p.called_ap_title = called_title;
  p.called_ae_qualifier = std::int64_t{12};
  p.mms_context_id = 3;
  p.initiate_request = initiate;
  CHECK(encoded(acse::make_mms_aarq(p)) == aarq_vector);

  p.password = "password";
  CHECK(encoded(acse::make_mms_aarq(p)) == aarq_password_vector);

  const auto a = decode_as<acse::aarq_apdu>(aarq_password_vector);
  CHECK(a.acse_requirements == acse::acse_requirements::authentication);
  CHECK(a.mechanism_name == acse::oids::password_mechanism);
  REQUIRE(a.authentication);
  CHECK(std::get<acse::auth_charstring>(*a.authentication).value == "password");
}

TEST_CASE("AARE encodes and decodes the known-answer vector", "[acse]") {
  const byte_buffer response{0xA9, 0x03, 0x80, 0x01, 0x7F};
  auto a = acse::make_mms_aare(3, response);
  a.protocol_version.reset();
  CHECK(encoded(a) == aare_vector);

  const auto d = decode_as<acse::aare_apdu>(aare_vector);
  CHECK_FALSE(d.protocol_version);
  CHECK(d.application_context_name == acse::oids::mms_application_context);
  CHECK(d.result == acse::associate_result::accepted);
  CHECK(d.result_source_diagnostic.source == acse::diagnostic_source::service_user);
  CHECK(d.result_source_diagnostic.reason == acse::service_user_diagnostic::null);
  REQUIRE(d.user_information.size() == 1);
  CHECK(d.user_information[0].indirect_reference == 3);
  CHECK(same(d.user_information[0].data, response));
}

TEST_CASE("AARE rejection with a provider diagnostic round-trips", "[acse]") {
  acse::aare_apdu a;
  a.application_context_name = acse::oids::mms_application_context;
  a.result = acse::associate_result::rejected_transient;
  a.result_source_diagnostic = {acse::diagnostic_source::service_provider,
                                acse::service_provider_diagnostic::no_common_acse_version};
  const auto data = encoded(a);
  CHECK(same(byte_view{data}.subspan(11, 12),
             byte_buffer{0xA2, 0x03, 0x02, 0x01, 0x02, 0xA3, 0x05, 0xA2, 0x03, 0x02, 0x01, 0x02}));
  const auto d = decode_as<acse::aare_apdu>(data);
  CHECK(d.result == acse::associate_result::rejected_transient);
  CHECK(d.result_source_diagnostic.source == acse::diagnostic_source::service_provider);
  CHECK(d.result_source_diagnostic.reason == acse::service_provider_diagnostic::no_common_acse_version);
}

TEST_CASE("RLRQ, RLRE and ABRT known-answer vectors", "[acse]") {
  acse::rlrq_apdu rq;
  rq.reason = acse::release_request_reason::normal;
  CHECK(encoded(rq) == rlrq_vector);
  CHECK(decode_as<acse::rlrq_apdu>(rlrq_vector).reason == acse::release_request_reason::normal);

  acse::rlre_apdu rp;
  rp.reason = acse::release_response_reason::normal;
  CHECK(encoded(rp) == rlre_vector);
  CHECK(decode_as<acse::rlre_apdu>(rlre_vector).reason == acse::release_response_reason::normal);

  acse::abrt_apdu ab;
  CHECK(encoded(ab) == abrt_vector);
  const auto d = decode_as<acse::abrt_apdu>(abrt_vector);
  CHECK(d.source == acse::abort_source::service_user);
  CHECK_FALSE(d.diagnostic);

  ab.source = acse::abort_source::service_provider;
  ab.diagnostic = acse::abort_diagnostic::protocol_error;
  CHECK(encoded(ab) == abrt_diagnostic_vector);
  const auto d2 = decode_as<acse::abrt_apdu>(abrt_diagnostic_vector);
  CHECK(d2.source == acse::abort_source::service_provider);
  CHECK(d2.diagnostic == acse::abort_diagnostic::protocol_error);

  // Empty release APDUs: every field is optional.
  CHECK(encoded(acse::rlrq_apdu{}) == byte_buffer{0x62, 0x00});
  CHECK_FALSE(decode_as<acse::rlre_apdu>(byte_buffer{0x63, 0x00}).reason);
}

TEST_CASE("AARQ with every field round-trips", "[acse]") {
  const byte_buffer name_form1{0x30, 0x00};               // AP-title form 1: empty RDNSequence
  const byte_buffer rdn_form1{0x31, 0x03, 0x30, 0x01, 0x00};  // AE-qualifier form 1, kept raw
  const byte_buffer ctx_list{0x06, 0x05, 0x28, 0xCA, 0x22, 0x02, 0x03};
  const byte_buffer octets{1, 2, 3}, bits{0xF0};
  acse::aarq_apdu a;
  a.protocol_version = acse::protocol_version::version1;
  a.application_context_name = acse::oids::mms_application_context;
  a.called_ap_title = acse::raw_form{name_form1};
  a.called_ae_qualifier = acse::raw_form{rdn_form1};
  a.called_ap_invocation_id = 1;
  a.called_ae_invocation_id = -2;
  a.calling_ap_title = ber::oid{1, 1, 999, 2};
  a.calling_ae_qualifier = std::int64_t{300};
  a.calling_ap_invocation_id = 70000;
  a.calling_ae_invocation_id = 0;
  a.acse_requirements = acse::acse_requirements::authentication |
                        acse::acse_requirements::nested_association;
  a.mechanism_name = ber::oid{1, 2, 3};
  a.authentication = acse::auth_bitstring{bits, 4};
  a.application_context_name_list = ctx_list;
  a.implementation_information = "openiec61850";
  acse::external x1;
  x1.direct_reference = acse::oids::ber_transfer_syntax;
  x1.indirect_reference = 1;
  x1.data_value_descriptor = "desc";
  x1.encoding = acse::external_encoding::octet_aligned;
  x1.data = octets;
  acse::external x2;
  x2.encoding = acse::external_encoding::arbitrary;
  x2.data = bits;
  x2.bit_count = 5;
  a.user_information = {x1, x2, acse::single_asn1_external(3, initiate)};

  const auto data = encoded(a);
  check_reencodes(data);
  const auto d = decode_as<acse::aarq_apdu>(data);
  CHECK(same(std::get<acse::raw_form>(*d.called_ap_title).encoding, name_form1));
  CHECK(same(std::get<acse::raw_form>(*d.called_ae_qualifier).encoding, rdn_form1));
  CHECK(d.called_ap_invocation_id == 1);
  CHECK(d.called_ae_invocation_id == -2);
  CHECK(std::get<ber::oid>(*d.calling_ap_title) == ber::oid{1, 1, 999, 2});
  CHECK(std::get<std::int64_t>(*d.calling_ae_qualifier) == 300);
  CHECK(d.calling_ap_invocation_id == 70000);
  CHECK(d.calling_ae_invocation_id == 0);
  CHECK(d.acse_requirements == (acse::acse_requirements::authentication |
                                acse::acse_requirements::nested_association));
  CHECK(d.mechanism_name == ber::oid{1, 2, 3});
  const auto& b = std::get<acse::auth_bitstring>(*d.authentication);
  CHECK(b.bit_count == 4);
  CHECK(same(b.bytes, bits));
  CHECK(same(d.application_context_name_list, ctx_list));
  CHECK(d.implementation_information == "openiec61850");
  REQUIRE(d.user_information.size() == 3);
  CHECK(d.user_information[0].direct_reference == acse::oids::ber_transfer_syntax);
  CHECK(d.user_information[0].indirect_reference == 1);
  CHECK(d.user_information[0].data_value_descriptor == "desc");
  CHECK(d.user_information[0].encoding == acse::external_encoding::octet_aligned);
  CHECK(same(d.user_information[0].data, octets));
  CHECK_FALSE(d.user_information[1].indirect_reference);
  CHECK(d.user_information[1].encoding == acse::external_encoding::arbitrary);
  CHECK(d.user_information[1].bit_count == 5);
  CHECK(same(d.user_information[1].data, bits));
  CHECK(d.user_information[2].indirect_reference == 3);
}

TEST_CASE("AARE with every field round-trips", "[acse]") {
  const byte_buffer other_value{0x04, 0x02, 0xAB, 0xCD};
  const byte_buffer ctx_list{0x06, 0x02, 0x28, 0x01};
  acse::aare_apdu a;
  a.protocol_version = acse::protocol_version::version1;
  a.application_context_name = acse::oids::mms_application_context;
  a.result = acse::associate_result::rejected_permanent;
  a.result_source_diagnostic = {acse::diagnostic_source::service_user,
                                acse::service_user_diagnostic::authentication_failure};
  a.responding_ap_title = ber::oid{1, 1, 999, 1};
  a.responding_ae_qualifier = std::int64_t{12};
  a.responding_ap_invocation_id = 5;
  a.responding_ae_invocation_id = 6;
  a.acse_requirements = acse::acse_requirements::authentication;
  a.mechanism_name = ber::oid{1, 2, 3, 4};
  a.authentication = acse::auth_other{ber::oid{1, 2, 3, 4}, other_value};
  a.application_context_name_list = ctx_list;
  a.implementation_information = "x";
  a.user_information.push_back(acse::single_asn1_external(3, initiate));
  const auto data = encoded(a);
  check_reencodes(data);
  const auto d = decode_as<acse::aare_apdu>(data);
  CHECK(d.result == acse::associate_result::rejected_permanent);
  CHECK(d.result_source_diagnostic.reason == acse::service_user_diagnostic::authentication_failure);
  CHECK(std::get<ber::oid>(*d.responding_ap_title) == ber::oid{1, 1, 999, 1});
  CHECK(std::get<std::int64_t>(*d.responding_ae_qualifier) == 12);
  CHECK(d.responding_ap_invocation_id == 5);
  CHECK(d.responding_ae_invocation_id == 6);
  CHECK(d.acse_requirements == acse::acse_requirements::authentication);
  const auto& o = std::get<acse::auth_other>(*d.authentication);
  CHECK(o.mechanism == ber::oid{1, 2, 3, 4});
  CHECK(same(o.value, other_value));
  CHECK(d.implementation_information == "x");
}

TEST_CASE("External authentication value and release user information round-trip", "[acse]") {
  acse::aarq_apdu a = reference_aarq();
  acse::external ext;
  ext.direct_reference = ber::oid{1, 2, 840};
  ext.encoding = acse::external_encoding::single_asn1_type;
  ext.data = initiate;
  a.authentication = acse::auth_external{ext};
  const auto data = encoded(a);
  check_reencodes(data);
  const auto d = decode_as<acse::aarq_apdu>(data);
  const auto& e = std::get<acse::auth_external>(*d.authentication).value;
  CHECK(e.direct_reference == ber::oid{1, 2, 840});
  CHECK(same(e.data, initiate));

  acse::rlrq_apdu rq;
  rq.reason = acse::release_request_reason::urgent;
  rq.user_information.push_back(acse::single_asn1_external(3, initiate));
  check_reencodes(encoded(rq));
  acse::rlre_apdu rp;
  rp.reason = acse::release_response_reason::user_defined;
  rp.user_information.push_back(acse::single_asn1_external(5, initiate));
  check_reencodes(encoded(rp));
  acse::abrt_apdu ab;
  ab.user_information.push_back(acse::single_asn1_external(5, initiate));
  const auto abd = encoded(ab);
  check_reencodes(abd);
  CHECK(decode_as<acse::abrt_apdu>(abd).user_information.at(0).indirect_reference == 5);
}

TEST_CASE("Unknown fields are skipped and indefinite lengths accepted", "[acse]") {
  // AARE with an unknown [20] field before user-information and an unknown [31] after it.
  byte_buffer data{0x61, 0x80,
                   0xA1, 0x07, 0x06, 0x05, 0x28, 0xCA, 0x22, 0x02, 0x03,
                   0xA2, 0x03, 0x02, 0x01, 0x00,
                   0xA3, 0x05, 0xA1, 0x03, 0x02, 0x01, 0x00,
                   0x94, 0x01, 0xFF,
                   0xBE, 0x80, 0x28, 0x80, 0x02, 0x01, 0x03, 0xA0, 0x80, 0xA8, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00,
                   0x9F, 0x1F, 0x00,
                   0x00, 0x00};
  const auto d = decode_as<acse::aare_apdu>(data);
  REQUIRE(d.user_information.size() == 1);
  CHECK(same(d.user_information[0].data, byte_buffer{0xA8, 0x00}));
}

TEST_CASE("Malformed APDUs are rejected", "[acse]") {
  auto fails_with = [](const byte_buffer& data, errc e) {
    auto r = acse::decode(data);
    REQUIRE_FALSE(r);
    CHECK(r.error() == e);
  };
  // Every truncation of the reference AARQ fails.
  for (std::size_t n = 0; n < aarq_vector.size(); ++n) {
    CHECK_FALSE(acse::decode(byte_view{aarq_vector}.first(n)));
  }
  byte_buffer trailing = aarq_vector;
  trailing.push_back(0x00);
  fails_with(trailing, errc::malformed_encoding);

  fails_with({0x30, 0x00}, errc::malformed_encoding);                 // not an APPLICATION tag
  fails_with({0x40, 0x00}, errc::malformed_encoding);                 // primitive AARQ
  fails_with({0x65, 0x00}, errc::unsupported);                        // A-DT
  fails_with({0x68, 0x00}, errc::malformed_encoding);                 // unknown APDU
  fails_with({0x60, 0x00}, errc::malformed_encoding);                 // AARQ without context
  fails_with({0x64, 0x00}, errc::malformed_encoding);                 // ABRT without source
  fails_with({0x61, 0x09, 0xA1, 0x07, 0x06, 0x05, 0x28, 0xCA, 0x22, 0x02, 0x03},
             errc::malformed_encoding);                               // AARE without result
  // Fields out of order, duplicated, or with the wrong form.
  fails_with({0x60, 0x0E, 0xA3, 0x03, 0x02, 0x01, 0x0C, 0xA1, 0x07, 0x06, 0x05, 0x28, 0xCA, 0x22,
              0x02, 0x03},
             errc::malformed_encoding);
  fails_with({0x62, 0x06, 0x80, 0x01, 0x00, 0x80, 0x01, 0x00}, errc::malformed_encoding);
  fails_with({0x60, 0x09, 0x81, 0x07, 0x06, 0x05, 0x28, 0xCA, 0x22, 0x02, 0x03},
             errc::malformed_encoding);
  fails_with({0x62, 0x02, 0x9E, 0x00}, errc::malformed_encoding);   // primitive user-information
  fails_with({0x62, 0x04, 0xBE, 0x02, 0x02, 0x00}, errc::malformed_encoding);  // not EXTERNAL
  // EXTERNAL without encoding, and single-ASN1-type holding two values.
  fails_with({0x62, 0x07, 0xBE, 0x05, 0x28, 0x03, 0x02, 0x01, 0x03}, errc::malformed_encoding);
  fails_with({0x62, 0x0A, 0xBE, 0x08, 0x28, 0x06, 0xA0, 0x04, 0x05, 0x00, 0x05, 0x00},
             errc::malformed_encoding);
  // Explicit tag with two elements inside (application context).
  fails_with({0x60, 0x0B, 0xA1, 0x09, 0x06, 0x05, 0x28, 0xCA, 0x22, 0x02, 0x03, 0x05, 0x00},
             errc::malformed_encoding);
  // Unknown authentication-value alternative.
  byte_buffer bad_auth{0x60, 0x0D, 0xA1, 0x07, 0x06, 0x05, 0x28, 0xCA, 0x22, 0x02, 0x03,
                       0xAC, 0x02, 0x85, 0x00};
  fails_with(bad_auth, errc::malformed_encoding);
  // Declared length beyond the buffer.
  fails_with({0x62, 0x7F, 0x80, 0x01, 0x00}, errc::length_overflow);
}

TEST_CASE("Deep nesting is bounded", "[acse]") {
  // ABRT carrying a deeply nested single-ASN1-type value.
  byte_buffer value;
  constexpr std::size_t levels = 100;
  for (std::size_t i = 0; i < levels; ++i) {
    value.push_back(0x30);
    value.push_back(0x80);
  }
  for (std::size_t i = 0; i < levels; ++i) {
    value.push_back(0x00);
    value.push_back(0x00);
  }
  acse::abrt_apdu ab;
  ab.user_information.push_back(acse::single_asn1_external(3, value));
  byte_buffer out;
  // An indefinite-length value deeper than the default limit is not even accepted as raw input.
  CHECK_FALSE(acse::encode(ab, out));
  CHECK(out.empty());
}

TEST_CASE("Encoders reject invalid input and leave the buffer unchanged", "[acse]") {
  byte_buffer out{0xEE};
  acse::aarq_apdu a = reference_aarq();
  a.application_context_name = ber::oid{};
  auto r = acse::encode(a, out);
  REQUIRE_FALSE(r);
  CHECK(r.error() == errc::invalid_state);
  CHECK(out == byte_buffer{0xEE});

  a = reference_aarq();
  a.user_information[0].data = {};
  CHECK(acse::encode(a, out).error() == errc::invalid_state);
  const byte_buffer two_values{0x05, 0x00, 0x05, 0x00};
  a.user_information[0].data = two_values;
  CHECK(acse::encode(a, out).error() == errc::invalid_state);
  a = reference_aarq();
  a.called_ap_title = acse::raw_form{two_values};
  CHECK(acse::encode(a, out).error() == errc::invalid_state);

  acse::aare_apdu e;
  e.application_context_name = acse::oids::mms_application_context;
  e.result_source_diagnostic.source = static_cast<acse::diagnostic_source>(3);
  CHECK(acse::encode(e, out).error() == errc::invalid_state);
  CHECK(out == byte_buffer{0xEE});
}

TEST_CASE("Long user information uses long-form lengths", "[acse]") {
  byte_buffer big{0x04, 0x82, 0x01, 0x2C};
  big.resize(4 + 300, 0x5A);
  acse::mms_aarq_params p;
  p.initiate_request = big;
  const auto data = encoded(acse::make_mms_aarq(p));
  CHECK(data[1] == 0x82);
  check_reencodes(data);
  const auto d = decode_as<acse::aarq_apdu>(data);
  CHECK(same(d.user_information.at(0).data, big));
}
