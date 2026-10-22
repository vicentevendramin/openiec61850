#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstdint>
#include <string_view>
#include <vector>

#include "mms_test_util.hpp"
#include "openiec61850/mms/pdu.hpp"

namespace mms = openiec61850::mms;
using mms_test::hex;
using openiec61850::byte_buffer;
using openiec61850::byte_view;
using openiec61850::errc;

namespace {

byte_buffer encode(const mms::mms_pdu& pdu) {
  byte_buffer out;
  REQUIRE(mms::encode_pdu(pdu, out));
  return out;
}

template <typename T>
T decode_as(byte_view bytes) {
  auto r = mms::decode_pdu(bytes);
  REQUIRE(r);
  REQUIRE(std::holds_alternative<T>(*r));
  return std::get<T>(*r);
}

template <typename S>
S request_service(byte_view bytes, std::uint32_t invoke_id) {
  const auto pdu = decode_as<mms::confirmed_request>(bytes);
  CHECK(pdu.invoke_id == invoke_id);
  REQUIRE(std::holds_alternative<S>(pdu.service));
  return std::get<S>(pdu.service);
}

template <typename S>
S response_service(byte_view bytes, std::uint32_t invoke_id) {
  const auto pdu = decode_as<mms::confirmed_response>(bytes);
  CHECK(pdu.invoke_id == invoke_id);
  REQUIRE(std::holds_alternative<S>(pdu.service));
  return std::get<S>(pdu.service);
}

// Every strict prefix must be rejected, and decoding then re-encoding must be the identity.
void check_canonical(const byte_buffer& bytes) {
  auto pdu = mms::decode_pdu(bytes);
  REQUIRE(pdu);
  CHECK(encode(*pdu) == bytes);
  for (std::size_t n = 0; n < bytes.size(); ++n) {
    CHECK_FALSE(mms::decode_pdu(byte_view{bytes.data(), n}));
  }
  byte_buffer longer = bytes;
  longer.push_back(0);
  CHECK(mms::decode_pdu(longer).error() == errc::malformed_encoding);
}

// Initiate-RequestPDU as sent by an IEC 61850 client: localDetailCalling 65000, 5/5 outstanding
// requests, nesting level 10, version 1, CBB str1 str2 vnam valt vlis, 85 service bits.
const byte_buffer initiate_request_vector = hex(
    "A8 26 80 03 00 FD E8 81 01 05 82 01 05 83 01 0A A4 16 80 01 01 81 03 05 F1 00"
    " 82 0C 03 6E 1C 00 00 00 00 00 00 00 01 18");

const byte_buffer get_name_list_request_vector =
    hex("A0 15 02 01 01 A1 10 A0 03 80 01 00 A1 09 81 07 'IED1LD0'");

const byte_buffer get_name_list_response_vector =
    hex("A1 17 02 01 01 A1 12 A0 0D 1A 04 'LLN0' 1A 05 'LPHD1' 81 01 00");

const byte_buffer read_request_vector =
    hex("A0 27 02 01 02 A4 22 A1 20 A0 1E 30 1C A0 1A A1 18 1A 07 'IED1LD0' 1A 0D 'MMXU1$MX$TotW'");

// MV {mag {f = 123.5}, q = test bit... (bit 12), t = 1600000000.5 s, accuracy 10}
const byte_buffer read_response_vector = hex(
    "A1 21 02 01 02 A4 1C A1 1A A2 18 A2 07 87 05 08 42 F7 00 00 84 03 03 00 08"
    " 91 08 5F 5E 10 00 80 00 00 0A");

const byte_buffer write_request_vector = hex(
    "A0 2D 02 01 03 A5 28 A0 21 30 1F A0 1D A1 1B 1A 07 'IED1LD0' 1A 10 'LLN0$DC$NamPlt$d'"
    " A0 03 83 01 FF");

const byte_buffer write_response_vector = hex("A1 0A 02 01 03 A5 05 81 00 80 01 03");

const byte_buffer information_report_vector = hex(
    "A3 18 A0 16 A1 05 80 03 'RPT' A0 0D 8A 03 'rcb' 84 03 06 40 00 85 01 05");

const byte_buffer reject_vector = hex("A4 06 80 01 05 81 01 01");

const byte_buffer gvaa_request_vector =
    hex("A0 18 02 01 04 A6 13 A0 11 A1 0F 1A 07 'IED1LD0' 1A 04 'LLN0'");

const byte_buffer gvaa_response_vector = hex(
    "A1 2E 02 01 04 A6 29 80 01 00 A2 24 A2 22 A1 20 30 0B 80 05 'stVal' A1 02 83 00"
    " 30 08 80 01 'q' A1 03 84 01 0D 30 07 80 01 't' A1 02 91 00");

}  // namespace

TEST_CASE("Initiate-Request known answer", "[mms]") {
  CHECK(encode(mms::initiate_request{}) == initiate_request_vector);
  const auto req = decode_as<mms::initiate_request>(initiate_request_vector);
  CHECK(req.local_detail_calling == 65000);
  CHECK(req.max_serv_outstanding_calling == 5);
  CHECK(req.max_serv_outstanding_called == 5);
  CHECK(req.data_structure_nesting_level == 10);
  CHECK(req.detail.version_number == 1);
  CHECK(req.detail.parameter_cbb == mms::iec61850_parameter_cbb);
  CHECK(req.detail.services == mms::iec61850_services);
  CHECK(req.detail.services.test(mms::service_bit::read));
  CHECK(req.detail.services.test(mms::service_bit::information_report));
  CHECK_FALSE(req.detail.services.test(mms::service_bit::status));
  CHECK(req.detail.services.bit_count() == 85);
  check_canonical(initiate_request_vector);
}

TEST_CASE("Initiate-Response round trip and negotiation", "[mms]") {
  mms::initiate_response resp;
  resp.local_detail_called.reset();
  resp.data_structure_nesting_level.reset();
  resp.max_serv_outstanding_calling = 10;
  resp.detail.services = mms::iec61850_services.intersect(
      mms::support_options{mms::service_bit::bit_count, {mms::service_bit::read}});
  const auto bytes = encode(resp);
  CHECK(bytes[0] == 0xA9);
  const auto back = decode_as<mms::initiate_response>(bytes);
  CHECK_FALSE(back.local_detail_called);
  CHECK_FALSE(back.data_structure_nesting_level);
  CHECK(back.max_serv_outstanding_calling == 10);
  CHECK(back.detail.services.test(mms::service_bit::read));
  CHECK_FALSE(back.detail.services.test(mms::service_bit::write));
  check_canonical(bytes);
}

TEST_CASE("Initiate decoding ignores unknown service bits and checks ranges", "[mms]") {
  // 136 service bits (more than support_options::max_bits).
  auto big = hex("A8 2A 81 01 05 82 01 05 A4 22 80 01 01 81 03 05 F1 00 82 18 00"
                 " FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF");
  big[1] = static_cast<std::uint8_t>(big.size() - 2);
  big[9] = static_cast<std::uint8_t>(big.size() - 10);
  const auto req = decode_as<mms::initiate_request>(big);
  CHECK(req.detail.services.bit_count() == mms::support_options::max_bits);
  CHECK(req.detail.services.test(127));
  CHECK_FALSE(req.local_detail_calling);

  // proposedMaxServOutstandingCalling does not fit Integer16.
  CHECK(mms::decode_pdu(hex("A8 13 81 03 01 00 00 82 01 05 A4 09 80 01 01 81 01 00 82 01 00"))
            .error() == errc::value_out_of_range);
}

TEST_CASE("GetNameList known answers", "[mms]") {
  mms::get_name_list_request req;
  req.cls = mms::object_class::named_variable;
  req.scope = mms::object_scope::domain_specific;
  req.domain_id = "IED1LD0";
  CHECK(encode(mms::confirmed_request{1, {}, req}) == get_name_list_request_vector);

  const auto d = request_service<mms::get_name_list_request>(get_name_list_request_vector, 1);
  CHECK(d.cls == mms::object_class::named_variable);
  CHECK(d.scope == mms::object_scope::domain_specific);
  CHECK(d.domain_id == "IED1LD0");
  CHECK_FALSE(d.continue_after);
  check_canonical(get_name_list_request_vector);

  const std::array<std::string_view, 2> ids{"LLN0", "LPHD1"};
  CHECK(encode(mms::confirmed_response{1, mms::get_name_list_response{ids, false}}) ==
        get_name_list_response_vector);
  const auto r = response_service<mms::get_name_list_response>(get_name_list_response_vector, 1);
  CHECK_FALSE(r.more_follows);
  CHECK(r.identifiers.is_encoded());
  CHECK(std::vector<std::string_view>(r.identifiers.begin(), r.identifiers.end()) ==
        std::vector<std::string_view>{"LLN0", "LPHD1"});
  check_canonical(get_name_list_response_vector);
}

TEST_CASE("GetNameList variants", "[mms]") {
  mms::get_name_list_request req;
  req.cls = mms::object_class::domain;
  req.continue_after = "LD3";
  const auto bytes = encode(mms::confirmed_request{7, {}, req});
  CHECK(bytes == hex("A0 13 02 01 07 A1 0E A0 03 80 01 09 A1 02 80 00 82 03 'LD3'"));
  const auto d = request_service<mms::get_name_list_request>(bytes, 7);
  CHECK(d.cls == mms::object_class::domain);
  CHECK(d.scope == mms::object_scope::vmd_specific);
  CHECK(d.continue_after == "LD3");

  req.scope = mms::object_scope::aa_specific;
  req.continue_after.reset();
  const auto aa = request_service<mms::get_name_list_request>(
      encode(mms::confirmed_request{8, {}, req}), 8);
  CHECK(aa.scope == mms::object_scope::aa_specific);

  // moreFollows absent: DEFAULT TRUE.
  const auto one = hex("A1 0B 02 01 01 A1 06 A0 04 1A 02 'LD'");
  const auto r = response_service<mms::get_name_list_response>(one, 1);
  CHECK(r.more_follows);
  CHECK(r.identifiers.size() == 1);
}

TEST_CASE("Read request and response known answers", "[mms]") {
  const std::array<mms::variable_spec, 1> vars{mms::object_name::domain("IED1LD0", "MMXU1$MX$TotW")};
  mms::read_request req;
  req.spec = mms::variable_access_specification::list(vars);
  CHECK(encode(mms::confirmed_request{2, {}, req}) == read_request_vector);

  const auto d = request_service<mms::read_request>(read_request_vector, 2);
  CHECK_FALSE(d.specification_with_result);
  REQUIRE(d.spec.type == mms::variable_access_specification::kind::list_of_variable);
  REQUIRE(d.spec.variables.size() == 1);
  const auto& v = *d.spec.variables.begin();
  CHECK(v.name == mms::object_name::domain("IED1LD0", "MMXU1$MX$TotW"));
  CHECK(v.alternate_access.empty());
  check_canonical(read_request_vector);

  // Build the response from owned values.
  const byte_buffer q{0x00, 0x08};
  const std::vector<mms::data> values{mms::data::structure({
      mms::data::structure({mms::data::floating_point(123.5F)}),
      mms::data::bit_string(q, 13),
      mms::data::utc_time({1'600'000'000, 0x800000, 10}),
  })};
  CHECK(encode(mms::confirmed_response{2, mms::read_response{std::nullopt, values}}) ==
        read_response_vector);

  const auto r = response_service<mms::read_response>(read_response_vector, 2);
  CHECK_FALSE(r.spec);
  REQUIRE(r.results.size() == 1);
  const auto& result = *r.results.begin();
  REQUIRE(result.success());
  const auto& mv = result.value.view();
  REQUIRE(mv.type() == mms::data_type::structure);
  CHECK(*mv.at(0)->at(0)->as_float() == 123.5F);
  CHECK(mv.at(1)->as_bit_string()->test(12));
  CHECK(mv.at(2)->as_utc_time()->fraction == 0x800000U);
  CHECK(*mms::data::from_view(mv) == values[0]);
  check_canonical(read_response_vector);
}

TEST_CASE("Read with a named variable list, specificationWithResult and failures", "[mms]") {
  mms::read_request req;
  req.specification_with_result = true;
  req.spec = mms::variable_access_specification::named(mms::object_name::domain("LD0", "LLN0$DS"));
  const auto bytes = encode(mms::confirmed_request{9, {}, req});
  const auto d = request_service<mms::read_request>(bytes, 9);
  CHECK(d.specification_with_result);
  CHECK(d.spec.type == mms::variable_access_specification::kind::variable_list_name);
  CHECK(d.spec.list_name == mms::object_name::domain("LD0", "LLN0$DS"));
  check_canonical(bytes);

  const auto value = mms::data::integer(3);
  const std::array<mms::access_result, 2> results{mms::access_result{value},
                                                  mms::data_access_error::object_non_existent};
  const auto resp = encode(mms::confirmed_response{9, mms::read_response{d.spec, results}});
  const auto r = response_service<mms::read_response>(resp, 9);
  REQUIRE(r.spec);
  CHECK(r.spec->list_name == mms::object_name::domain("LD0", "LLN0$DS"));
  std::vector<mms::access_result> got(r.results.begin(), r.results.end());
  REQUIRE(got.size() == 2);
  CHECK(*got[0].value.view().as_int64() == 3);
  CHECK(got[1].failure == mms::data_access_error::object_non_existent);
  check_canonical(resp);
}

TEST_CASE("Alternate access is carried opaque", "[mms]") {
  const auto bytes = hex(
      "A0 1A 02 01 01 A4 15 A1 13 A0 11 30 0F A0 06 80 04 'LLN0' A5 05 80 03 'Mod'");
  const auto d = request_service<mms::read_request>(bytes, 1);
  const auto& v = *d.spec.variables.begin();
  CHECK(v.name == mms::object_name::vmd("LLN0"));
  CHECK(v.alternate_access.size() == 5);
  check_canonical(bytes);
}

TEST_CASE("Write request and response known answers", "[mms]") {
  const std::array<mms::variable_spec, 1> vars{mms::object_name::domain("IED1LD0", "LLN0$DC$NamPlt$d")};
  const std::array<mms::data, 1> values{mms::data::boolean(true)};
  const mms::write_request req{mms::variable_access_specification::list(vars), values};
  CHECK(encode(mms::confirmed_request{3, {}, req}) == write_request_vector);

  const auto d = request_service<mms::write_request>(write_request_vector, 3);
  REQUIRE(d.values.size() == 1);
  CHECK(*d.values.begin()->view().as_boolean());
  check_canonical(write_request_vector);

  const std::array<mms::write_result, 2> results{mms::write_result{},
                                                 mms::data_access_error::object_access_denied};
  CHECK(encode(mms::confirmed_response{3, mms::write_response{results}}) == write_response_vector);
  const auto r = response_service<mms::write_response>(write_response_vector, 3);
  std::vector<mms::write_result> got(r.results.begin(), r.results.end());
  REQUIRE(got.size() == 2);
  CHECK(got[0].success());
  CHECK(got[1].failure == mms::data_access_error::object_access_denied);
  check_canonical(write_response_vector);
}

TEST_CASE("InformationReport known answer", "[mms]") {
  const std::vector<mms::data> values{mms::data::visible_string("rcb"),
                                      mms::data::bit_string(hex("40 00"), 10),
                                      mms::data::integer(5)};
  const mms::information_report report{
      mms::variable_access_specification::named(mms::object_name::vmd("RPT")), values};
  CHECK(encode(mms::unconfirmed_pdu{report}) == information_report_vector);

  const auto pdu = decode_as<mms::unconfirmed_pdu>(information_report_vector);
  REQUIRE(std::holds_alternative<mms::information_report>(pdu.service));
  const auto& r = std::get<mms::information_report>(pdu.service);
  CHECK(r.spec.type == mms::variable_access_specification::kind::variable_list_name);
  CHECK(r.spec.list_name == mms::object_name::vmd("RPT"));
  std::vector<mms::data_type> types;
  for (const auto& x : r.results) types.push_back(x.value.type());
  CHECK(types == std::vector{mms::data_type::visible_string, mms::data_type::bit_string,
                             mms::data_type::integer});
  CHECK(*r.results.begin()->value.view().as_visible_string() == "rcb");
  CHECK_FALSE(mms::invoke_id(pdu));
  check_canonical(information_report_vector);
}

TEST_CASE("InformationReport with listOfVariable", "[mms]") {
  const std::array<mms::variable_spec, 1> vars{mms::object_name::vmd("RPT")};
  const std::array<mms::data, 1> values{mms::data::integer(1)};
  const mms::information_report report{mms::variable_access_specification::list(vars), values};
  const auto bytes = encode(mms::unconfirmed_pdu{report});
  CHECK(bytes == hex("A3 12 A0 10 A0 09 30 07 A0 05 80 03 'RPT' A0 03 85 01 01"));
  const auto pdu = decode_as<mms::unconfirmed_pdu>(bytes);
  const auto& r = std::get<mms::information_report>(pdu.service);
  CHECK(r.spec.variables.begin()->name == mms::object_name::vmd("RPT"));
  check_canonical(bytes);
}

TEST_CASE("RejectPDU known answer", "[mms]") {
  const mms::reject_pdu rej{5, mms::reject_type::confirmed_request,
                            mms::reject_code::confirmed_request::unrecognized_service};
  CHECK(encode(rej) == reject_vector);
  const auto d = decode_as<mms::reject_pdu>(reject_vector);
  CHECK(d.original_invoke_id == 5U);
  CHECK(d.type == mms::reject_type::confirmed_request);
  CHECK(d.reason == 1);
  CHECK(mms::invoke_id(mms::mms_pdu{d}) == 5U);
  check_canonical(reject_vector);

  const auto no_id = encode(mms::reject_pdu{std::nullopt, mms::reject_type::pdu_error,
                                            mms::reject_code::pdu_error::invalid_pdu});
  CHECK(no_id == hex("A4 03 85 01 01"));
  CHECK_FALSE(decode_as<mms::reject_pdu>(no_id).original_invoke_id);
  CHECK(mms::decode_pdu(hex("A4 03 8C 01 01")).error() == errc::malformed_encoding);
}

TEST_CASE("Confirmed-ErrorPDU and ServiceError", "[mms]") {
  mms::confirmed_error err;
  err.invoke_id = 7;
  err.error.cls = mms::error_class::access;
  err.error.code = mms::error_code::access::object_non_existent;
  const auto bytes = encode(err);
  CHECK(bytes == hex("A2 0A 80 01 07 A2 05 A0 03 87 01 02"));
  const auto d = decode_as<mms::confirmed_error>(bytes);
  CHECK(d.invoke_id == 7U);
  CHECK(d.error.cls == mms::error_class::access);
  CHECK(d.error.code == 2);
  check_canonical(bytes);

  mms::service_error full;
  full.cls = mms::error_class::file;
  full.code = mms::error_code::file::file_non_existent;
  full.additional_code = -3;
  full.additional_description = "no such file";
  const auto info = hex("80 01 00");
  full.service_specific_info = info;
  const auto ce = encode(mms::cancel_error{4, full});
  const auto c = decode_as<mms::cancel_error>(ce);
  CHECK(c.invoke_id == 4U);
  CHECK(c.error.cls == mms::error_class::file);
  CHECK(c.error.additional_code == -3);
  CHECK(c.error.additional_description == "no such file");
  CHECK(c.error.service_specific_info.size() == 3);
  check_canonical(ce);

  const auto ie = encode(mms::initiate_error{{mms::error_class::initiate,
                                              mms::error_code::initiate::nesting_level_insufficient}});
  CHECK(ie == hex("AA 05 A0 03 88 01 07"));
  CHECK(decode_as<mms::initiate_error>(ie).error.code == 7);
  CHECK(mms::decode_pdu(hex("AA 05 A0 03 8D 01 07")).error() == errc::malformed_encoding);
}

TEST_CASE("Cancel and Conclude PDUs", "[mms]") {
  CHECK(encode(mms::cancel_request{9}) == hex("85 01 09"));
  CHECK(encode(mms::cancel_response{9}) == hex("86 01 09"));
  CHECK(encode(mms::conclude_request{}) == hex("8B 00"));
  CHECK(encode(mms::conclude_response{}) == hex("8C 00"));
  CHECK(decode_as<mms::cancel_request>(hex("85 01 09")).invoke_id == 9U);
  CHECK(decode_as<mms::cancel_response>(hex("86 01 09")).invoke_id == 9U);
  CHECK(mms::invoke_id(*mms::decode_pdu(hex("85 01 09"))) == 9U);
  CHECK(mms::type_of(*mms::decode_pdu(hex("8B 00"))) == mms::pdu_type::conclude_request);
  CHECK(mms::type_of(*mms::decode_pdu(hex("8C 00"))) == mms::pdu_type::conclude_response);
  const auto ce = encode(mms::conclude_error{{mms::error_class::conclude, 1}});
  CHECK(ce == hex("AD 05 A0 03 89 01 01"));
  CHECK(decode_as<mms::conclude_error>(ce).error.cls == mms::error_class::conclude);
  CHECK(mms::decode_pdu(hex("8B 01 00")).error() == errc::malformed_encoding);
  CHECK(mms::decode_pdu(hex("A5 03 02 01 01")).error() == errc::malformed_encoding);
}

TEST_CASE("Identify", "[mms]") {
  const auto req = hex("A0 05 02 01 01 82 00");
  CHECK(encode(mms::confirmed_request{1, {}, mms::identify_request{}}) == req);
  (void)request_service<mms::identify_request>(req, 1);

  const std::array<openiec61850::ber::oid, 1> syntaxes{{{1, 0, 9506, 2, 1}}};
  const auto resp = encode(mms::confirmed_response{
      1, mms::identify_response{"openiec61850", "server", "0.1", syntaxes}});
  const auto d = response_service<mms::identify_response>(resp, 1);
  CHECK(d.vendor_name == "openiec61850");
  CHECK(d.model_name == "server");
  CHECK(d.revision == "0.1");
  REQUIRE(d.abstract_syntaxes.size() == 1);
  CHECK(*d.abstract_syntaxes.begin() == openiec61850::ber::oid{1, 0, 9506, 2, 1});
  check_canonical(resp);
  const auto plain = encode(mms::confirmed_response{1, mms::identify_response{"a", "b", "c", {}}});
  CHECK(plain == hex("A1 0E 02 01 01 A2 09 80 01 'a' 81 01 'b' 82 01 'c'"));
}

TEST_CASE("GetVariableAccessAttributes known answers", "[mms]") {
  const mms::get_variable_access_attributes_request req{mms::object_name::domain("IED1LD0", "LLN0")};
  CHECK(encode(mms::confirmed_request{4, {}, req}) == gvaa_request_vector);
  CHECK(request_service<mms::get_variable_access_attributes_request>(gvaa_request_vector, 4).name ==
        req.name);
  check_canonical(gvaa_request_vector);

  using td = mms::type_description;
  mms::get_variable_access_attributes_response resp;
  resp.type = td::structure({{"stVal", td::boolean()}, {"q", td::bit_string(13)}, {"t", td::utc_time()}});
  CHECK(encode(mms::confirmed_response{4, resp}) == gvaa_response_vector);
  const auto d =
      response_service<mms::get_variable_access_attributes_response>(gvaa_response_vector, 4);
  CHECK_FALSE(d.mms_deletable);
  CHECK(d.type == resp.type);
  REQUIRE(d.type.components.size() == 3);
  CHECK(d.type.components[1].name == "q");
  CHECK(d.type.components[1].type.size == 13);
  check_canonical(gvaa_response_vector);

  // address [1] and the optional trailing fields are skipped.
  const auto with_address = hex("A1 12 02 01 04 A6 0D 80 01 FF A1 02 80 00 A2 02 83 00 83 00");
  const auto a = response_service<mms::get_variable_access_attributes_response>(with_address, 4);
  CHECK(a.mms_deletable);
  CHECK(a.type.type == mms::data_type::boolean);

  CHECK(mms::decode_pdu(hex("A0 0A 02 01 04 A6 05 A1 03 80 01 00")).error() == errc::unsupported);
}

TEST_CASE("Named variable list services", "[mms]") {
  const std::array<mms::variable_spec, 2> vars{mms::object_name::domain("LD0", "MMXU1$MX$A"),
                                               mms::object_name::domain("LD0", "MMXU1$MX$PhV")};
  const auto name = mms::object_name::domain("LD0", "LLN0$DS1");

  const auto define = encode(mms::confirmed_request{
      10, {}, mms::define_named_variable_list_request{name, vars}});
  const auto dr = request_service<mms::define_named_variable_list_request>(define, 10);
  CHECK(dr.name == name);
  CHECK(dr.variables.size() == 2);
  check_canonical(define);
  const auto define_resp = encode(mms::confirmed_response{10, mms::define_named_variable_list_response{}});
  CHECK(define_resp == hex("A1 05 02 01 0A 8B 00"));
  (void)response_service<mms::define_named_variable_list_response>(define_resp, 10);

  const auto get = encode(mms::confirmed_request{11, {}, mms::get_named_variable_list_attributes_request{name}});
  CHECK(get == hex("A0 16 02 01 0B AC 11 A1 0F 1A 03 'LD0' 1A 08 'LLN0$DS1'"));
  CHECK(request_service<mms::get_named_variable_list_attributes_request>(get, 11).name == name);
  check_canonical(get);
  const auto get_resp = encode(mms::confirmed_response{
      11, mms::get_named_variable_list_attributes_response{true, vars}});
  const auto gr = response_service<mms::get_named_variable_list_attributes_response>(get_resp, 11);
  CHECK(gr.mms_deletable);
  std::vector<mms::variable_spec> got(gr.variables.begin(), gr.variables.end());
  REQUIRE(got.size() == 2);
  CHECK(got[1].name == vars[1].name);
  check_canonical(get_resp);

  const std::array<mms::object_name, 1> names{name};
  mms::delete_named_variable_list_request del;
  del.names = names;
  const auto delete_req = encode(mms::confirmed_request{12, {}, del});
  CHECK(delete_req == hex("A0 18 02 01 0C AD 13 A1 11 A1 0F 1A 03 'LD0' 1A 08 'LLN0$DS1'"));
  const auto dd = request_service<mms::delete_named_variable_list_request>(delete_req, 12);
  CHECK(dd.scope == mms::delete_scope::specific);
  CHECK(*dd.names.begin() == name);
  check_canonical(delete_req);

  mms::delete_named_variable_list_request by_domain;
  by_domain.scope = mms::delete_scope::domain;
  by_domain.domain_name = "LD0";
  const auto by_domain_bytes = encode(mms::confirmed_request{13, {}, by_domain});
  const auto bd = request_service<mms::delete_named_variable_list_request>(by_domain_bytes, 13);
  CHECK(bd.scope == mms::delete_scope::domain);
  CHECK(bd.domain_name == "LD0");
  CHECK(bd.names.empty());

  const auto delete_resp =
      encode(mms::confirmed_response{12, mms::delete_named_variable_list_response{1, 1}});
  CHECK(delete_resp == hex("A1 0B 02 01 0C AD 06 80 01 01 81 01 01"));
  const auto dresp = response_service<mms::delete_named_variable_list_response>(delete_resp, 12);
  CHECK(dresp.number_matched == 1U);
  CHECK(dresp.number_deleted == 1U);
}

TEST_CASE("Unimplemented services decode as other_service", "[mms]") {
  // fileDirectory [77] request with an empty SEQUENCE.
  const auto bytes = hex("A0 06 02 01 01 BF 4D 00");
  const auto pdu = decode_as<mms::confirmed_request>(bytes);
  REQUIRE(std::holds_alternative<mms::other_service>(pdu.service));
  CHECK(std::get<mms::other_service>(pdu.service).tag == 77U);
  CHECK(mms::service_tag(pdu.service) == 77U);
  CHECK(encode(pdu) == bytes);
  CHECK(mms::service_tag(mms::confirmed_service_request{mms::read_request{}}) == 4U);
  CHECK(mms::service_tag(mms::confirmed_service_response{mms::get_named_variable_list_attributes_response{}}) == 12U);

  const auto unconfirmed = hex("A3 02 81 00");
  const auto u = decode_as<mms::unconfirmed_pdu>(unconfirmed);
  REQUIRE(std::holds_alternative<mms::other_service>(u.service));
  CHECK(encode(u) == unconfirmed);
}

TEST_CASE("Invoke IDs", "[mms]") {
  const auto max = encode(mms::confirmed_request{0xFFFFFFFF, {}, mms::identify_request{}});
  CHECK(max == hex("A0 09 02 05 00 FF FF FF FF 82 00"));
  CHECK(decode_as<mms::confirmed_request>(max).invoke_id == 0xFFFFFFFFU);
  CHECK(mms::decode_pdu(hex("A0 09 02 05 01 00 00 00 00 82 00")).error() == errc::value_out_of_range);
  CHECK(mms::decode_pdu(hex("A0 05 02 01 FF 82 00")).error() == errc::value_out_of_range);

  // The invokeID can be recovered from a request whose service is malformed.
  const auto bad = hex("A0 05 02 01 07 A4 00");
  CHECK_FALSE(mms::decode_pdu(bad));
  CHECK(*mms::peek_invoke_id(bad) == 7U);
  CHECK(*mms::peek_invoke_id(write_response_vector) == 3U);
  CHECK(*mms::peek_invoke_id(hex("A2 0A 80 01 07 A2 05 A0 03 87 01 02")) == 7U);
  CHECK_FALSE(mms::peek_invoke_id(information_report_vector));
  CHECK(mms::invoke_id(*mms::decode_pdu(read_request_vector)) == 2U);
}

TEST_CASE("Modifiers and service-ext are carried or skipped", "[mms]") {
  const auto with_modifier = hex("A0 07 02 01 01 30 00 82 00");
  CHECK(mms::decode_pdu(with_modifier));
  const auto pdu = decode_as<mms::confirmed_request>(with_modifier);
  CHECK(pdu.modifiers.empty());
  const auto with_ext = hex("A0 08 02 01 01 82 00 BF 4F 00");
  CHECK(decode_as<mms::confirmed_request>(with_ext).invoke_id == 1U);
  const auto modifier = hex("A0 0A 02 01 01 30 03 80 01 00 82 00");
  const auto m = decode_as<mms::confirmed_request>(modifier);
  CHECK(m.modifiers.size() == 3);
  CHECK(encode(m) == modifier);
}

TEST_CASE("Malformed PDUs are rejected", "[mms]") {
  auto err = [](std::string_view h) { return mms::decode_pdu(hex(h)).error(); };
  CHECK(err("AE 00") == errc::unsupported);              // [14]
  CHECK(err("30 00") == errc::malformed_encoding);       // universal class
  CHECK(err("80 00") == errc::malformed_encoding);       // primitive confirmed request
  CHECK(err("A0 03 02 01 01") == errc::truncated_input);  // no service
  CHECK(err("A0 06 02 01 01 82 00 00") != std::error_code{});
  // Read: specificationWithResult must be BOOLEAN, VariableSpecification address unsupported.
  CHECK(err("A0 0A 02 01 01 A4 05 80 00 A1 01 00") != std::error_code{});
  CHECK(err("A0 0E 02 01 01 A4 09 A1 07 A0 05 30 03 81 01 00") == errc::unsupported);
  // ObjectName with a bad alternative.
  CHECK(err("A0 0E 02 01 01 A4 09 A1 07 A1 05 83 03 'RPT'") == errc::malformed_encoding);
  // Data in a report nested beyond the limit.
  CHECK(mms::decode_pdu(hex("A3 12 A0 10 A1 05 80 03 'RPT' A0 07 A2 05 A2 03 A2 01 00"),
                        {.max_nesting = 2})
            .error() != std::error_code{});
  CHECK(mms::decode_pdu(hex("A3 12 A0 10 A1 05 80 03 'RPT' A0 07 A2 05 A2 03 A2 00 00"),
                        {.max_nesting = 2})
            .error() == errc::nesting_too_deep);
  // Write response element neither [0] nor [1].
  CHECK(err("A1 07 02 01 01 A5 02 82 00") == errc::malformed_encoding);
  // Invalid DataAccessError.
  CHECK(err("A1 08 02 01 01 A5 03 80 01 FF") == errc::value_out_of_range);
}

TEST_CASE("Encoding failures leave the buffer unchanged", "[mms]") {
  const std::array<mms::data, 1> values{mms::data{}};
  const mms::information_report report{
      mms::variable_access_specification::named(mms::object_name::vmd("RPT")), values};
  byte_buffer out{0x01, 0x02};
  CHECK(mms::encode_pdu(mms::unconfirmed_pdu{report}, out).error() == errc::invalid_state);
  CHECK(out == byte_buffer{0x01, 0x02});

  mms::get_variable_access_attributes_response resp;
  resp.type.type = mms::data_type::array;  // no element type
  CHECK(mms::encode_pdu(mms::confirmed_response{1, resp}, out).error() == errc::invalid_state);
  CHECK(out == byte_buffer{0x01, 0x02});
}
