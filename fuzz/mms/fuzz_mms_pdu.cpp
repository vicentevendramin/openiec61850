// Decodes arbitrary input as an MMSpdu, iterates every lazy list and walks every Data value, then
// checks that encoding is a fixed point: encode(decode(x)) decodes and re-encodes to itself.
// Seed corpus: fuzz/corpus/mms_pdu/

#include <cstddef>
#include <cstdint>
#include <type_traits>
#include <variant>

#include "fuzz_util.hpp"
#include "openiec61850/mms/pdu.hpp"

namespace mms = openiec61850::mms;
using mms_fuzz::check;
using openiec61850::byte_buffer;
using openiec61850::byte_view;

namespace {

template <typename T>
std::size_t count(const mms::list_view<T>& l) {
  std::size_t n = 0;
  for (const auto& x : l) {
    (void)x;
    ++n;
  }
  check(n == l.size());
  check((n == 0) == l.empty());
  return n;
}

void visit_spec(const mms::variable_access_specification& s) { (void)count(s.variables); }

void visit_results(const mms::list_view<mms::access_result>& l) {
  for (const auto& r : l) {
    if (r.success()) mms_fuzz::walk(r.value.view());
  }
  (void)count(l);
}

template <typename T>
void visit_service(const T& s) {
  if constexpr (std::is_same_v<T, mms::get_name_list_response>) {
    (void)count(s.identifiers);
  } else if constexpr (std::is_same_v<T, mms::identify_response>) {
    for (const auto& o : s.abstract_syntaxes) (void)o.to_string();
  } else if constexpr (std::is_same_v<T, mms::read_request>) {
    visit_spec(s.spec);
  } else if constexpr (std::is_same_v<T, mms::read_response>) {
    if (s.spec) visit_spec(*s.spec);
    visit_results(s.results);
  } else if constexpr (std::is_same_v<T, mms::write_request>) {
    visit_spec(s.spec);
    for (const auto& d : s.values) mms_fuzz::walk(d.view());
  } else if constexpr (std::is_same_v<T, mms::write_response>) {
    (void)count(s.results);
  } else if constexpr (std::is_same_v<T, mms::get_named_variable_list_attributes_response> ||
                       std::is_same_v<T, mms::define_named_variable_list_request>) {
    (void)count(s.variables);
  } else if constexpr (std::is_same_v<T, mms::delete_named_variable_list_request>) {
    (void)count(s.names);
  } else if constexpr (std::is_same_v<T, mms::read_journal_request>) {
    if (s.variables) (void)count(*s.variables);
  } else if constexpr (std::is_same_v<T, mms::read_journal_response>) {
    for (const auto& e : s.entries) {
      for (const auto& v : e.variables) mms_fuzz::walk(v.value.view());
      (void)count(e.variables);
    }
    (void)count(s.entries);
  } else if constexpr (std::is_same_v<T, mms::file_open_request> ||
                       std::is_same_v<T, mms::file_delete_request>) {
    (void)count(s.file_name);
  } else if constexpr (std::is_same_v<T, mms::file_rename_request>) {
    (void)count(s.current_name);
    (void)count(s.new_name);
  } else if constexpr (std::is_same_v<T, mms::file_directory_request>) {
    if (s.file_specification) (void)count(*s.file_specification);
    if (s.continue_after) (void)count(*s.continue_after);
  } else if constexpr (std::is_same_v<T, mms::obtain_file_request>) {
    (void)count(s.source_file);
    (void)count(s.destination_file);
  } else if constexpr (std::is_same_v<T, mms::file_directory_response>) {
    for (const auto& e : s.entries) (void)count(e.file_name);
    (void)count(s.entries);
  }
}

void visit(const mms::mms_pdu& pdu) {
  (void)mms::invoke_id(pdu);
  if (const auto* req = std::get_if<mms::confirmed_request>(&pdu)) {
    (void)mms::service_tag(req->service);
    std::visit([](const auto& s) { visit_service(s); }, req->service);
  } else if (const auto* resp = std::get_if<mms::confirmed_response>(&pdu)) {
    (void)mms::service_tag(resp->service);
    std::visit([](const auto& s) { visit_service(s); }, resp->service);
  } else if (const auto* u = std::get_if<mms::unconfirmed_pdu>(&pdu)) {
    if (const auto* report = std::get_if<mms::information_report>(&u->service)) {
      visit_spec(report->spec);
      visit_results(report->results);
    }
  }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  const byte_view input{data, size};
  (void)mms::peek_invoke_id(input);
  (void)mms::decode_pdu(input, {.max_nesting = 3});
  auto pdu = mms::decode_pdu(input);
  if (!pdu) return 0;
  visit(*pdu);

  byte_buffer first;
  check(static_cast<bool>(mms::encode_pdu(*pdu, first)));
  auto again = mms::decode_pdu(first, {.max_nesting = 1024});
  check(again.has_value());
  check(again->index() == pdu->index());
  byte_buffer second;
  check(static_cast<bool>(mms::encode_pdu(*again, second)));
  check(first == second);
  return 0;
}
