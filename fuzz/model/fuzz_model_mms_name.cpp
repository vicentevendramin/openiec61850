// Reverse MMS name mapping: the input is "domain \0 item \0 AlternateAccess-contents"; the whole
// input is also tried as a textual MMS reference. Accepted names must map back consistently.
// Seed corpus: fuzz/corpus/model_mms_name/

#include <cstddef>
#include <cstdint>
#include <string_view>

#include "openiec61850/model/mms_mapping.hpp"

namespace model = openiec61850::model;
namespace mms = openiec61850::mms;

namespace {

void check(bool condition) {
  if (!condition) __builtin_trap();
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  const std::string_view input{reinterpret_cast<const char*>(data), size};
  const auto first = input.find('\0');
  const auto domain = input.substr(0, first);
  std::string_view item;
  openiec61850::byte_view alt;
  if (first != std::string_view::npos) {
    const auto rest = input.substr(first + 1);
    const auto second = rest.find('\0');
    item = rest.substr(0, second);
    if (second != std::string_view::npos) {
      alt = openiec61850::byte_view{data + first + 1 + second + 1, rest.size() - second - 1};
    }
  }

  const auto name = mms::object_name::domain(domain, item);
  for (const auto& opts : {model::parse_options_for(model::edition::ed1),
                           model::parse_options{model::name_limits::unlimited(), false}}) {
    if (auto r = model::from_mms_variable(name, alt, opts)) {
      // Without AlternateAccess the mapping is a bijection. A component selected through
      // AlternateAccess maps back into the item id, which may then exceed the limits.
      auto v = model::to_mms_variable(*r, opts.limits);
      if (alt.empty()) {
        check(v.has_value() && v->name.view() == name && v->alternate_access.empty());
      }
      if (v) {
        auto back = model::from_mms_variable(v->name.view(), v->alternate_access, opts);
        check(back.has_value() && *back == *r);
      }
    }
    if (auto r = model::from_mms_named_variable_list(name, opts)) {
      auto n = model::to_mms_named_variable_list(*r, opts.limits);
      check(n.has_value() && n->view() == name);
    }
    if (auto r = model::from_mms_named_variable_list(mms::object_name::aa(item), opts)) {
      auto n = model::to_mms_named_variable_list(*r, opts.limits);
      check(n.has_value() && n->view() == mms::object_name::aa(item));
    }
    if (auto r = model::from_mms_reference(input, opts)) {
      auto s = model::to_mms_reference(*r, opts.limits);
      check(s.has_value() && *s == input);
    }
    if (auto r = model::from_mms_data_set_reference(input, opts)) {
      auto s = model::to_mms_data_set_reference(*r, opts.limits);
      check(s.has_value() && *s == input);
    }
  }
  return 0;
}
