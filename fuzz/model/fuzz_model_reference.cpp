// Parses arbitrary text as an ACSI object reference under Ed.1, Ed.2 and lenient options and
// checks the invariants of every accepted reference: canonical round trip, path decoding,
// parent/child consistency and the MMS mapping round trip.
// Seed corpus: fuzz/corpus/model_reference/

#include <cstddef>
#include <cstdint>
#include <string_view>

#include "openiec61850/model/mms_mapping.hpp"
#include "openiec61850/model/object_reference.hpp"

namespace model = openiec61850::model;

namespace {

void check(bool condition) {
  if (!condition) __builtin_trap();
}

void exercise(std::string_view text, const model::parse_options& opts) {
  auto r = model::object_reference::parse(text, opts);
  if (!r) return;
  check(!r->empty());
  check(r->text().size() <= opts.limits.max_object_reference);
  check(r->ld().size() <= opts.limits.max_ld_name || r->is_association_specific());

  auto again = model::object_reference::parse(r->to_string(), opts);
  check(again.has_value() && *again == *r);

  std::size_t n = 0;
  for (auto e : r->path()) {
    check(model::is_identifier(e.name));
    ++n;
  }
  check(n == r->depth());
  (void)r->ln_parts();
  (void)r->leaf();

  if (auto p = r->parent()) {
    check(r->is_within(*p));
    if (auto leaf = r->leaf(); leaf && p->has_ln()) {
      auto c = p->child(leaf->name, leaf->index, opts);
      check(c.has_value() && c->text() == r->text());
    }
  }

  if (auto v = model::to_mms_variable(*r, opts.limits)) {
    auto back = model::from_mms_variable(v->name.view(), v->alternate_access, opts);
    check(back.has_value() && *back == *r);
  }
  if (auto s = model::to_mms_reference(*r, opts.limits)) {
    auto back = model::from_mms_reference(*s, opts);
    check(back.has_value() && *back == *r);
  }
  if (auto n2 = model::to_mms_named_variable_list(*r, opts.limits)) {
    auto back = model::from_mms_named_variable_list(n2->view(), opts);
    check(back.has_value() && *back == *r);
  }
  if (auto s = model::to_mms_data_set_reference(*r, opts.limits)) {
    auto back = model::from_mms_data_set_reference(*s, opts);
    check(back.has_value() && *back == *r);
  }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  const std::string_view text{reinterpret_cast<const char*>(data), size};
  exercise(text, model::parse_options_for(model::edition::ed1));
  exercise(text, model::parse_options_for(model::edition::ed2));
  exercise(text, {model::name_limits::unlimited(), false});
  return 0;
}
