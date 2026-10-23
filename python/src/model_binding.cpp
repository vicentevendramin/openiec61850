// Object reference helpers (model/object_reference.hpp, model/mms_mapping.hpp) used by the pure
// Python ObjectReference class.

#include <nanobind/nanobind.h>
#include <nanobind/stl/optional.h>
#include <nanobind/stl/string.h>

#include <string>
#include <string_view>

#include "bindings.hpp"
#include "convert.hpp"
#include "openiec61850/model/mms_mapping.hpp"
#include "openiec61850/model/object_reference.hpp"

namespace openiec61850::python {

namespace {

model::parse_options options(int edition, bool strict) {
  if (edition < 1 || edition > 3) throw nb::value_error("unknown edition");
  return {model::name_limits::for_edition(static_cast<model::edition>(edition)), strict};
}

model::name_limits limits(int edition) { return options(edition, false).limits; }

[[noreturn]] void raise(std::string_view text, std::error_code ec) {
  nb::object cls = nb::module_::import_("openiec61850._errors").attr("InvalidReference");
  nb::object exc = cls("invalid object reference '" + std::string(text) + "': " + ec.message());
  PyErr_SetObject(cls.ptr(), exc.ptr());
  throw nb::python_error();
}

template <typename T>
T check(result<T> r, std::string_view text) {
  if (!r) raise(text, r.error());
  return std::move(*r);
}

// (text, ld, ln, [(name, index | None)], fc | None, association_specific)
nb::object parts(const model::object_reference& r) {
  nb::list path;
  for (const auto e : r.path()) {
    path.append(nb::make_tuple(std::string(e.name),
                               e.index ? nb::cast(*e.index) : nb::none()));
  }
  return nb::make_tuple(std::string(r.text()), std::string(r.ld()), std::string(r.ln()), path,
                        r.fc() ? nb::cast(std::string(model::to_string(*r.fc()))) : nb::none(),
                        r.is_association_specific());
}

model::object_reference parse(const std::string& text, int edition, bool strict) {
  return check(model::object_reference::parse(text, options(edition, strict)), text);
}

}  // namespace

void bind_model(nb::module_& m) {
  m.def(
      "parse_reference",
      [](const std::string& text, int edition, bool strict) {
        return parts(parse(text, edition, strict));
      },
      nb::arg("text"), nb::arg("edition") = 2, nb::arg("strict_ln_names") = true,
      "Validates an object reference; returns (text, ld, ln, path, fc, association_specific).");
  m.def(
      "split_ln_name",
      [](const std::string& ln) -> nb::object {
        const auto p = model::split_ln_name(ln);
        if (!p) return nb::none();
        return nb::make_tuple(std::string(p->prefix), std::string(p->ln_class), std::string(p->inst));
      },
      nb::arg("ln"));
  m.def(
      "to_mms_reference",
      [](const std::string& text, int edition) {
        return check(model::to_mms_reference(parse(text, edition, false), limits(edition)), text);
      },
      nb::arg("text"), nb::arg("edition") = 2);
  m.def(
      "from_mms_reference",
      [](const std::string& text, int edition, bool strict) {
        return check(model::from_mms_reference(text, options(edition, strict)), text).to_string();
      },
      nb::arg("text"), nb::arg("edition") = 2, nb::arg("strict_ln_names") = false);
  m.def(
      "to_mms_data_set_reference",
      [](const std::string& text, int edition) {
        return check(model::to_mms_data_set_reference(parse(text, edition, false), limits(edition)),
                     text);
      },
      nb::arg("text"), nb::arg("edition") = 2);
  m.def(
      "from_mms_data_set_reference",
      [](const std::string& text, int edition, bool strict) {
        return check(model::from_mms_data_set_reference(text, options(edition, strict)), text)
            .to_string();
      },
      nb::arg("text"), nb::arg("edition") = 2, nb::arg("strict_ln_names") = false);
  m.def(
      "to_mms_variable",
      [](const std::string& text, int edition) {
        const auto v = check(model::to_mms_variable(parse(text, edition, false), limits(edition)), text);
        return nb::make_tuple(static_cast<int>(v.name.scope), v.name.domain_id, v.name.item_id,
                              to_bytes(v.alternate_access));
      },
      nb::arg("text"), nb::arg("edition") = 2,
      "MMS variable of a functionally constrained reference: (scope, domain, item, alternate "
      "access contents).");
}

}  // namespace openiec61850::python
