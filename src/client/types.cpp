#include "openiec61850/client/types.hpp"

#include "openiec61850/model/mms_mapping.hpp"

namespace openiec61850::client {

const data_definition* data_definition::find(std::string_view child) const noexcept {
  for (const auto& c : children) {
    if (c.name == child) return &c;
  }
  return nullptr;
}

std::optional<model::object_reference> rcb_values::data_set(const model::parse_options& opts) const {
  if (!dat_set || dat_set->empty()) return std::nullopt;
  auto r = model::from_mms_data_set_reference(*dat_set, opts);
  if (!r) return std::nullopt;
  return std::move(*r);
}

}  // namespace openiec61850::client
