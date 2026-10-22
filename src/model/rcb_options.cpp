#include "openiec61850/model/rcb_options.hpp"

#include "detail.hpp"

namespace openiec61850::model {

mms::data trigger_conditions::to_mms() const {
  return detail::bits_to_mms(bits_, trg_ops_bit_count);
}

result<mms::data> trigger_conditions::to_mms_reason_code(edition e) const {
  if (e == edition::ed1) {
    if (application_trigger()) return errc::invalid_state;
    return detail::bits_to_mms(bits_, trg_ops_bit_count);
  }
  return detail::bits_to_mms(bits_, reason_code_bit_count);
}

result<trigger_conditions> trigger_conditions::from_mms(const mms::data_ref& d) noexcept {
  auto bits = detail::bits_from_mms(d, reason_code_bit_count);
  if (!bits) return bits.error();
  return from_raw(static_cast<std::uint8_t>(*bits));
}

mms::data optional_fields::to_mms() const { return detail::bits_to_mms(bits_, bit_count); }

result<optional_fields> optional_fields::from_mms(const mms::data_ref& d) noexcept {
  auto bits = detail::bits_from_mms(d, bit_count);
  if (!bits) return bits.error();
  return from_raw(static_cast<std::uint16_t>(*bits));
}

}  // namespace openiec61850::model
