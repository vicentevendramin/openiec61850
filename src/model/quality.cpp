#include "openiec61850/model/quality.hpp"

#include <string_view>

#include "detail.hpp"

namespace openiec61850::model {

mms::data quality::to_mms() const { return detail::bits_to_mms(bits_, bit_count); }

result<quality> quality::from_mms(const mms::data_ref& d) noexcept {
  auto bits = detail::bits_from_mms(d, bit_count);
  if (!bits) return bits.error();
  return from_raw(static_cast<std::uint16_t>(*bits));
}

std::string to_string(quality q) {
  static constexpr std::string_view validity_names[] = {"good", "invalid", "reserved",
                                                        "questionable"};
  static constexpr std::string_view flag_names[] = {
      "overflow",     "outOfRange", "badReference", "oscillatory", "failure",        "oldData",
      "inconsistent", "inaccurate", "substituted",  "test",        "operatorBlocked"};
  std::string s{validity_names[static_cast<std::size_t>(q.validity())]};
  for (std::size_t i = 0; i < std::size(flag_names); ++i) {
    if ((static_cast<unsigned>(q.raw()) >> (i + 2)) & 1U) {
      s.push_back('|');
      s.append(flag_names[i]);
    }
  }
  return s;
}

}  // namespace openiec61850::model
