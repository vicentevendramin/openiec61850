#include "openiec61850/model/enums.hpp"

#include <array>

#include "detail.hpp"

namespace openiec61850::model {
namespace {

// A 2-bit CODED ENUM value v has bit 0 = v's high bit (IEC 61850-8-1 §8.1.3.5).
constexpr std::uint32_t swap2(std::uint32_t v) noexcept { return ((v >> 1) & 1U) | ((v & 1U) << 1); }

result<std::uint8_t> coded_enum2(const mms::data_ref& d) noexcept {
  auto bits = detail::bits_from_mms(d, 2);
  if (!bits) return bits.error();
  return static_cast<std::uint8_t>(swap2(*bits));
}

template <typename E>
result<E> enumerated(const mms::data_ref& d, int min, int max) noexcept {
  auto v = detail::integer_from_mms<int>(d);
  if (!v) return v.error();
  if (*v < min || *v > max) return errc::value_out_of_range;
  return static_cast<E>(*v);
}

template <typename E, std::size_t N>
std::string_view name_of(E v, const std::array<std::string_view, N>& names,
                         std::size_t first = 0) noexcept {
  const auto i = static_cast<std::size_t>(v);
  return i >= first && i - first < N ? names[i - first] : std::string_view{};
}

}  // namespace

mms::data check_conditions::to_mms() const {
  return detail::bits_to_mms((sync_ ? 1U : 0U) | (interlock_ ? 2U : 0U), bit_count);
}

result<check_conditions> check_conditions::from_mms(const mms::data_ref& d) noexcept {
  auto bits = detail::bits_from_mms(d, bit_count);
  if (!bits) return bits.error();
  return check_conditions{(*bits & 1U) != 0, (*bits & 2U) != 0};
}

mms::data to_mms(dbpos v) { return detail::bits_to_mms(swap2(static_cast<std::uint32_t>(v)), 2); }
mms::data to_mms(step_command v) {
  return detail::bits_to_mms(swap2(static_cast<std::uint32_t>(v)), 2);
}
mms::data to_mms(orcat v) { return mms::data::integer(static_cast<std::int64_t>(v)); }
mms::data to_mms(ctl_model v) { return mms::data::integer(static_cast<std::int64_t>(v)); }
mms::data to_mms(behaviour v) { return mms::data::integer(static_cast<std::int64_t>(v)); }
mms::data to_mms(health v) { return mms::data::integer(static_cast<std::int64_t>(v)); }

result<dbpos> dbpos_from_mms(const mms::data_ref& d) noexcept {
  auto v = coded_enum2(d);
  if (!v) return v.error();
  return static_cast<dbpos>(*v);
}
result<step_command> step_command_from_mms(const mms::data_ref& d) noexcept {
  auto v = coded_enum2(d);
  if (!v) return v.error();
  return static_cast<step_command>(*v);
}
result<orcat> orcat_from_mms(const mms::data_ref& d) noexcept {
  return enumerated<orcat>(d, 0, 8);
}
result<ctl_model> ctl_model_from_mms(const mms::data_ref& d) noexcept {
  return enumerated<ctl_model>(d, 0, 4);
}
result<behaviour> behaviour_from_mms(const mms::data_ref& d) noexcept {
  return enumerated<behaviour>(d, 1, 5);
}
result<health> health_from_mms(const mms::data_ref& d) noexcept {
  return enumerated<health>(d, 1, 3);
}

std::string_view to_string(dbpos v) noexcept {
  static constexpr std::array<std::string_view, 4> names{"intermediate-state", "off", "on",
                                                         "bad-state"};
  return name_of(v, names);
}
std::string_view to_string(step_command v) noexcept {
  static constexpr std::array<std::string_view, 4> names{"stop", "lower", "higher", "reserved"};
  return name_of(v, names);
}
std::string_view to_string(orcat v) noexcept {
  static constexpr std::array<std::string_view, 9> names{
      "not-supported",     "bay-control",      "station-control", "remote-control",
      "automatic-bay",     "automatic-station", "automatic-remote", "maintenance",
      "process"};
  return name_of(v, names);
}
std::string_view to_string(ctl_model v) noexcept {
  static constexpr std::array<std::string_view, 5> names{
      "status-only", "direct-with-normal-security", "sbo-with-normal-security",
      "direct-with-enhanced-security", "sbo-with-enhanced-security"};
  return name_of(v, names);
}
std::string_view to_string(behaviour v) noexcept {
  static constexpr std::array<std::string_view, 5> names{"on", "on-blocked", "test",
                                                         "test/blocked", "off"};
  return name_of(v, names, 1);
}
std::string_view to_string(health v) noexcept {
  static constexpr std::array<std::string_view, 3> names{"Ok", "Warning", "Alarm"};
  return name_of(v, names, 1);
}

}  // namespace openiec61850::model
