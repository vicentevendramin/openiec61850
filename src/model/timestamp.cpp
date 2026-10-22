#include "openiec61850/model/timestamp.hpp"

namespace openiec61850::model {

timestamp timestamp::now(std::uint8_t accuracy) noexcept {
  auto t = from_time_point(std::chrono::system_clock::now(), accuracy);
  return t ? *t : timestamp{};
}

std::optional<std::chrono::nanoseconds> timestamp::accuracy() const noexcept {
  const auto bits = time_accuracy();
  if (bits > 24) return std::nullopt;
  const std::uint64_t ns = (((2'000'000'000ULL) >> bits) + 1) >> 1;
  return std::chrono::nanoseconds{static_cast<std::int64_t>(ns)};
}

result<timestamp> timestamp::from_mms(const mms::data_ref& d) noexcept {
  auto t = d.owned() != nullptr ? d.owned()->as_utc_time() : d.view().as_utc_time();
  if (!t) return t.error();
  return timestamp{*t};
}

result<entry_time> entry_time_from_mms(const mms::data_ref& d) noexcept {
  if (const auto* owned = d.owned()) return owned->as_binary_time();
  return d.view().as_binary_time();
}

}  // namespace openiec61850::model
