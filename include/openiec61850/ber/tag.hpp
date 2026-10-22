#pragma once

#include <cstdint>

namespace openiec61850::ber {

// X.690 §8.1.2.2, bits 8-7 of the first identifier octet.
enum class tag_class : std::uint8_t {
  universal = 0,
  application = 1,
  context = 2,
  private_ = 3,
};

// An identifier: class, form (primitive/constructed) and tag number.
// Tag numbers above 2^32-1 are valid X.690 but rejected with errc::unsupported.
struct tag {
  tag_class cls = tag_class::universal;
  bool constructed = false;
  std::uint32_t number = 0;

  [[nodiscard]] constexpr tag as_constructed() const noexcept { return {cls, true, number}; }
  [[nodiscard]] constexpr tag as_primitive() const noexcept { return {cls, false, number}; }
  // Same class and number, regardless of form.
  [[nodiscard]] constexpr bool same_id(tag other) const noexcept {
    return cls == other.cls && number == other.number;
  }

  friend constexpr bool operator==(tag, tag) noexcept = default;
};

[[nodiscard]] constexpr tag universal(std::uint32_t number, bool constructed = false) noexcept {
  return {tag_class::universal, constructed, number};
}
[[nodiscard]] constexpr tag application(std::uint32_t number, bool constructed = false) noexcept {
  return {tag_class::application, constructed, number};
}
[[nodiscard]] constexpr tag context(std::uint32_t number, bool constructed = false) noexcept {
  return {tag_class::context, constructed, number};
}
[[nodiscard]] constexpr tag private_tag(std::uint32_t number, bool constructed = false) noexcept {
  return {tag_class::private_, constructed, number};
}

// Universal tags (X.680 §8.4), in the form used by the encoders of this library.
namespace tags {
inline constexpr tag boolean = universal(1);
inline constexpr tag integer = universal(2);
inline constexpr tag bit_string = universal(3);
inline constexpr tag octet_string = universal(4);
inline constexpr tag null = universal(5);
inline constexpr tag object_identifier = universal(6);
inline constexpr tag external = universal(8, true);
inline constexpr tag real = universal(9);
inline constexpr tag enumerated = universal(10);
inline constexpr tag utf8_string = universal(12);
inline constexpr tag sequence = universal(16, true);
inline constexpr tag set = universal(17, true);
inline constexpr tag printable_string = universal(19);
inline constexpr tag ia5_string = universal(22);
inline constexpr tag utc_time = universal(23);
inline constexpr tag generalized_time = universal(24);
inline constexpr tag graphic_string = universal(25);
inline constexpr tag visible_string = universal(26);
}  // namespace tags

}  // namespace openiec61850::ber
