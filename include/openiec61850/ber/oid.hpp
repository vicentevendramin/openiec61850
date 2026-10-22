#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <span>
#include <string>
#include <string_view>

#include "openiec61850/core/result.hpp"

namespace openiec61850::ber {

// OBJECT IDENTIFIER value with inline storage (no allocation).
// Arcs are limited to 32 bits and to max_arcs components; larger values are valid
// X.680 but rejected with errc::unsupported by the decoders.
class oid {
 public:
  static constexpr std::size_t max_arcs = 32;

  constexpr oid() noexcept = default;
  // Lists longer than max_arcs produce an empty (invalid) oid.
  constexpr oid(std::initializer_list<std::uint32_t> arcs) noexcept {
    if (arcs.size() > max_arcs) return;
    for (auto a : arcs) arcs_[size_++] = a;
  }

  // Parses dotted notation, e.g. "1.0.9506.2.1". Leading zeros, empty arcs and
  // values that violate X.690 §8.19.4 are rejected with errc::malformed_encoding.
  [[nodiscard]] static result<oid> from_string(std::string_view text);
  [[nodiscard]] std::string to_string() const;

  // Appends an arc; returns false when full.
  constexpr bool push_back(std::uint32_t arc) noexcept {
    if (size_ == max_arcs) return false;
    arcs_[size_++] = arc;
    return true;
  }

  // At least two arcs, first arc 0..2 and second arc 0..39 under roots 0 and 1 (X.690 §8.19.4).
  [[nodiscard]] constexpr bool valid() const noexcept {
    if (size_ < 2 || arcs_[0] > 2) return false;
    return arcs_[0] == 2 || arcs_[1] < 40;
  }

  [[nodiscard]] constexpr std::size_t size() const noexcept { return size_; }
  [[nodiscard]] constexpr bool empty() const noexcept { return size_ == 0; }
  [[nodiscard]] constexpr std::uint32_t operator[](std::size_t i) const noexcept { return arcs_[i]; }
  [[nodiscard]] constexpr std::span<const std::uint32_t> arcs() const noexcept {
    return {arcs_.data(), size_};
  }
  [[nodiscard]] constexpr const std::uint32_t* begin() const noexcept { return arcs_.data(); }
  [[nodiscard]] constexpr const std::uint32_t* end() const noexcept { return arcs_.data() + size_; }

  friend constexpr bool operator==(const oid& a, const oid& b) noexcept {
    if (a.size_ != b.size_) return false;
    for (std::size_t i = 0; i < a.size_; ++i) {
      if (a.arcs_[i] != b.arcs_[i]) return false;
    }
    return true;
  }

 private:
  std::array<std::uint32_t, max_arcs> arcs_{};
  std::size_t size_ = 0;
};

}  // namespace openiec61850::ber
