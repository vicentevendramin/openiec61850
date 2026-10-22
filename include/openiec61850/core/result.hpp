#pragma once

#include <cassert>
#include <system_error>
#include <utility>
#include <variant>

#include "openiec61850/core/error.hpp"

namespace openiec61850 {

// Minimal C++20 stand-in for std::expected<T, std::error_code> (C++23).
template <typename T>
class [[nodiscard]] result {
 public:
  result(T value) : storage_(std::in_place_index<0>, std::move(value)) {}
  result(std::error_code ec) : storage_(std::in_place_index<1>, ec) { assert(ec); }
  result(errc e) : result(make_error_code(e)) {}

  [[nodiscard]] bool has_value() const noexcept { return storage_.index() == 0; }
  explicit operator bool() const noexcept { return has_value(); }

  [[nodiscard]] T& value() & { assert(has_value()); return std::get<0>(storage_); }
  [[nodiscard]] const T& value() const& { assert(has_value()); return std::get<0>(storage_); }
  [[nodiscard]] T&& value() && { assert(has_value()); return std::get<0>(std::move(storage_)); }

  T& operator*() & { return value(); }
  const T& operator*() const& { return value(); }
  T&& operator*() && { return std::move(*this).value(); }
  T* operator->() { return &value(); }
  const T* operator->() const { return &value(); }

  [[nodiscard]] std::error_code error() const noexcept {
    return has_value() ? std::error_code{} : std::get<1>(storage_);
  }

 private:
  std::variant<T, std::error_code> storage_;
};

template <>
class [[nodiscard]] result<void> {
 public:
  result() = default;
  result(std::error_code ec) : ec_(ec) {}
  result(errc e) : ec_(make_error_code(e)) {}

  [[nodiscard]] bool has_value() const noexcept { return !ec_; }
  explicit operator bool() const noexcept { return has_value(); }
  [[nodiscard]] std::error_code error() const noexcept { return ec_; }

 private:
  std::error_code ec_;
};

}  // namespace openiec61850
