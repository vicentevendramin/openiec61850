#pragma once

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <ranges>
#include <span>
#include <type_traits>

#include "openiec61850/ber/decode.hpp"
#include "openiec61850/core/bytes.hpp"
#include "openiec61850/core/result.hpp"

namespace openiec61850::mms {

// Non-owning view of an ASN.1 SEQUENCE OF, in one of two modes:
//  - encoded: the contents octets of a decoded SEQUENCE OF. Elements are decoded on the fly while
//    iterating, without allocating. The PDU decoders validate every element before handing out
//    such a view, so iteration never fails.
//  - borrowed: a contiguous range supplied by the caller for encoding (e.g. a std::vector or a
//    C array). The range must outlive the view.
// The encoders copy encoded-mode lists verbatim, so a decoded list can be forwarded cheaply.
template <typename T>
class list_view {
 public:
  using value_type = T;
  // Decodes one element; must not fail on input that passed validation.
  using element_decoder = result<T> (*)(const ber::tlv&) noexcept;

  list_view() noexcept = default;

  template <typename U>
    requires std::constructible_from<T, const U&>
  list_view(std::span<const U> items) noexcept
      : base_(items.data()), size_(items.size()), get_(&get_at<U>) {}

  template <typename R>
    requires(!std::same_as<std::remove_cvref_t<R>, list_view> &&
             std::ranges::contiguous_range<R> && std::ranges::sized_range<R> &&
             (std::is_lvalue_reference_v<R> || std::ranges::borrowed_range<R>) &&
             std::constructible_from<T, const std::ranges::range_value_t<R>&>)
  list_view(R&& items) noexcept  // NOLINT(bugprone-forwarding-reference-overload)
      : list_view(std::span<const std::ranges::range_value_t<R>>(std::ranges::data(items),
                                                                  std::ranges::size(items))) {}

  [[nodiscard]] static list_view encoded(byte_view contents, element_decoder decode) noexcept {
    list_view l;
    l.encoded_ = contents;
    l.decode_ = decode;
    return l;
  }

  [[nodiscard]] bool is_encoded() const noexcept { return decode_ != nullptr; }
  // Contents octets of the SEQUENCE OF (encoded mode only).
  [[nodiscard]] byte_view encoded_contents() const noexcept { return encoded_; }

  class iterator {
   public:
    using value_type = T;
    using difference_type = std::ptrdiff_t;
    using iterator_concept = std::forward_iterator_tag;
    using iterator_category = std::input_iterator_tag;

    iterator() noexcept = default;

    // By value, so `*list.begin()` never dangles; elements are small views.
    T operator*() const noexcept { return current_; }
    const T* operator->() const noexcept { return &current_; }
    iterator& operator++() noexcept {
      if (decode_ != nullptr) {
        load();
      } else if (++index_ < size_) {
        current_ = get_(base_, index_);
      }
      return *this;
    }
    iterator operator++(int) noexcept {
      iterator old = *this;
      ++*this;
      return old;
    }
    friend bool operator==(const iterator& a, const iterator& b) noexcept {
      return a.pos_ == b.pos_ && a.index_ == b.index_;
    }

   private:
    friend class list_view;

    void load() noexcept {
      const std::uint8_t* const end = rest_.data() + rest_.size();
      if (rest_.empty()) {
        pos_ = end;
        return;
      }
      auto e = ber::decode_tlv(rest_);
      if (!e) {
        pos_ = end;
        rest_ = {};
        return;
      }
      auto v = decode_(*e);
      if (!v) {
        pos_ = end;
        rest_ = {};
        return;
      }
      current_ = std::move(*v);
      pos_ = rest_.data();
      rest_ = rest_.subspan(e->encoding.size());
    }

    // Encoded mode.
    element_decoder decode_ = nullptr;
    byte_view rest_;
    const std::uint8_t* pos_ = nullptr;
    // Borrowed mode.
    const void* base_ = nullptr;
    std::size_t index_ = 0;
    std::size_t size_ = 0;
    T (*get_)(const void*, std::size_t) = nullptr;
    T current_{};
  };

  [[nodiscard]] iterator begin() const noexcept {
    iterator it;
    if (decode_ != nullptr) {
      it.decode_ = decode_;
      it.rest_ = encoded_;
      it.load();
    } else {
      it.base_ = base_;
      it.size_ = size_;
      it.get_ = get_;
      if (size_ > 0) it.current_ = get_(base_, 0);
    }
    return it;
  }
  [[nodiscard]] iterator end() const noexcept {
    iterator it;
    if (decode_ != nullptr) {
      it.pos_ = encoded_.data() + encoded_.size();
    } else {
      it.index_ = size_;
    }
    return it;
  }

  // O(n) in encoded mode (counts the TLVs).
  [[nodiscard]] std::size_t size() const noexcept {
    if (decode_ == nullptr) return size_;
    std::size_t n = 0;
    byte_view rest = encoded_;
    while (!rest.empty()) {
      auto e = ber::decode_tlv(rest);
      if (!e) break;
      rest = rest.subspan(e->encoding.size());
      ++n;
    }
    return n;
  }
  [[nodiscard]] bool empty() const noexcept {
    return decode_ != nullptr ? encoded_.empty() : size_ == 0;
  }

 private:
  template <typename U>
  static T get_at(const void* base, std::size_t i) noexcept {
    return T(static_cast<const U*>(base)[i]);
  }

  byte_view encoded_;
  element_decoder decode_ = nullptr;
  const void* base_ = nullptr;
  std::size_t size_ = 0;
  T (*get_)(const void*, std::size_t) = nullptr;
};

}  // namespace openiec61850::mms
