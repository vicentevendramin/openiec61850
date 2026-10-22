#pragma once

#include <compare>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <initializer_list>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>

#include "openiec61850/core/result.hpp"
#include "openiec61850/model/functional_constraint.hpp"

// ACSI object references (IEC 61850-7-2 §6.2, IEC 61850-7-3):
//
//   LDName[/LNName[.Name[(index)]]...]  [ "[" FC "]" ]
//   "@" Name                                   -- association-specific (non-persistent) data set
//
// where Name is a DataObject, sub-DataObject, DataAttribute or sub-attribute name, or the name of
// a data set or control block in the LN. The grammar cannot tell a DO from a DA (e.g. WYE.phsA is
// a sub-DO although it starts with a lower-case letter), so the names after the LN are exposed as
// a flat path. The optional "[FC]" suffix makes the reference functionally constrained (FCD/FCDA).
//
// Validation:
//   - LD names and all path names are identifiers: an ASCII letter followed by letters, digits
//     or '_'; LD names are also bounded by name_limits::max_ld_name.
//   - With parse_options::strict_ln_names, LN names are [prefix]LNClass[inst] (see split_ln_name);
//     otherwise any identifier.
//   - The whole reference without the FC suffix is bounded by name_limits::max_object_reference.
//   - An index is decimal, without leading zeros, at most 2^32-1, and only after a path name.
//
// Syntax errors fail with errc::malformed_encoding; exceeded limits with errc::length_overflow.

namespace openiec61850::model {

// Edition of IEC 61850 implemented by a server (see GLOSSARY "Edição do Servidor").
enum class edition : std::uint8_t { ed1 = 1, ed2 = 2, ed2_1 = 3 };

// Size limits that depend on the edition.
//   Ed.1: ObjectReference VISIBLE STRING65, MMS Identifier (8-1 Ed.1) up to 32 characters, so an
//         LD name (MMS domain name) is limited to 32.
//   Ed.2: ObjectReference VISIBLE STRING129, LD names up to 64 (7-2 Ed.2 §6.2.2), MMS Identifier
//         up to 64 characters (8-1 Ed.2).
struct name_limits {
  std::size_t max_ld_name = 64;
  std::size_t max_object_reference = 129;
  std::size_t max_mms_identifier = 64;

  [[nodiscard]] static constexpr name_limits for_edition(edition e) noexcept {
    if (e == edition::ed1) return {32, 65, 32};
    return {64, 129, 64};
  }
  // No limits beyond the hard cap of object_reference (65535 characters).
  [[nodiscard]] static constexpr name_limits unlimited() noexcept {
    return {0xFFFF, 0xFFFF, 0xFFFF};
  }
};

struct parse_options {
  name_limits limits = name_limits::for_edition(edition::ed2);
  bool strict_ln_names = true;
};

[[nodiscard]] constexpr parse_options parse_options_for(edition e) noexcept {
  return {name_limits::for_edition(e), true};
}

// Components of an LN name (IEC 61850-7-2 §22 / SCL tPrefix, tLNClassEnum, tLNInst).
struct ln_name_parts {
  std::string_view prefix;    // up to 11 characters, starting with a letter; may be empty
  std::string_view ln_class;  // 4 upper-case letters, or "LLN0"
  std::string_view inst;      // 1 to 12 digits; empty only for LLN0

  friend constexpr bool operator==(const ln_name_parts&, const ln_name_parts&) noexcept = default;
};

// Splits "PrefXCBR12" into {"Pref", "XCBR", "12"}; the instance is the longest run of trailing
// digits. Returns nullopt when the name does not follow the pattern.
[[nodiscard]] std::optional<ln_name_parts> split_ln_name(std::string_view ln) noexcept;

// True for an ASCII letter followed by letters, digits or '_'.
[[nodiscard]] bool is_identifier(std::string_view s) noexcept;

// One name after the LN, with its optional array index: "phsA", "Arr(3)".
struct path_element {
  std::string_view name;
  std::optional<std::uint32_t> index;

  friend constexpr bool operator==(const path_element&, const path_element&) noexcept = default;
};

// Owning, validated object reference. Stored as its canonical text (one allocation for
// references longer than the small-string buffer) plus a few offsets; the path is decoded lazily.
class object_reference {
 public:
  class path_iterator {
   public:
    using iterator_category = std::forward_iterator_tag;
    using value_type = path_element;
    using difference_type = std::ptrdiff_t;
    using pointer = void;
    using reference = path_element;

    path_iterator() noexcept = default;
    path_element operator*() const noexcept;
    path_iterator& operator++() noexcept;
    path_iterator operator++(int) noexcept {
      auto copy = *this;
      ++*this;
      return copy;
    }
    friend bool operator==(const path_iterator& a, const path_iterator& b) noexcept {
      return a.pos_ == b.pos_;
    }

   private:
    friend class object_reference;
    path_iterator(std::string_view text, std::size_t pos) noexcept : text_(text), pos_(pos) {}
    std::string_view text_;
    std::size_t pos_ = 0;
  };

  class path_range {
   public:
    [[nodiscard]] path_iterator begin() const noexcept { return begin_; }
    [[nodiscard]] path_iterator end() const noexcept { return end_; }
    [[nodiscard]] bool empty() const noexcept { return begin_ == end_; }
    // O(n).
    [[nodiscard]] std::size_t size() const noexcept;

   private:
    friend class object_reference;
    path_range(path_iterator b, path_iterator e) noexcept : begin_(b), end_(e) {}
    path_iterator begin_;
    path_iterator end_;
  };

  // Empty reference (empty() is true); not a valid ACSI reference.
  object_reference() = default;

  [[nodiscard]] static result<object_reference> parse(std::string_view text,
                                                      const parse_options& opts = {});
  // Builds "ld/ln.path..." with the same validation as parse(); `ln` may be empty for an
  // LD-only reference (then `path` and `fc` must be empty too).
  [[nodiscard]] static result<object_reference> make(
      std::string_view ld, std::string_view ln, std::initializer_list<path_element> path = {},
      std::optional<functional_constraint> constraint = std::nullopt,
      const parse_options& opts = {});
  // "@name": association-specific data set.
  [[nodiscard]] static result<object_reference> association_specific(
      std::string_view name, const parse_options& opts = {});

  [[nodiscard]] bool empty() const noexcept { return text_.empty(); }
  [[nodiscard]] bool is_association_specific() const noexcept { return aa_; }
  // Canonical text without the FC suffix.
  [[nodiscard]] std::string_view text() const noexcept { return text_; }
  // Canonical text with the "[FC]" suffix when the reference is functionally constrained.
  [[nodiscard]] std::string to_string() const;

  // Empty for association-specific references.
  [[nodiscard]] std::string_view ld() const noexcept {
    return std::string_view{text_}.substr(0, ld_end_);
  }
  // Empty for LD-only and association-specific references.
  [[nodiscard]] std::string_view ln() const noexcept;
  [[nodiscard]] bool has_ln() const noexcept { return ln_end_ > ld_end_; }
  // Components of ln(); when the LN name is not [prefix]LNClass[inst] (lenient parsing), the
  // whole name is reported as the class.
  [[nodiscard]] ln_name_parts ln_parts() const noexcept;

  // The names after the LN; for an association-specific reference, the data set name.
  [[nodiscard]] path_range path() const noexcept;
  [[nodiscard]] std::size_t depth() const noexcept { return path().size(); }
  // Last path element (nullopt when the path is empty).
  [[nodiscard]] std::optional<path_element> leaf() const noexcept;
  [[nodiscard]] bool has_index() const noexcept;

  [[nodiscard]] std::optional<functional_constraint> fc() const noexcept { return fc_; }
  void set_fc(std::optional<functional_constraint> f) noexcept { fc_ = f; }
  [[nodiscard]] object_reference with_fc(std::optional<functional_constraint> f) const {
    object_reference r = *this;
    r.fc_ = f;
    return r;
  }

  // Appends ".name[(index)]" (or "/name" to an LD-only reference); keeps the FC.
  [[nodiscard]] result<object_reference> child(std::string_view name,
                                               std::optional<std::uint32_t> index = std::nullopt,
                                               const parse_options& opts = {}) const;
  // Drops the last path element (or the LN). Fails with errc::invalid_state for LD-only,
  // association-specific and empty references. The FC is kept unless the result is LD-only.
  [[nodiscard]] result<object_reference> parent() const;
  // True when `ancestor` is this reference or one of its parents (FCs are ignored).
  [[nodiscard]] bool is_within(const object_reference& ancestor) const noexcept;

  friend bool operator==(const object_reference& a, const object_reference& b) noexcept {
    return a.fc_ == b.fc_ && a.text_ == b.text_;
  }
  friend std::strong_ordering operator<=>(const object_reference& a,
                                          const object_reference& b) noexcept {
    if (auto c = a.text_.compare(b.text_); c != 0) {
      return c < 0 ? std::strong_ordering::less : std::strong_ordering::greater;
    }
    return a.fc_ <=> b.fc_;
  }

 private:
  [[nodiscard]] std::size_t path_begin() const noexcept;

  std::string text_;
  std::uint16_t ld_end_ = 0;  // end of the LD name
  std::uint16_t ln_end_ = 0;  // end of the LN name (== ld_end_ when absent)
  std::optional<functional_constraint> fc_;
  bool aa_ = false;
};

}  // namespace openiec61850::model

template <>
struct std::hash<openiec61850::model::object_reference> {
  std::size_t operator()(const openiec61850::model::object_reference& r) const noexcept {
    const auto h = std::hash<std::string_view>{}(r.text());
    const auto f = r.fc() ? static_cast<std::size_t>(*r.fc()) + 1 : 0;
    return h ^ (f * 0x9E3779B97F4A7C15ULL);
  }
};
