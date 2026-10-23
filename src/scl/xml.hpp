#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>
#include <utility>
#include <vector>

#include <pugixml.hpp>

// Namespace-aware element matching and line numbers on top of pugixml (internal).

namespace openiec61850::scl::detail {

inline constexpr std::string_view scl_namespace = "http://www.iec.ch/61850/2003/SCL";

// Prefix bindings declared on one element, chained to the enclosing element's scope.
class ns_scope {
 public:
  ns_scope(const ns_scope* parent, pugi::xml_node element) : parent_(parent) {
    for (auto a = element.first_attribute(); a; a = a.next_attribute()) {
      const std::string_view n = a.name();
      if (n == "xmlns") {
        bindings_.emplace_back(std::string_view{}, a.value());
      } else if (n.size() > 6 && n.substr(0, 6) == "xmlns:") {
        bindings_.emplace_back(n.substr(6), a.value());
      }
    }
  }

  [[nodiscard]] std::optional<std::string_view> lookup(std::string_view prefix) const {
    for (const ns_scope* s = this; s != nullptr; s = s->parent_) {
      for (auto it = s->bindings_.rbegin(); it != s->bindings_.rend(); ++it) {
        if (it->first == prefix) return it->second;
      }
    }
    return std::nullopt;
  }

  // An element of this scope is an SCL element when it is in the SCL namespace (any
  // http://www.iec.ch/61850/<year>/SCL) or, for unprefixed names, in no namespace.
  [[nodiscard]] bool is_scl(pugi::xml_node element) const {
    const std::string_view n = element.name();
    const auto colon = n.find(':');
    const auto prefix = colon == std::string_view::npos ? std::string_view{} : n.substr(0, colon);
    const auto uri = lookup(prefix);
    if (!uri) return prefix.empty();
    if (uri->empty()) return prefix.empty();
    return is_scl_namespace(*uri);
  }

  [[nodiscard]] static bool is_scl_namespace(std::string_view uri) noexcept {
    constexpr std::string_view head = "http://www.iec.ch/61850/";
    constexpr std::string_view tail = "/SCL";
    return uri == scl_namespace ||
           (uri.size() > head.size() + tail.size() && uri.substr(0, head.size()) == head &&
            uri.substr(uri.size() - tail.size()) == tail);
  }

 private:
  const ns_scope* parent_;
  std::vector<std::pair<std::string_view, std::string_view>> bindings_;
};

[[nodiscard]] inline std::string_view local_name(pugi::xml_node element) noexcept {
  const std::string_view n = element.name();
  const auto colon = n.find(':');
  return colon == std::string_view::npos ? n : n.substr(colon + 1);
}

// Calls f(local_name, element, scope) for each SCL child element.
template <typename F>
void for_each_scl_child(const ns_scope& scope, pugi::xml_node parent, F&& f) {
  for (auto c = parent.first_child(); c; c = c.next_sibling()) {
    if (c.type() != pugi::node_element) continue;
    const ns_scope child_scope{&scope, c};
    if (!child_scope.is_scl(c)) continue;
    f(local_name(c), c, child_scope);
  }
}

class line_map {
 public:
  explicit line_map(std::string_view text) {
    for (std::size_t i = 0; i < text.size(); ++i) {
      if (text[i] == '\n') newlines_.push_back(i);
    }
    size_ = text.size();
  }

  // 1-based line of a byte offset; 0 when out of range.
  [[nodiscard]] std::uint32_t line_of(std::ptrdiff_t offset) const noexcept {
    if (offset < 0 || static_cast<std::size_t>(offset) > size_) return 0;
    const auto it = std::lower_bound(newlines_.begin(), newlines_.end(),
                                     static_cast<std::size_t>(offset));
    const auto line = static_cast<std::size_t>(it - newlines_.begin()) + 1;
    return line > 0xFFFFFFFFU ? 0 : static_cast<std::uint32_t>(line);
  }

 private:
  std::vector<std::size_t> newlines_;
  std::size_t size_ = 0;
};

}  // namespace openiec61850::scl::detail
