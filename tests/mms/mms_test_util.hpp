#pragma once

#include <cctype>
#include <cstdint>
#include <string>
#include <string_view>

#include "openiec61850/core/bytes.hpp"

namespace mms_test {

// Parses "A0 03 'abc' 1A": hex octets separated by spaces, with 'quoted' ASCII runs.
inline openiec61850::byte_buffer hex(std::string_view text) {
  openiec61850::byte_buffer out;
  std::size_t i = 0;
  auto nibble = [](char c) {
    return static_cast<std::uint8_t>(std::isdigit(static_cast<unsigned char>(c)) != 0
                                         ? c - '0'
                                         : std::toupper(static_cast<unsigned char>(c)) - 'A' + 10);
  };
  while (i < text.size()) {
    const char c = text[i];
    if (c == ' ') {
      ++i;
    } else if (c == '\'') {
      const auto end = text.find('\'', i + 1);
      for (std::size_t j = i + 1; j < end; ++j) out.push_back(static_cast<std::uint8_t>(text[j]));
      i = end + 1;
    } else {
      out.push_back(static_cast<std::uint8_t>((nibble(text[i]) << 4) | nibble(text[i + 1])));
      i += 2;
    }
  }
  return out;
}

}  // namespace mms_test
