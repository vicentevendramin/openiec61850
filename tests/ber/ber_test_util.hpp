#pragma once

#include <cstdint>
#include <initializer_list>

#include "openiec61850/core/bytes.hpp"

namespace ber_test {

inline openiec61850::byte_buffer bytes(std::initializer_list<std::uint8_t> list) { return list; }

inline openiec61850::byte_buffer copy(openiec61850::byte_view v) { return {v.begin(), v.end()}; }

}  // namespace ber_test
