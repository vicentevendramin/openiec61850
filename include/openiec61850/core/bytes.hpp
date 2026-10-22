#pragma once

#include <cstdint>
#include <span>
#include <vector>

namespace openiec61850 {

using byte_view = std::span<const std::uint8_t>;
using byte_buffer = std::vector<std::uint8_t>;

}  // namespace openiec61850
