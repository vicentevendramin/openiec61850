#pragma once

#include <string_view>

namespace openiec61850 {

struct version_info {
  int major;
  int minor;
  int patch;
  std::string_view string;
};

[[nodiscard]] version_info version() noexcept;

}  // namespace openiec61850
