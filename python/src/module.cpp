#include <nanobind/nanobind.h>
#include <nanobind/stl/string.h>

#include <string>

#include "openiec61850/core/version.hpp"

namespace nb = nanobind;

NB_MODULE(_core, m) {
  m.doc() = "openiec61850 native core";
  m.attr("__version__") = std::string{openiec61850::version().string};
}
