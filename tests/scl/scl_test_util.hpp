#pragma once

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <string_view>

#include "openiec61850/scl/scl.hpp"

namespace scl_test {

inline std::string data_path(std::string_view file) {
  return std::string{OPENIEC61850_SCL_TEST_DATA} + "/" + std::string{file};
}

// Loads a file of tests/scl/data, which must load without errors.
inline openiec61850::scl::document load_data(std::string_view file) {
  auto r = openiec61850::scl::load_file(data_path(file));
  for (const auto& d : r.diags) UNSCOPED_INFO(openiec61850::scl::to_string(d));
  REQUIRE(r.ok());
  CHECK(r.diags.error_count() == 0);
  return std::move(*r.doc);
}

// Minimal SCL wrapper around IED and DataTypeTemplates content.
inline std::string wrap(std::string_view ieds, std::string_view templates) {
  std::string s = R"(<?xml version="1.0"?>
<SCL xmlns="http://www.iec.ch/61850/2003/SCL" version="2007" revision="B">
<Header id="t"/>
)";
  s += ieds;
  s += "\n<DataTypeTemplates>\n";
  s += templates;
  s += "\n</DataTypeTemplates>\n</SCL>\n";
  return s;
}

}  // namespace scl_test
