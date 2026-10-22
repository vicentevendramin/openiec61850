#include <catch2/catch_test_macros.hpp>

#include "openiec61850/core/version.hpp"

TEST_CASE("version string matches components", "[core]") {
  const auto v = openiec61850::version();
  CHECK(v.major >= 0);
  CHECK_FALSE(v.string.empty());
}
