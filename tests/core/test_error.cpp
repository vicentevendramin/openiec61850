#include <catch2/catch_test_macros.hpp>

#include "openiec61850/core/error.hpp"

TEST_CASE("errc converts to std::error_code", "[core]") {
  std::error_code ec = openiec61850::errc::truncated_input;
  CHECK(ec);
  CHECK(ec.category().name() == std::string_view{"openiec61850"});
  CHECK(ec.message() == "truncated input");
  CHECK(ec == openiec61850::errc::truncated_input);
}
