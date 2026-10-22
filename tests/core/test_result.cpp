#include <catch2/catch_test_macros.hpp>

#include <string>

#include "openiec61850/core/result.hpp"

using openiec61850::errc;
using openiec61850::result;

TEST_CASE("result holds a value", "[core]") {
  result<std::string> r{std::string{"abc"}};
  REQUIRE(r);
  CHECK(*r == "abc");
  CHECK(r->size() == 3);
  CHECK_FALSE(r.error());
}

TEST_CASE("result holds an error", "[core]") {
  result<int> r{errc::malformed_encoding};
  REQUIRE_FALSE(r);
  CHECK(r.error() == errc::malformed_encoding);
}

TEST_CASE("result<void>", "[core]") {
  result<void> ok;
  CHECK(ok);
  result<void> fail{errc::unsupported};
  CHECK_FALSE(fail);
  CHECK(fail.error() == errc::unsupported);
}
