#include <catch2/catch_test_macros.hpp>

#include <cmath>
#include <string>
#include <variant>

#include "openiec61850/scl/btype.hpp"

namespace scl = openiec61850::scl;
namespace model = openiec61850::model;
using model::basic_type;
using openiec61850::errc;

TEST_CASE("SCL bType names map to basic types", "[scl]") {
  const auto t = [](std::string_view s) {
    auto i = scl::parse_btype(s);
    REQUIRE(i);
    return *i;
  };
  CHECK(t("BOOLEAN").type == basic_type::boolean);
  CHECK(t("INT8").type == basic_type::int8);
  CHECK(t("INT128").type == basic_type::int128);
  CHECK(t("INT24U").type == basic_type::int24u);
  CHECK(t("FLOAT64").type == basic_type::float64);
  CHECK(t("Enum").type == basic_type::enumerated);
  CHECK(t("Dbpos").type == basic_type::dbpos);
  CHECK(t("Tcmd").type == basic_type::tcmd);
  CHECK(t("Check").type == basic_type::check);
  CHECK(t("Quality").type == basic_type::quality);
  CHECK(t("Timestamp").type == basic_type::timestamp);
  CHECK(t("EntryTime").type == basic_type::entry_time);
  CHECK(t("ObjRef").type == basic_type::object_reference);
  CHECK(t("EntryID").type == basic_type::entry_id);
  CHECK(t("TrgOps").type == basic_type::trigger_conditions);
  CHECK(t("OptFlds").type == basic_type::optional_fields);
  CHECK(t("VisString255").type == basic_type::visible_string);
  CHECK(t("VisString255").size == 255);
  CHECK(t("VisString129").size == 129);
  CHECK(t("Octet64").type == basic_type::octet_string);
  CHECK(t("Octet64").size == 64);
  CHECK(t("Unicode255").type == basic_type::unicode_string);
  CHECK(t("Currency").type == basic_type::visible_string);
  CHECK(t("Currency").size == 3);
  CHECK(t("Struct").is_struct);
  CHECK_FALSE(t("Struct").type);
  CHECK_FALSE(t("PhyComAddr").type);
  CHECK_FALSE(t("PhyComAddr").is_struct);

  for (auto bad : {"", "Bool", "boolean", "VisString", "VisString0", "VisString08", "Octet-1",
                   "INT33", "Unicode25a", "STRUCT"}) {
    INFO(bad);
    CHECK_FALSE(scl::parse_btype(bad));
  }
}

TEST_CASE("Val text converts to the attribute type", "[scl]") {
  CHECK(std::get<bool>(*scl::parse_value(basic_type::boolean, " true ")));
  CHECK_FALSE(std::get<bool>(*scl::parse_value(basic_type::boolean, "0")));
  CHECK(scl::parse_value(basic_type::boolean, "TRUE").error() == errc::malformed_encoding);

  CHECK(std::get<std::int64_t>(*scl::parse_value(basic_type::int8, "-128")) == -128);
  CHECK(scl::parse_value(basic_type::int8, "128").error() == errc::value_out_of_range);
  CHECK(scl::parse_value(basic_type::int16, "1.5").error() == errc::malformed_encoding);
  CHECK(std::get<std::int64_t>(*scl::parse_value(basic_type::int64, "-9223372036854775808")) ==
        INT64_MIN);
  CHECK(scl::parse_value(basic_type::int128, "99999999999999999999").error() ==
        errc::value_out_of_range);
  CHECK(std::get<std::uint64_t>(*scl::parse_value(basic_type::int32u, "4294967295")) ==
        4294967295U);
  CHECK(scl::parse_value(basic_type::int32u, "4294967296").error() == errc::value_out_of_range);
  CHECK(scl::parse_value(basic_type::int8u, "-1").error() == errc::value_out_of_range);
  CHECK(scl::parse_value(basic_type::int8u, "x").error() == errc::malformed_encoding);

  CHECK(std::get<double>(*scl::parse_value(basic_type::float32, "1.25")) == 1.25);
  CHECK(std::get<double>(*scl::parse_value(basic_type::float64, "-2e300")) == -2e300);
  CHECK(std::isinf(std::get<double>(*scl::parse_value(basic_type::float32, "INF"))));
  CHECK(std::isnan(std::get<double>(*scl::parse_value(basic_type::float32, "NaN"))));
  CHECK(scl::parse_value(basic_type::float32, "1e39").error() == errc::value_out_of_range);
  CHECK(scl::parse_value(basic_type::float64, "1e999").error() == errc::value_out_of_range);
  CHECK(scl::parse_value(basic_type::float64, "-1e999").error() == errc::value_out_of_range);
  CHECK(scl::parse_value(basic_type::float64, "1.5x").error() == errc::malformed_encoding);
  CHECK(scl::parse_value(basic_type::float64, "abc").error() == errc::malformed_encoding);
  CHECK(scl::parse_value(basic_type::float32, "1,5").error() == errc::malformed_encoding);

  scl::enum_type e{"E", "", {{-3, "m", ""}, {0, "", ""}, {3, "k", ""}}, 0};
  CHECK(std::get<std::int64_t>(*scl::parse_value(basic_type::enumerated, "k", &e)) == 3);
  CHECK(std::get<std::int64_t>(*scl::parse_value(basic_type::enumerated, "", &e)) == 0);
  CHECK(std::get<std::int64_t>(*scl::parse_value(basic_type::enumerated, "-3", &e)) == -3);
  CHECK(scl::parse_value(basic_type::enumerated, "7", &e).error() == errc::value_out_of_range);
  CHECK(scl::parse_value(basic_type::enumerated, "M", &e).error() == errc::malformed_encoding);
  CHECK(std::get<std::int64_t>(*scl::parse_value(basic_type::enumerated, "7")) == 7);

  CHECK(std::get<std::string>(*scl::parse_value(basic_type::visible_string, "a b")) == "a b");
  CHECK(std::get<std::string>(*scl::parse_value(basic_type::dbpos, "on")) == "on");
}
