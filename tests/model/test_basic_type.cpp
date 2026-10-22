#include <catch2/catch_test_macros.hpp>

#include "openiec61850/model/basic_type.hpp"

namespace model = openiec61850::model;
namespace mms = openiec61850::mms;
using model::basic_type;
using openiec61850::errc;
using td = mms::type_description;

namespace {

td mms_type(basic_type t, std::int32_t size = 0, model::edition e = model::edition::ed2) {
  auto r = model::to_mms_type(t, size, e);
  REQUIRE(r);
  return *r;
}

}  // namespace

TEST_CASE("Basic types map to MMS TypeDescription", "[model]") {
  CHECK(mms_type(basic_type::boolean) == td::boolean());
  CHECK(mms_type(basic_type::int8) == td::integer(8));
  CHECK(mms_type(basic_type::int16) == td::integer(16));
  CHECK(mms_type(basic_type::int24) == td::integer(24));
  CHECK(mms_type(basic_type::int32) == td::integer(32));
  CHECK(mms_type(basic_type::int64) == td::integer(64));
  CHECK(mms_type(basic_type::int128) == td::integer(128));
  CHECK(mms_type(basic_type::int8u) == td::unsigned_integer(8));
  CHECK(mms_type(basic_type::int16u) == td::unsigned_integer(16));
  CHECK(mms_type(basic_type::int24u) == td::unsigned_integer(24));
  CHECK(mms_type(basic_type::int32u) == td::unsigned_integer(32));
  CHECK(mms_type(basic_type::float32) == td::float32());
  CHECK(mms_type(basic_type::float64) == td::float64());
  CHECK(mms_type(basic_type::enumerated) == td::integer(8));
  CHECK(mms_type(basic_type::coded_enum, 3) == td::bit_string(3));
  CHECK(mms_type(basic_type::packed_list, 5) == td::bit_string(5));
  CHECK(mms_type(basic_type::octet_string, 64) == td::octet_string(-64));
  CHECK(mms_type(basic_type::visible_string, 255) == td::visible_string(-255));
  CHECK(mms_type(basic_type::unicode_string, 255) == td::mms_string(-255));
  CHECK(mms_type(basic_type::timestamp) == td::utc_time());
  CHECK(mms_type(basic_type::entry_time) == td::binary_time(true));
  CHECK(mms_type(basic_type::quality) == td::bit_string(13));
  CHECK(mms_type(basic_type::object_reference) == td::visible_string(-129));
  CHECK(mms_type(basic_type::object_reference, 0, model::edition::ed1) == td::visible_string(-65));
  CHECK(mms_type(basic_type::entry_id) == td::octet_string(8));
  CHECK(mms_type(basic_type::dbpos) == td::bit_string(2));
  CHECK(mms_type(basic_type::tcmd) == td::bit_string(2));
  CHECK(mms_type(basic_type::check) == td::bit_string(2));
  CHECK(mms_type(basic_type::trigger_conditions) == td::bit_string(6));
  CHECK(mms_type(basic_type::optional_fields) == td::bit_string(10));

  for (auto t : {basic_type::coded_enum, basic_type::packed_list, basic_type::octet_string,
                 basic_type::visible_string, basic_type::unicode_string}) {
    CHECK(model::to_mms_type(t).error() == errc::invalid_state);
    CHECK(model::to_mms_type(t, -1).error() == errc::invalid_state);
  }
  CHECK(model::to_mms_type(static_cast<basic_type>(200)).error() == errc::invalid_state);

  // The TypeDescription encodes (e.g. Quality as bit-string 13: 84 01 0D).
  openiec61850::byte_buffer out;
  openiec61850::ber::writer w{out};
  REQUIRE(mms_type(basic_type::quality).encode(w));
  CHECK(out == openiec61850::byte_buffer{0x84, 0x01, 0x0D});
}

TEST_CASE("Basic type names", "[model]") {
  CHECK(model::to_string(basic_type::int32u) == "INT32U");
  CHECK(model::to_string(basic_type::enumerated) == "Enum");
  CHECK(model::to_string(basic_type::object_reference) == "ObjRef");
  CHECK(model::to_string(basic_type::optional_fields) == "OptFlds");
  CHECK(model::to_string(static_cast<basic_type>(200)).empty());
}

TEST_CASE("Basic type deduction from MMS TypeDescription", "[model]") {
  using model::deduce_basic_type;
  CHECK(deduce_basic_type(td::boolean()) == basic_type::boolean);
  CHECK(deduce_basic_type(td::integer(16)) == basic_type::int16);
  CHECK(deduce_basic_type(td::integer(32)) == basic_type::int32);
  CHECK(deduce_basic_type(td::integer(64)) == basic_type::int64);
  CHECK(deduce_basic_type(td::unsigned_integer(8)) == basic_type::int8u);
  CHECK(deduce_basic_type(td::unsigned_integer(32)) == basic_type::int32u);
  CHECK(deduce_basic_type(td::float32()) == basic_type::float32);
  CHECK(deduce_basic_type(td::float64()) == basic_type::float64);
  CHECK(deduce_basic_type(td::bit_string(13)) == basic_type::quality);
  CHECK(deduce_basic_type(td::utc_time()) == basic_type::timestamp);
  CHECK(deduce_basic_type(td::binary_time(true)) == basic_type::entry_time);
  CHECK(deduce_basic_type(td::visible_string(-129)) == basic_type::visible_string);
  CHECK(deduce_basic_type(td::octet_string(8)) == basic_type::octet_string);
  CHECK(deduce_basic_type(td::mms_string(-255)) == basic_type::unicode_string);

  // Ambiguous or without a basic type.
  CHECK_FALSE(deduce_basic_type(td::integer(8)));
  CHECK_FALSE(deduce_basic_type(td::integer(12)));
  CHECK_FALSE(deduce_basic_type(td::unsigned_integer(64)));
  CHECK_FALSE(deduce_basic_type(td::bit_string(2)));
  CHECK_FALSE(deduce_basic_type(td::bit_string(10)));
  CHECK_FALSE(deduce_basic_type(td::binary_time(false)));
  CHECK_FALSE(deduce_basic_type(td::generalized_time()));
  CHECK_FALSE(deduce_basic_type(td::bcd(8)));
  CHECK_FALSE(deduce_basic_type(td::obj_id()));
  CHECK_FALSE(deduce_basic_type(td::array(3, td::boolean())));
  CHECK_FALSE(deduce_basic_type(td::structure({{"stVal", td::boolean()}})));

  // Every unambiguous mapping round trips.
  for (auto t : {basic_type::boolean, basic_type::int16, basic_type::int24, basic_type::int32,
                 basic_type::int64, basic_type::int128, basic_type::int8u, basic_type::int16u,
                 basic_type::int24u, basic_type::int32u, basic_type::float32,
                 basic_type::float64, basic_type::timestamp, basic_type::entry_time,
                 basic_type::quality}) {
    INFO(model::to_string(t));
    CHECK(deduce_basic_type(mms_type(t)) == t);
  }
}
