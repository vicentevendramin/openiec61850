#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstdint>
#include <limits>
#include <vector>

#include "mms_test_util.hpp"
#include "openiec61850/mms/data.hpp"

namespace mms = openiec61850::mms;
namespace ber = openiec61850::ber;
using mms_test::hex;
using openiec61850::byte_buffer;
using openiec61850::byte_view;
using openiec61850::errc;

namespace {

byte_buffer encode(const mms::data& d) {
  byte_buffer out;
  REQUIRE(mms::encode_data(d, out));
  return out;
}

mms::data round_trip(const mms::data& d) {
  const auto bytes = encode(d);
  auto v = mms::data_view::parse(bytes);
  REQUIRE(v);
  CHECK(v->type() == d.type());
  CHECK(v->encoding().size() == bytes.size());
  auto copy = mms::data::from_view(*v);
  REQUIRE(copy);
  CHECK(encode(*copy) == bytes);
  return *copy;
}

const byte_buffer quality_bytes{0x00, 0x08};

}  // namespace

TEST_CASE("Data scalar known answers", "[mms]") {
  CHECK(encode(mms::data::boolean(true)) == hex("83 01 FF"));
  CHECK(encode(mms::data::integer(-1)) == hex("85 01 FF"));
  CHECK(encode(mms::data::integer(1000)) == hex("85 02 03 E8"));
  CHECK(encode(mms::data::unsigned_integer(255)) == hex("86 02 00 FF"));
  CHECK(encode(mms::data::floating_point(123.5F)) == hex("87 05 08 42 F7 00 00"));
  CHECK(encode(mms::data::floating_point(1.0)) == hex("87 09 0B 3F F0 00 00 00 00 00 00"));
  CHECK(encode(mms::data::bit_string(quality_bytes, 13)) == hex("84 03 03 00 08"));
  CHECK(encode(mms::data::octet_string(hex("01 02"))) == hex("89 02 01 02"));
  CHECK(encode(mms::data::visible_string("LD0")) == hex("8A 03 'LD0'"));
  CHECK(encode(mms::data::generalized_time("20200101120000Z")) ==
        hex("8B 0F '20200101120000Z'"));
  CHECK(encode(mms::data::binary_time({1000, 1})) == hex("8C 06 00 00 03 E8 00 01"));
  CHECK(encode(mms::data::binary_time({1000, std::nullopt})) == hex("8C 04 00 00 03 E8"));
  CHECK(encode(mms::data::bcd(42)) == hex("8D 01 2A"));
  CHECK(encode(mms::data::boolean_array(hex("A0"), 3)) == hex("8E 02 05 A0"));
  CHECK(encode(mms::data::obj_id({1, 0, 9506, 2, 1})) == hex("8F 05 28 CA 22 02 01"));
  CHECK(encode(mms::data::mms_string("\xC3\xA9")) == hex("90 02 C3 A9"));
  CHECK(encode(mms::data::utc_time({0x5F5E1000, 0x800000, 0x0A})) ==
        hex("91 08 5F 5E 10 00 80 00 00 0A"));
  CHECK(encode(mms::data::structure({})) == hex("A2 00"));
  CHECK(encode(mms::data::array({mms::data::integer(1), mms::data::integer(2)})) ==
        hex("A1 06 85 01 01 85 01 02"));
}

TEST_CASE("Data round trips every alternative", "[mms]") {
  const std::vector<mms::data> values{
      mms::data::boolean(false),
      mms::data::boolean(true),
      mms::data::bit_string(quality_bytes, 13),
      mms::data::bit_string({}, 0),
      mms::data::integer(std::numeric_limits<std::int64_t>::min()),
      mms::data::integer(std::numeric_limits<std::int64_t>::max()),
      mms::data::unsigned_integer(0),
      mms::data::unsigned_integer(std::numeric_limits<std::uint64_t>::max()),
      mms::data::floating_point(-0.25F),
      mms::data::floating_point(3.141592653589793),
      mms::data::octet_string(hex("00 FF 10")),
      mms::data::visible_string(""),
      mms::data::visible_string("IED1LD0/LLN0"),
      mms::data::generalized_time("19840101000000.000Z"),
      mms::data::binary_time({86'399'999, 0xFFFF}),
      mms::data::binary_time({0, std::nullopt}),
      mms::data::bcd(1234),
      mms::data::boolean_array(hex("F0 80"), 9),
      mms::data::obj_id({2, 999, 3}),
      mms::data::mms_string("caf\xC3\xA9"),
      mms::data::utc_time({1, 2, 3}),
      mms::data::array({mms::data::floating_point(1.5F), mms::data::floating_point(2.5F)}),
      mms::data::structure({mms::data::structure({mms::data::integer(7)}),
                            mms::data::array({}), mms::data::visible_string("x")}),
  };
  for (const auto& v : values) {
    CHECK(round_trip(v) == v);
  }
}

TEST_CASE("data_view accessors", "[mms]") {
  const auto bytes = hex("A2 18 A2 07 87 05 08 42 F7 00 00 84 03 03 00 08 91 08 5F 5E 10 00 80 00 00 0A");
  auto v = mms::data_view::parse(bytes);
  REQUIRE(v);
  CHECK(v->type() == mms::data_type::structure);
  CHECK(v->size() == 3);

  std::vector<mms::data_type> types;
  for (const auto& e : v->elements()) types.push_back(e.type());
  CHECK(types == std::vector{mms::data_type::structure, mms::data_type::bit_string,
                             mms::data_type::utc_time});

  auto mag = v->at(0);
  REQUIRE(mag);
  auto f = mag->at(0);
  REQUIRE(f);
  CHECK(*f->as_float() == 123.5F);
  CHECK(*f->as_double() == 123.5);
  CHECK_FALSE(f->is_double());

  auto q = v->at(1)->as_bit_string();
  REQUIRE(q);
  CHECK(q->bit_count == 13);
  CHECK(q->test(12));
  CHECK_FALSE(q->test(0));

  auto t = v->at(2)->as_utc_time();
  REQUIRE(t);
  CHECK(t->seconds == 1'600'000'000U);
  CHECK(t->fraction == 0x800000U);
  CHECK(t->accuracy() == 10);

  CHECK(v->at(3).error() == errc::value_out_of_range);
  CHECK(v->as_boolean().error() == errc::invalid_state);
  CHECK(f->as_int64().error() == errc::invalid_state);
  CHECK(v->at(1)->elements().empty());
}

TEST_CASE("data_view integer accessors check the range", "[mms]") {
  const auto i_bytes = hex("85 02 01 00");
  auto i = mms::data_view::parse(i_bytes);
  REQUIRE(i);
  CHECK(*i->as_integer<std::int16_t>() == 256);
  CHECK(i->as_integer<std::int8_t>().error() == errc::value_out_of_range);
  CHECK(*i->as_uint64() == 256U);
  const auto n_bytes = hex("85 01 FF");
  auto n = mms::data_view::parse(n_bytes);
  REQUIRE(n);
  CHECK(n->as_uint64().error() == errc::value_out_of_range);
  const auto u_bytes = hex("86 09 00 FF FF FF FF FF FF FF FF");
  auto u = mms::data_view::parse(u_bytes);
  REQUIRE(u);
  CHECK(*u->as_uint64() == std::numeric_limits<std::uint64_t>::max());
  CHECK(u->as_int64().error() == errc::value_out_of_range);
  const auto d_bytes = hex("87 09 0B 3F F0 00 00 00 00 00 00");
  auto d = mms::data_view::parse(d_bytes);
  REQUIRE(d);
  CHECK(d->is_double());
  CHECK(*d->as_double() == 1.0);
  CHECK(d->as_float().error() == errc::value_out_of_range);
  const auto other_bytes = hex("87 03 04 01 02");
  auto other = mms::data_view::parse(other_bytes);
  REQUIRE(other);
  CHECK(other->as_double().error() == errc::unsupported);
}

TEST_CASE("UtcTime chrono conversions", "[mms]") {
  using namespace std::chrono;
  const sys_time<milliseconds> tp{seconds{1'600'000'000} + milliseconds{500}};
  auto t = mms::utc_time::from_time_point(tp, mms::utc_time::leap_seconds_known | 10);
  REQUIRE(t);
  CHECK(t->seconds == 1'600'000'000U);
  CHECK(t->fraction == 0x800000U);
  CHECK(t->quality == 0x8A);
  CHECK(t->to_time_point() == tp);
  CHECK(t->to_bytes() == std::array<std::uint8_t, 8>{0x5F, 0x5E, 0x10, 0x00, 0x80, 0x00, 0x00, 0x8A});

  // Every 24-bit fraction survives a round trip through nanoseconds.
  for (std::uint32_t f : {0U, 1U, 2U, 0x7FFFFFU, 0xABCDEFU, 0xFFFFFEU, 0xFFFFFFU}) {
    const mms::utc_time u{10, f, 0};
    auto back = mms::utc_time::from_time_point(u.to_time_point());
    REQUIRE(back);
    CHECK(back->fraction == f);
    CHECK(back->seconds == 10U);
  }
  // Rounding never carries into the seconds.
  auto near = mms::utc_time::from_time_point(sys_time<nanoseconds>{seconds{5} + nanoseconds{999'999'999}});
  REQUIRE(near);
  CHECK(near->seconds == 5U);
  CHECK(near->fraction == 0xFFFFFFU);

  CHECK(mms::utc_time::from_time_point(sys_seconds{seconds{-1}}).error() == errc::value_out_of_range);
  CHECK(mms::utc_time::from_time_point(sys_seconds{seconds{std::int64_t{1} << 32}}).error() ==
        errc::value_out_of_range);
}

TEST_CASE("TimeOfDay chrono conversions", "[mms]") {
  using namespace std::chrono;
  const sys_time<milliseconds> tp{sys_days{year{1984} / 1 / 2} + seconds{1}};
  auto t = mms::binary_time::from_time_point(tp);
  REQUIRE(t);
  CHECK(t->days == 1);
  CHECK(t->ms_of_day == 1000U);
  CHECK(*t->to_time_point() == tp);
  CHECK(mms::binary_time{5, std::nullopt}.to_time_point().error() == errc::invalid_state);
  CHECK(mms::binary_time::from_time_point(sys_days{year{1983} / 12 / 31}).error() ==
        errc::value_out_of_range);
}

TEST_CASE("Data nesting limit", "[mms]") {
  auto nested = [](std::size_t levels) {
    mms::data d = mms::data::integer(1);
    for (std::size_t i = 0; i < levels; ++i) d = mms::data::structure({d});
    return encode(d);
  };
  const mms::decode_options opts{.max_nesting = 4};
  CHECK(mms::data_view::parse(nested(4), opts));
  CHECK(mms::data_view::parse(nested(5), opts).error() == errc::nesting_too_deep);
  CHECK(mms::data_view::parse(nested(32)));
  CHECK(mms::data_view::parse(nested(33)).error() == errc::nesting_too_deep);
  CHECK(mms::data_view::parse(hex("85 01 01"), {.max_nesting = 0}));
  CHECK(mms::data_view::parse(hex("A2 00"), {.max_nesting = 0}).error() == errc::nesting_too_deep);
}

TEST_CASE("Malformed Data is rejected", "[mms]") {
  auto err = [](std::string_view h) { return mms::data_view::parse(hex(h)).error(); };
  CHECK(err("") == errc::truncated_input);
  CHECK(err("A2 03 83 01") == errc::length_overflow);
  CHECK(err("83 01 FF 00") == errc::malformed_encoding);  // trailing
  CHECK(err("80 00") == errc::malformed_encoding);        // [0] is not Data
  CHECK(err("88 01 00") == errc::unsupported);            // [8] real
  CHECK(err("92 00") == errc::malformed_encoding);        // [18]
  CHECK(err("03 02 00 00") == errc::malformed_encoding);  // universal class
  CHECK(err("A3 03 01 01 FF") == errc::malformed_encoding);  // constructed boolean
  CHECK(err("82 00") == errc::malformed_encoding);           // primitive structure
  CHECK(err("A9 00") == errc::unsupported);                  // segmented octet string
  CHECK(err("83 02 00 00") == errc::malformed_encoding);
  CHECK_FALSE(mms::data_view::parse(hex("84 00")));
  CHECK(err("84 02 08 FF") == errc::malformed_encoding);  // unused bits > 7
  CHECK_FALSE(mms::data_view::parse(hex("85 00")));
  CHECK(err("85 09 01 00 00 00 00 00 00 00 00") == errc::value_out_of_range);
  CHECK(err("86 01 FF") == errc::value_out_of_range);  // negative unsigned
  CHECK(err("87 01 08") == errc::malformed_encoding);
  CHECK(err("8C 05 00 00 00 00 00") == errc::malformed_encoding);
  CHECK(err("91 07 00 00 00 00 00 00 00") == errc::malformed_encoding);
  CHECK_FALSE(mms::data_view::parse(hex("8F 01 80")));
  CHECK(err("A2 05 A2 03 92 01 00") == errc::malformed_encoding);  // bad nested element
}

TEST_CASE("Owned data accessors and mutation", "[mms]") {
  auto s = mms::data::structure({mms::data::integer(-5)});
  CHECK(s.elements().size() == 1);
  CHECK(*s.elements()[0].as_int64() == -5);
  CHECK(s.elements()[0].as_uint64().error() == errc::value_out_of_range);
  auto children = s.mutable_elements();
  REQUIRE(children);
  (*children)->push_back(mms::data::visible_string("ok"));
  CHECK(*s.elements()[1].as_visible_string() == "ok");
  CHECK(mms::data::integer(1).mutable_elements().error() == errc::invalid_state);
  CHECK(mms::data::floating_point(2.0).as_float().error() == errc::value_out_of_range);
  CHECK(*mms::data::floating_point(2.0F).as_double() == 2.0);
  // Padding bits are cleared and missing octets zero-filled.
  auto bits = mms::data::bit_string(hex("FF"), 13);
  CHECK(encode(bits) == hex("84 03 03 FF 00"));
  CHECK(encode(mms::data::bit_string(hex("FF FF"), 4)) == hex("84 02 04 F0"));

  byte_buffer out{0xEE};
  CHECK(mms::encode_data(mms::data{}, out).error() == errc::invalid_state);
  CHECK(mms::encode_data(mms::data::structure({mms::data{}}), out).error() == errc::invalid_state);
  CHECK(mms::encode_data(mms::data::obj_id({}), out).error() == errc::invalid_state);
  CHECK(out == byte_buffer{0xEE});
}

TEST_CASE("data_ref encodes views verbatim and owned values", "[mms]") {
  const auto bytes = hex("A1 06 85 01 01 85 01 02");
  auto v = mms::data_view::parse(bytes);
  REQUIRE(v);
  const auto owned = mms::data::boolean(true);
  byte_buffer out;
  ber::writer w{out};
  REQUIRE(mms::data_ref{*v}.encode(w));
  REQUIRE(mms::data_ref{owned}.encode(w));
  CHECK(out == hex("A1 06 85 01 01 85 01 02 83 01 FF"));
  CHECK(mms::data_ref{}.encode(w).error() == errc::invalid_state);
}
