#include <catch2/catch_test_macros.hpp>

#include <chrono>

#include "../mms/mms_test_util.hpp"
#include "openiec61850/model/entry_id.hpp"
#include "openiec61850/model/enums.hpp"
#include "openiec61850/model/quality.hpp"
#include "openiec61850/model/rcb_options.hpp"
#include "openiec61850/model/timestamp.hpp"

namespace model = openiec61850::model;
namespace mms = openiec61850::mms;
using mms_test::hex;
using model::quality;
using model::quality_flag;
using openiec61850::byte_buffer;
using openiec61850::errc;

namespace {

byte_buffer encode(const mms::data& d) {
  byte_buffer out;
  REQUIRE(mms::encode_data(d, out));
  return out;
}

mms::data_view view(const byte_buffer& bytes) {
  auto v = mms::data_view::parse(bytes);
  REQUIRE(v);
  return *v;
}

}  // namespace

TEST_CASE("Quality bit layout", "[model]") {
  const auto enc = [](quality q) { return encode(q.to_mms()); };
  CHECK(enc(quality{}) == hex("84 03 03 00 00"));
  CHECK(enc(quality{}.set_validity(model::validity::invalid)) == hex("84 03 03 40 00"));
  CHECK(enc(quality{}.set_validity(model::validity::reserved)) == hex("84 03 03 80 00"));
  CHECK(enc(quality{}.set_validity(model::validity::questionable)) == hex("84 03 03 C0 00"));
  CHECK(enc(quality{}.set(quality_flag::overflow)) == hex("84 03 03 20 00"));
  CHECK(enc(quality{}.set(quality_flag::out_of_range)) == hex("84 03 03 10 00"));
  CHECK(enc(quality{}.set(quality_flag::bad_reference)) == hex("84 03 03 08 00"));
  CHECK(enc(quality{}.set(quality_flag::oscillatory)) == hex("84 03 03 04 00"));
  CHECK(enc(quality{}.set(quality_flag::failure)) == hex("84 03 03 02 00"));
  CHECK(enc(quality{}.set(quality_flag::old_data)) == hex("84 03 03 01 00"));
  CHECK(enc(quality{}.set(quality_flag::inconsistent)) == hex("84 03 03 00 80"));
  CHECK(enc(quality{}.set(quality_flag::inaccurate)) == hex("84 03 03 00 40"));
  CHECK(enc(quality{}.set_source(model::source::substituted)) == hex("84 03 03 00 20"));
  CHECK(enc(quality{}.set(quality_flag::test)) == hex("84 03 03 00 10"));
  CHECK(enc(quality{}.set(quality_flag::operator_blocked)) == hex("84 03 03 00 08"));

  auto q = quality{}
               .set_validity(model::validity::questionable)
               .set(quality_flag::old_data)
               .set(quality_flag::test);
  CHECK(q.to_bytes() == std::array<std::uint8_t, 2>{0xC1, 0x10});
  CHECK(q.validity() == model::validity::questionable);
  CHECK(q.old_data());
  CHECK(q.test());
  CHECK_FALSE(q.failure());
  CHECK_FALSE(q.is_good());
  CHECK(q.source() == model::source::process);
  CHECK(model::to_string(q) == "questionable|oldData|test");
  CHECK(model::to_string(quality{}) == "good");
  q.set(quality_flag::test, false);
  CHECK_FALSE(q.test());
  CHECK(quality::from_raw(0xFFFF).raw() == quality::mask);
}

TEST_CASE("Quality from MMS", "[model]") {
  const auto bytes = hex("84 03 03 41 08");
  auto q = quality::from_mms(view(bytes));
  REQUIRE(q);
  CHECK(q->validity() == model::validity::invalid);
  CHECK(q->old_data());
  CHECK(q->operator_blocked());
  CHECK(encode(q->to_mms()) == bytes);

  auto owned = quality::from_mms(q->to_mms());
  REQUIRE(owned);
  CHECK(*owned == *q);

  for (std::uint16_t raw = 0; raw <= quality::mask; ++raw) {
    const auto x = quality::from_raw(raw);
    auto back = quality::from_mms(x.to_mms());
    REQUIRE(back);
    CHECK(*back == x);
  }

  // Tolerant widths: a short string reads missing bits as zero, extra bits are ignored.
  auto shorter = quality::from_mms(view(hex("84 02 06 40")));
  REQUIRE(shorter);
  CHECK(shorter->validity() == model::validity::invalid);
  auto longer = quality::from_mms(view(hex("84 03 00 00 0F")));
  REQUIRE(longer);
  CHECK(longer->raw() == static_cast<std::uint16_t>(quality_flag::operator_blocked));

  CHECK(quality::from_mms(mms::data::integer(0)).error() == errc::invalid_state);
}

TEST_CASE("Timestamp layout and chrono conversions", "[model]") {
  using namespace std::chrono;
  const sys_time<milliseconds> tp{sys_days{year{2020} / 1 / 1} + milliseconds{500}};
  auto ts = model::timestamp::from_time_point(tp, model::time_accuracy_class::t1);
  REQUIRE(ts);
  CHECK(ts->seconds() == 1577836800U);
  CHECK(ts->fraction() == 0x800000U);
  CHECK(ts->time_accuracy() == 10);
  CHECK_FALSE(ts->leap_seconds_known());
  CHECK(ts->to_time_point() == tp);
  CHECK(encode(ts->to_mms()) == hex("91 08 5E 0B E1 00 80 00 00 0A"));

  ts->set_leap_seconds_known(true).set_clock_failure(true).set_clock_not_synchronized(true);
  CHECK(ts->time_quality() == 0xEA);
  CHECK(encode(ts->to_mms()) == hex("91 08 5E 0B E1 00 80 00 00 EA"));
  ts->set_clock_failure(false).set_time_accuracy(model::time_accuracy_class::unspecified);
  CHECK(ts->time_quality() == 0xBF);
  CHECK_FALSE(ts->clock_failure());
  CHECK(ts->clock_not_synchronized());
  CHECK_FALSE(ts->accuracy());

  auto back = model::timestamp::from_mms(view(hex("91 08 5E 0B E1 00 80 00 00 EA")));
  REQUIRE(back);
  CHECK(back->leap_seconds_known());
  CHECK(back->clock_failure());
  CHECK(back->clock_not_synchronized());
  CHECK(back->time_accuracy() == 10);
  CHECK(back->accuracy() == nanoseconds{976563});
  CHECK(back->to_time_point() == tp);
  CHECK(model::timestamp::from_mms(mms::data::boolean(true)).error() == errc::invalid_state);

  CHECK(model::timestamp{}.set_time_accuracy(0).accuracy() == seconds{1});
  CHECK(model::timestamp{}.set_time_accuracy(24).accuracy() == nanoseconds{60});
  CHECK_FALSE(model::timestamp{}.set_time_accuracy(25).accuracy());

  CHECK(model::timestamp::from_time_point(sys_days{year{1969} / 12 / 31}).error() ==
        errc::value_out_of_range);
  const auto now = model::timestamp::now(model::time_accuracy_class::t5);
  CHECK(now.seconds() > 1577836800U);
  CHECK(now.time_accuracy() == 20);

  const model::entry_time et{1000, 1};
  CHECK(encode(model::to_mms(et)) == hex("8C 06 00 00 03 E8 00 01"));
  auto et_back = model::entry_time_from_mms(view(hex("8C 06 00 00 03 E8 00 01")));
  REQUIRE(et_back);
  CHECK(*et_back == et);
}

TEST_CASE("Coded and enumerated attribute types", "[model]") {
  CHECK(encode(model::to_mms(model::dbpos::intermediate)) == hex("84 02 06 00"));
  CHECK(encode(model::to_mms(model::dbpos::off)) == hex("84 02 06 40"));
  CHECK(encode(model::to_mms(model::dbpos::on)) == hex("84 02 06 80"));
  CHECK(encode(model::to_mms(model::dbpos::bad)) == hex("84 02 06 C0"));
  CHECK(encode(model::to_mms(model::step_command::lower)) == hex("84 02 06 40"));
  CHECK(encode(model::to_mms(model::step_command::higher)) == hex("84 02 06 80"));
  for (auto v : {model::dbpos::intermediate, model::dbpos::off, model::dbpos::on,
                 model::dbpos::bad}) {
    auto back = model::dbpos_from_mms(view(encode(model::to_mms(v))));
    REQUIRE(back);
    CHECK(*back == v);
  }
  auto step = model::step_command_from_mms(model::to_mms(model::tcmd::stop));
  REQUIRE(step);
  CHECK(*step == model::tcmd::stop);
  CHECK(model::dbpos_from_mms(mms::data::integer(1)).error() == errc::invalid_state);

  const model::check_conditions sync{true, false};
  const model::check_conditions both{true, true};
  CHECK(encode(sync.to_mms()) == hex("84 02 06 80"));
  CHECK(encode(model::check_conditions{false, true}.to_mms()) == hex("84 02 06 40"));
  auto c = model::check_conditions::from_mms(view(hex("84 02 06 C0")));
  REQUIRE(c);
  CHECK(*c == both);

  CHECK(encode(model::to_mms(model::orcat::remote_control)) == hex("85 01 03"));
  auto o = model::orcat_from_mms(view(hex("85 01 08")));
  REQUIRE(o);
  CHECK(*o == model::orcat::process);
  CHECK(model::orcat_from_mms(view(hex("85 01 09"))).error() == errc::value_out_of_range);
  CHECK(model::orcat_from_mms(view(hex("85 01 FF"))).error() == errc::value_out_of_range);
  auto o2 = model::orcat_from_mms(mms::data::unsigned_integer(2));
  REQUIRE(o2);
  CHECK(*o2 == model::orcat::station_control);
  CHECK(model::orcat_from_mms(mms::data::boolean(true)).error() == errc::invalid_state);

  auto cm = model::ctl_model_from_mms(view(hex("85 01 04")));
  REQUIRE(cm);
  CHECK(*cm == model::ctl_model::sbo_with_enhanced_security);
  CHECK(model::ctl_model_from_mms(view(hex("85 01 05"))).error() == errc::value_out_of_range);
  auto beh = model::behaviour_from_mms(model::to_mms(model::behaviour::test_blocked));
  REQUIRE(beh);
  CHECK(*beh == model::behaviour::test_blocked);
  CHECK(model::behaviour_from_mms(mms::data::integer(0)).error() == errc::value_out_of_range);
  auto h = model::health_from_mms(view(hex("85 01 03")));
  REQUIRE(h);
  CHECK(*h == model::health::alarm);

  CHECK(model::to_string(model::dbpos::bad) == "bad-state");
  CHECK(model::to_string(model::orcat::automatic_remote) == "automatic-remote");
  CHECK(model::to_string(model::ctl_model::sbo_with_enhanced_security) ==
        "sbo-with-enhanced-security");
  CHECK(model::to_string(model::behaviour::on_blocked) == "on-blocked");
  CHECK(model::to_string(model::health::ok) == "Ok");
  CHECK(model::to_string(model::step_command::higher) == "higher");
}

TEST_CASE("EntryID", "[model]") {
  auto e = model::entry_id::parse_hex("0001020304a5B6ff");
  REQUIRE(e);
  CHECK(e->to_hex() == "0001020304A5B6FF");
  CHECK(encode(e->to_mms()) == hex("89 08 00 01 02 03 04 A5 B6 FF"));
  auto back = model::entry_id::from_mms(view(hex("89 08 00 01 02 03 04 A5 B6 FF")));
  REQUIRE(back);
  CHECK(*back == *e);
  CHECK_FALSE(e->is_zero());
  CHECK(model::entry_id{}.is_zero());
  CHECK(model::entry_id{} < *e);

  CHECK(model::entry_id::from_mms(view(hex("89 07 00 01 02 03 04 05 06"))).error() ==
        errc::value_out_of_range);
  CHECK(model::entry_id::from_mms(mms::data::visible_string("x")).error() == errc::invalid_state);
  CHECK(model::entry_id::from_bytes(hex("00 01 02 03 04 05 06 07 08")).error() ==
        errc::value_out_of_range);
  CHECK(model::entry_id::parse_hex("0001020304A5B6F").error() == errc::malformed_encoding);
  CHECK(model::entry_id::parse_hex("0001020304A5B6FG").error() == errc::malformed_encoding);
}

TEST_CASE("TrgOps and ReasonCode", "[model]") {
  using model::trigger;
  using model::trigger_conditions;
  const auto t = trigger_conditions::of(
      {trigger::data_change, trigger::integrity, trigger::general_interrogation});
  CHECK(encode(t.to_mms()) == hex("84 02 02 4C"));
  CHECK(t.data_change());
  CHECK_FALSE(t.quality_change());
  CHECK_FALSE(t.data_update());
  CHECK(t.integrity());
  CHECK(t.general_interrogation());

  const auto all = trigger_conditions::of({trigger::data_change, trigger::quality_change,
                                           trigger::data_update, trigger::integrity,
                                           trigger::general_interrogation});
  CHECK(encode(all.to_mms()) == hex("84 02 02 7C"));

  // ReasonCode: 7 bits from Ed.2 (application-trigger), 6 bits in Ed.1.
  const auto dchg = trigger_conditions::of({trigger::data_change});
  auto r2 = dchg.to_mms_reason_code(model::edition::ed2);
  REQUIRE(r2);
  CHECK(encode(*r2) == hex("84 02 01 40"));
  auto r1 = dchg.to_mms_reason_code(model::edition::ed1);
  REQUIRE(r1);
  CHECK(encode(*r1) == hex("84 02 02 40"));
  const auto app = trigger_conditions::of({trigger::application_trigger});
  auto ra = app.to_mms_reason_code();
  REQUIRE(ra);
  CHECK(encode(*ra) == hex("84 02 01 02"));
  CHECK(app.to_mms_reason_code(model::edition::ed1).error() == errc::invalid_state);
  CHECK(encode(app.to_mms()) == hex("84 02 02 00"));  // not part of TrgOps

  auto d = trigger_conditions::from_mms(view(hex("84 02 01 42")));
  REQUIRE(d);
  CHECK(d->data_change());
  CHECK(d->application_trigger());
  auto d1 = trigger_conditions::from_mms(view(hex("84 02 02 7C")));
  REQUIRE(d1);
  CHECK(*d1 == all);
  // The reserved bit 0 is dropped.
  auto reserved = trigger_conditions::from_mms(view(hex("84 02 02 80")));
  REQUIRE(reserved);
  CHECK(reserved->empty());
  CHECK(trigger_conditions::from_mms(mms::data::integer(0)).error() == errc::invalid_state);
}

TEST_CASE("OptFlds", "[model]") {
  using model::optional_field;
  using model::optional_fields;
  const auto o = optional_fields::of(
      {optional_field::sequence_number, optional_field::report_time_stamp,
       optional_field::reason_for_inclusion, optional_field::data_set_name,
       optional_field::entry_id, optional_field::conf_revision});
  CHECK(encode(o.to_mms()) == hex("84 03 06 79 80"));
  CHECK(o.sequence_number());
  CHECK(o.report_time_stamp());
  CHECK(o.reason_for_inclusion());
  CHECK(o.data_set_name());
  CHECK_FALSE(o.data_reference());
  CHECK_FALSE(o.buffer_overflow());
  CHECK(o.entry_id());
  CHECK(o.conf_revision());
  CHECK_FALSE(o.segmentation());

  CHECK(encode(optional_fields::of({optional_field::data_reference}).to_mms()) ==
        hex("84 03 06 04 00"));
  CHECK(encode(optional_fields::of({optional_field::buffer_overflow}).to_mms()) ==
        hex("84 03 06 02 00"));
  CHECK(encode(optional_fields::of({optional_field::segmentation}).to_mms()) ==
        hex("84 03 06 00 40"));

  auto d = optional_fields::from_mms(view(hex("84 03 06 79 80")));
  REQUIRE(d);
  CHECK(*d == o);
  // Same layout for Ed.1 and Ed.2; shorter strings from old servers are accepted.
  auto shorter = optional_fields::from_mms(view(hex("84 02 00 79")));
  REQUIRE(shorter);
  CHECK(*shorter == optional_fields{o}.set(optional_field::conf_revision, false));

  auto full = optional_fields::from_raw(0xFFFF);
  CHECK(full.raw() == optional_fields::mask);
  CHECK(full.configurable(true).raw() == (optional_fields::mask & ~0x200U));
  CHECK_FALSE(full.configurable(false).buffer_overflow());
  CHECK_FALSE(full.configurable(false).entry_id());
  CHECK(full.configurable(false).conf_revision());
  CHECK_FALSE(full.configurable(true).segmentation());
}
