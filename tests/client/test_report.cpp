#include <catch2/catch_test_macros.hpp>

#include <vector>

#include "client_test_util.hpp"
#include "openiec61850/client/report.hpp"

namespace client = openiec61850::client;
namespace mms = openiec61850::mms;
namespace model = openiec61850::model;
using client_test::ref;
using openiec61850::byte_buffer;
using openiec61850::errc;
using model::optional_field;

namespace {

mms::data vs(std::string_view s) { return mms::data::visible_string(s); }

mms::data bits(std::initializer_list<int> set, std::size_t count) {
  byte_buffer b((count + 7) / 8, 0);
  for (const int i : set) {
    const auto u = static_cast<std::size_t>(i);
    b[u / 8] = static_cast<std::uint8_t>(b[u / 8] | (0x80U >> (u % 8)));
  }
  return mms::data::bit_string(b, count);
}

// Owns the values of a locally built InformationReport.
struct built {
  explicit built(std::vector<mms::data> v, std::string_view name = "RPT") : values(std::move(v)) {
    for (const auto& d : values) results.emplace_back(mms::data_ref(d));
    ir = {mms::variable_access_specification::named(mms::object_name::vmd(name)), results};
  }
  std::vector<mms::data> values;
  std::vector<mms::access_result> results;
  mms::information_report ir;
};

const std::vector<model::object_reference>& members() {
  static const std::vector<model::object_reference> m{
      ref("IED1LD0/MMXU1.TotW[MX]"), ref("IED1LD0/XCBR1.Pos.stVal[ST]"),
      ref("IED1LD0/XCBR1.Pos.q[ST]"), ref("IED1LD0/MMXU1.PhV.phsA.cVal.mag.f[MX]")};
  return m;
}

}  // namespace

TEST_CASE("report without optional fields", "[client]") {
  const built b({vs("rpt1"), model::optional_fields{}.to_mms(), bits({1, 3}, 4),
                 mms::data::boolean(true), mms::data::floating_point(2.0F)});
  REQUIRE(client::is_report(b.ir));
  auto r = client::parse_report(b.ir, members());
  REQUIRE(r);
  CHECK(r->rpt_id == "rpt1");
  CHECK(!r->seq_num);
  CHECK(!r->entry_id);
  CHECK(r->inclusion == std::vector<bool>{false, true, false, true});
  REQUIRE(r->entries.size() == 2);
  CHECK(r->entries[0].index == 1);
  CHECK(r->entries[0].reference == ref("IED1LD0/XCBR1.Pos.stVal[ST]"));
  CHECK(r->entries[0].data_reference.empty());
  CHECK(r->entries[0].value == mms::data::boolean(true));
  CHECK(!r->entries[0].reason);
  CHECK(r->entries[1].index == 3);
  CHECK(r->entries[1].reference == ref("IED1LD0/MMXU1.PhV.phsA.cVal.mag.f[MX]"));

  // Without the data set directory the entries are unnamed.
  auto anonymous = client::parse_report(b.ir);
  REQUIRE(anonymous);
  CHECK(!anonymous->entries[0].reference);
}

TEST_CASE("report with every optional field", "[client]") {
  const auto opt = model::optional_fields::of(
      {optional_field::sequence_number, optional_field::report_time_stamp,
       optional_field::reason_for_inclusion, optional_field::data_set_name,
       optional_field::data_reference, optional_field::buffer_overflow, optional_field::entry_id,
       optional_field::conf_revision});
  const model::entry_id id({0, 0, 0, 0, 0, 0, 0, 9});
  const mms::binary_time when{1000, std::uint16_t{14000}};
  const built b({vs("brcb01-id"), opt.to_mms(), mms::data::unsigned_integer(7),
                 mms::data::binary_time(when), vs("IED1LD0/LLN0$DS1"), mms::data::boolean(false),
                 id.to_mms(), mms::data::unsigned_integer(3), bits({0}, 4),
                 vs("IED1LD0/MMXU1$MX$TotW"),
                 mms::data::structure({mms::data::floating_point(1.0F)}),
                 *model::trigger_conditions::of({model::trigger::data_change, model::trigger::integrity})
                      .to_mms_reason_code()});
  auto r = client::parse_report(b.ir);
  REQUIRE(r);
  CHECK(r->opt_flds == opt);
  CHECK(r->seq_num == 7U);
  CHECK(r->time_of_entry == when);
  CHECK(r->data_set == "IED1LD0/LLN0$DS1");
  CHECK(r->buffer_overflow == false);
  CHECK(r->entry_id == id);
  CHECK(r->conf_rev == 3U);
  CHECK(!r->sub_seq_num);
  REQUIRE(r->entries.size() == 1);
  const auto& e = r->entries[0];
  CHECK(e.data_reference == "IED1LD0/MMXU1$MX$TotW");
  CHECK(e.reference == ref("IED1LD0/MMXU1.TotW[MX]"));
  REQUIRE(e.reason);
  CHECK(e.reason->data_change());
  CHECK(e.reason->integrity());
  CHECK(!e.reason->general_interrogation());
}

TEST_CASE("segmented reports and Ed.1 reason codes", "[client]") {
  const auto opt = model::optional_fields::of(
      {optional_field::sequence_number, optional_field::segmentation,
       optional_field::reason_for_inclusion});
  const built b({vs("r"), opt.to_mms(), mms::data::unsigned_integer(1),
                 mms::data::unsigned_integer(2), mms::data::boolean(true), bits({2, 3}, 4),
                 mms::data::integer(1), mms::data::integer(2),
                 bits({5}, 6), bits({1, 2}, 6)});
  auto r = client::parse_report(b.ir, members());
  REQUIRE(r);
  CHECK(r->sub_seq_num == 2U);
  CHECK(r->more_segments_follow == true);
  REQUIRE(r->entries.size() == 2);
  CHECK(r->entries[0].reason->general_interrogation());
  CHECK(r->entries[1].reason->data_change());
  CHECK(r->entries[1].reason->quality_change());
}

TEST_CASE("malformed reports", "[client]") {
  const auto none = model::optional_fields{}.to_mms();
  // Missing value for an included member.
  CHECK(client::parse_report(built({vs("r"), none, bits({0, 1}, 4), mms::data::integer(1)}).ir)
            .error() == errc::protocol_violation);
  // Extra trailing value.
  CHECK(client::parse_report(
            built({vs("r"), none, bits({0}, 4), mms::data::integer(1), mms::data::integer(2)}).ir)
            .error() == errc::protocol_violation);
  // RptID of the wrong type.
  CHECK(client::parse_report(built({mms::data::integer(1), none, bits({}, 4)}).ir).error() ==
        errc::protocol_violation);
  // Missing header fields announced by OptFlds.
  const auto seq = model::optional_fields::of({optional_field::sequence_number}).to_mms();
  CHECK(client::parse_report(built({vs("r"), seq, bits({}, 4)}).ir).error() ==
        errc::protocol_violation);
  // data-reference announced but no references: the layout IEC61850bean 1.9.0 sends. The values
  // are not visible strings, so nothing may be guessed from them.
  const auto refs = model::optional_fields::of({optional_field::data_reference}).to_mms();
  CHECK(client::parse_report(built({vs("r"), refs, bits({0}, 4), mms::data::boolean(true)}).ir)
            .error() == errc::protocol_violation);
  // Inclusion longer than the data set.
  CHECK(client::parse_report(built({vs("r"), none, bits({}, 5)}).ir, members()).error() ==
        errc::protocol_violation);
  // Not a report.
  const built other({vs("r")}, "LastApplError");
  CHECK(!client::is_report(other.ir));
  CHECK(client::parse_report(other.ir).error() == errc::unsupported);
  // A failure access result.
  std::vector<mms::access_result> results{mms::access_result(mms::data_access_error::object_invalidated)};
  const mms::information_report failed{
      mms::variable_access_specification::named(mms::object_name::vmd("RPT")), results};
  CHECK(client::parse_report(failed).error() == errc::protocol_violation);
}
