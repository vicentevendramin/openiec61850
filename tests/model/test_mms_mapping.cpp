#include <catch2/catch_test_macros.hpp>

#include <string>

#include "../mms/mms_test_util.hpp"
#include "openiec61850/model/mms_mapping.hpp"

namespace model = openiec61850::model;
namespace mms = openiec61850::mms;
using mms_test::hex;
using model::fc;
using model::object_reference;
using openiec61850::byte_buffer;
using openiec61850::errc;

namespace {

object_reference parsed(std::string_view text) {
  auto r = object_reference::parse(text);
  REQUIRE(r);
  return *r;
}

model::mms_variable var(std::string_view text) {
  auto v = model::to_mms_variable(parsed(text));
  REQUIRE(v);
  return *v;
}

}  // namespace

TEST_CASE("MMS variable names", "[model]") {
  auto v = var("IED1LD0/Q0XCBR1.Pos.stVal[ST]");
  CHECK(v.name.scope == mms::object_scope::domain_specific);
  CHECK(v.name.domain_id == "IED1LD0");
  CHECK(v.name.item_id == "Q0XCBR1$ST$Pos$stVal");
  CHECK(v.alternate_access.empty());
  CHECK(v.name.view() == mms::object_name::domain("IED1LD0", "Q0XCBR1$ST$Pos$stVal"));
  const auto spec = v.spec();
  CHECK(spec.name == mms::object_name::domain("IED1LD0", "Q0XCBR1$ST$Pos$stVal"));
  CHECK(spec.alternate_access.empty());

  CHECK(var("LD0/MMXU1.PhV.phsA.cVal.mag.f[MX]").name.item_id == "MMXU1$MX$PhV$phsA$cVal$mag$f");
  CHECK(var("LD0/XCBR1.Pos[CO]").name.item_id == "XCBR1$CO$Pos");
  CHECK(var("LD0/LLN0[ST]").name.item_id == "LLN0$ST");
  CHECK(var("LD0/LLN0").name.item_id == "LLN0");

  // Control blocks are FC-constrained names in LLN0 (or any LN).
  CHECK(var("LD0/LLN0.brcb01[BR]").name.item_id == "LLN0$BR$brcb01");
  CHECK(var("LD0/LLN0.urcbA01[RP]").name.item_id == "LLN0$RP$urcbA01");
  CHECK(var("LD0/LLN0.brcb01.RptEna[BR]").name.item_id == "LLN0$BR$brcb01$RptEna");
  CHECK(var("LD0/LLN0.gcb01[GO]").name.item_id == "LLN0$GO$gcb01");
  CHECK(var("LD0/LLN0.SGCB.ActSG[SP]").name.item_id == "LLN0$SP$SGCB$ActSG");
  CHECK(var("LD0/LLN0.log01[LG]").name.item_id == "LLN0$LG$log01");
  CHECK(var("LD0/LLN0.msvcb01[MS]").name.item_id == "LLN0$MS$msvcb01");

  auto item = model::to_mms_item_id(parsed("LD0/LLN0.Mod.stVal[ST]"));
  REQUIRE(item);
  CHECK(*item == "LLN0$ST$Mod$stVal");
}

TEST_CASE("MMS variable mapping errors", "[model]") {
  CHECK(model::to_mms_variable(parsed("LD0/LLN0.Mod.stVal")).error() == errc::invalid_state);
  CHECK(model::to_mms_variable(parsed("LD0/LLN0.Mod[XX]")).error() == errc::invalid_state);
  CHECK(model::to_mms_variable(parsed("LD0")).error() == errc::invalid_state);
  CHECK(model::to_mms_variable(parsed("@ds")).error() == errc::invalid_state);
  CHECK(model::to_mms_variable(object_reference{}).error() == errc::invalid_state);
  CHECK(model::to_mms_item_id(parsed("LD0/GGIO1.Arr(1)[ST]")).error() == errc::invalid_state);

  // Ed.1 MMS identifiers are limited to 32 characters.
  const auto ed1 = model::name_limits::for_edition(model::edition::ed1);
  const auto long_ref = parsed("LD0/LLN0.ABCDEFGHIJKL.MNOPQRSTUVWX[ST]");  // item: 33 characters
  CHECK(model::to_mms_variable(long_ref, ed1).error() == errc::length_overflow);
  CHECK(model::to_mms_variable(long_ref));
  CHECK(model::to_mms_variable(parsed("LD0/LLN0.ABCDEFGHIJKL.MNOPQRSTUVW[ST]"), ed1));
}

TEST_CASE("MMS array elements map to AlternateAccess", "[model]") {
  auto v = var("LD0/GGIO1.Arr(2)[ST]");
  CHECK(v.name.item_id == "GGIO1$ST$Arr");
  CHECK(v.alternate_access == hex("82 01 02"));

  v = var("LD0/GGIO1.Arr(2).f[ST]");
  CHECK(v.name.item_id == "GGIO1$ST$Arr");
  CHECK(v.alternate_access == hex("A0 08 81 01 02 30 03 81 01 'f'"));

  v = var("LD0/GGIO1.Arr(2).f.g[ST]");
  CHECK(v.alternate_access == hex("A0 0F 81 01 02 30 0A A0 08 80 01 'f' 30 03 81 01 'g'"));

  v = var("LD0/GGIO1.Arr(2).sub(1)[ST]");
  CHECK(v.alternate_access == hex("A0 11 81 01 02 30 0C A0 0A 80 03 'sub' 30 03 82 01 01"));

  v = var("LD0/GGIO1.DO.Arr(300)[MX]");
  CHECK(v.name.item_id == "GGIO1$MX$DO$Arr");
  CHECK(v.alternate_access == hex("82 02 01 2C"));
  CHECK(var("LD0/GGIO1.Arr(128)[MX]").alternate_access == hex("82 02 00 80"));

  for (const char* text : {"LD0/GGIO1.Arr(2)[ST]", "LD0/GGIO1.Arr(2).f[ST]",
                           "LD0/GGIO1.Arr(2).f.g[ST]", "LD0/GGIO1.Arr(2).sub(1)[ST]",
                           "LD0/GGIO1.Arr(0).a(1).b(2).c[CF]", "LD0/GGIO1.DO.Arr(300)[MX]"}) {
    INFO(text);
    const auto mv = var(text);
    auto back = model::from_mms_variable(mv.name.view(), mv.alternate_access);
    REQUIRE(back);
    CHECK(back->to_string() == text);
  }
}

TEST_CASE("AlternateAccess encoding", "[model]") {
  byte_buffer out;
  const model::access_selector component{"x", std::nullopt};
  REQUIRE(model::encode_alternate_access(std::span{&component, 1}, out));
  CHECK(out == hex("81 01 'x'"));
  out.clear();
  REQUIRE(model::encode_alternate_access({}, out));
  CHECK(out.empty());
  const model::access_selector bad{"x", 1U};
  CHECK(model::encode_alternate_access(std::span{&bad, 1}, out).error() == errc::invalid_state);
  const model::access_selector bad_name{"$x", std::nullopt};
  CHECK(model::encode_alternate_access(std::span{&bad_name, 1}, out).error() ==
        errc::invalid_state);
}

TEST_CASE("MMS variable reverse mapping", "[model]") {
  auto r = model::from_mms_variable(mms::object_name::domain("IED1LD0", "Q0XCBR1$ST$Pos$stVal"));
  REQUIRE(r);
  CHECK(r->to_string() == "IED1LD0/Q0XCBR1.Pos.stVal[ST]");
  CHECK(r->fc() == fc::ST);

  r = model::from_mms_variable(mms::object_name::domain("LD0", "LLN0$BR$brcb01"));
  REQUIRE(r);
  CHECK(r->to_string() == "LD0/LLN0.brcb01[BR]");
  r = model::from_mms_variable(mms::object_name::domain("LD0", "LLN0$MX"));
  REQUIRE(r);
  CHECK(r->to_string() == "LD0/LLN0[MX]");
  r = model::from_mms_variable(mms::object_name::domain("LD0", "LLN0"));
  REQUIRE(r);
  CHECK(r->to_string() == "LD0/LLN0");
  CHECK_FALSE(r->fc());
  // A component selected through AlternateAccess without an index.
  r = model::from_mms_variable(mms::object_name::domain("LD0", "LLN0$ST$Mod"), hex("81 05 'stVal'"));
  REQUIRE(r);
  CHECK(r->to_string() == "LD0/LLN0.Mod.stVal[ST]");

  for (const char* text :
       {"LD0/LLN0.Mod.stVal[ST]", "LD0/LLN0.Mod.ctlModel[CF]", "LD0/LLN0.urcb01[RP]",
        "LD0/PROT_PTOC1.StrVal.setMag.f[SG]", "LD0/PROT_PTOC1.StrVal.setMag.f[SE]",
        "LD0/LLN0.NamPlt.vendor[DC]", "LD0/MMXU1.TotW.subMag.f[SV]", "LD0/XCBR1.Pos.Oper[CO]",
        "LD0/LLN0.Mod[OR]", "LD0/LLN0.Mod.blkEna[BL]", "LD0/LLN0.Mod[SR]",
        "LD0/LLN0.NamPlt.dataNs[EX]"}) {
    INFO(text);
    const auto mv = var(text);
    auto back = model::from_mms_variable(mv.name.view(), mv.alternate_access);
    REQUIRE(back);
    CHECK(back->to_string() == text);
  }
}

TEST_CASE("Invalid MMS variable names", "[model]") {
  const auto bad = [](mms::object_name n, byte_buffer alt = {}) {
    auto r = model::from_mms_variable(n, alt);
    REQUIRE_FALSE(r);
    return r.error();
  };
  CHECK(bad(mms::object_name::vmd("LLN0$ST$Mod")) == errc::malformed_encoding);
  CHECK(bad(mms::object_name::aa("LLN0$ST$Mod")) == errc::malformed_encoding);
  for (const char* item : {"", "$", "LLN0$", "LLN0$ST$", "LLN0$$Mod", "LLN0$ZZ$Mod",
                           "LLN0$st$Mod", "LLN0$XX$Mod", "LLN0$ST$Mod$", "LLN0$ST$Mod.stVal",
                           "LLN0$ST$Mod(1)", "LLN0$ST$Mod/x", "LLN0$ST$Mod[ST]", "lln0$ST$Mod",
                           "LLN0$ST$0Mod", "$ST$Mod"}) {
    INFO(item);
    CHECK(bad(mms::object_name::domain("LD0", item)) == errc::malformed_encoding);
  }
  CHECK(bad(mms::object_name::domain("", "LLN0$ST$Mod")) == errc::malformed_encoding);
  CHECK(bad(mms::object_name::domain("LD/0", "LLN0$ST$Mod")) == errc::malformed_encoding);
  CHECK(bad(mms::object_name::domain(std::string(65, 'L'), "LLN0")) == errc::length_overflow);

  const auto d = mms::object_name::domain("LD0", "GGIO1$ST$Arr");
  CHECK(bad(mms::object_name::domain("LD0", "GGIO1"), hex("82 01 01")) ==
        errc::malformed_encoding);  // AlternateAccess needs an FC
  CHECK(bad(d, hex("A3 06 80 01 00 81 01 02")) == errc::unsupported);  // indexRange
  CHECK(bad(d, hex("84 00")) == errc::unsupported);                    // allElements
  CHECK(bad(d, hex("A5 06 80 01 'x' 82 01 01")) == errc::unsupported);  // named
  CHECK(bad(d, hex("A0 07 A2 00 30 03 82 01 01")) == errc::unsupported);  // nested indexRange
  CHECK(bad(d, hex("82 01 01 82 01 02")) == errc::unsupported);         // two selections
  CHECK(bad(d, hex("A0 08 81 01 01 30 03 82 01 02")) == errc::unsupported);  // 2-D index
  CHECK(bad(d, hex("82 01")) == errc::length_overflow);
  CHECK(bad(d, hex("82 05 01 00 00 00 00")) == errc::malformed_encoding);  // > 2^32-1
  CHECK(bad(d, hex("82 01 FF")) == errc::malformed_encoding);              // negative
  CHECK(bad(d, hex("81 01 '$'")) == errc::malformed_encoding);
  CHECK(bad(d, hex("A2 03 02 01 01")) == errc::malformed_encoding);        // constructed index
  CHECK(bad(d, hex("86 00")) == errc::malformed_encoding);
  CHECK(bad(d, hex("A0 03 81 01 01")) == errc::truncated_input);  // missing nested access
  CHECK(bad(d, hex("A0 05 81 01 01 30 00")) != errc::ok);            // empty nested access
  CHECK(bad(d, hex("A0 0A 81 01 01 30 03 82 01 01 05 00")) == errc::malformed_encoding);

  // Deep but valid nesting is bounded.
  byte_buffer deep = hex("81 01 'x'");
  for (int i = 0; i < 200; ++i) {
    byte_buffer outer;
    openiec61850::ber::writer w{outer};
    w.constructed(openiec61850::ber::context(0, true), [&] {
      w.write_visible_string("a", openiec61850::ber::context(0));
      w.write_tlv(openiec61850::ber::tags::sequence, deep);
    });
    deep = outer;
  }
  CHECK(bad(d, deep) == errc::nesting_too_deep);
}

TEST_CASE("MMS data set names", "[model]") {
  auto n = model::to_mms_named_variable_list(parsed("LD0/LLN0.DataSet1"));
  REQUIRE(n);
  CHECK(n->view() == mms::object_name::domain("LD0", "LLN0$DataSet1"));
  n = model::to_mms_named_variable_list(parsed("@Temp"));
  REQUIRE(n);
  CHECK(n->view() == mms::object_name::aa("Temp"));

  CHECK(model::to_mms_named_variable_list(parsed("LD0/LLN0")).error() == errc::invalid_state);
  CHECK(model::to_mms_named_variable_list(parsed("LD0/LLN0.DS.x")).error() == errc::invalid_state);
  CHECK(model::to_mms_named_variable_list(parsed("LD0/LLN0.DS(1)")).error() == errc::invalid_state);
  CHECK(model::to_mms_named_variable_list(parsed("LD0/LLN0.DS[ST]")).error() == errc::invalid_state);
  CHECK(model::to_mms_named_variable_list(parsed("LD0")).error() == errc::invalid_state);

  auto r = model::from_mms_named_variable_list(mms::object_name::domain("LD0", "LLN0$DataSet1"));
  REQUIRE(r);
  CHECK(r->to_string() == "LD0/LLN0.DataSet1");
  // A data set named like an FC is still a data set here.
  r = model::from_mms_named_variable_list(mms::object_name::domain("LD0", "LLN0$ST"));
  REQUIRE(r);
  CHECK(r->to_string() == "LD0/LLN0.ST");
  r = model::from_mms_named_variable_list(mms::object_name::aa("Temp"));
  REQUIRE(r);
  CHECK(r->to_string() == "@Temp");
  CHECK(r->is_association_specific());

  CHECK(model::from_mms_named_variable_list(mms::object_name::vmd("DS")).error() ==
        errc::malformed_encoding);
  for (const char* item : {"LLN0", "LLN0$", "$DS", "LLN0$DS$x", "LLN0$1DS", "LLN0$D.S"}) {
    INFO(item);
    CHECK(model::from_mms_named_variable_list(mms::object_name::domain("LD0", item)).error() ==
          errc::malformed_encoding);
  }
  CHECK(model::from_mms_named_variable_list(mms::object_name::aa("1x")).error() ==
        errc::malformed_encoding);
}

TEST_CASE("MMS textual references", "[model]") {
  auto s = model::to_mms_reference(parsed("LD0/LLN0.Mod.stVal[ST]"));
  REQUIRE(s);
  CHECK(*s == "LD0/LLN0$ST$Mod$stVal");
  s = model::to_mms_reference(parsed("LD0/LLN0.gcb01[GO]"));
  REQUIRE(s);
  CHECK(*s == "LD0/LLN0$GO$gcb01");
  CHECK(model::to_mms_reference(parsed("LD0/LLN0.Arr(1)[ST]")).error() == errc::invalid_state);

  auto r = model::from_mms_reference("LD0/LLN0$BR$brcb01");
  REQUIRE(r);
  CHECK(r->to_string() == "LD0/LLN0.brcb01[BR]");
  r = model::from_mms_reference("IED1LD0/MMXU1$MX$TotW$mag$f");
  REQUIRE(r);
  CHECK(r->to_string() == "IED1LD0/MMXU1.TotW.mag.f[MX]");
  CHECK(model::from_mms_reference("LLN0$ST$Mod").error() == errc::malformed_encoding);
  CHECK(model::from_mms_reference("LD0/LLN0.Mod").error() == errc::malformed_encoding);
  CHECK(model::from_mms_reference("LD0/LLN0$ST$Mod/x").error() == errc::malformed_encoding);

  s = model::to_mms_data_set_reference(parsed("LD0/LLN0.DataSet1"));
  REQUIRE(s);
  CHECK(*s == "LD0/LLN0$DataSet1");
  s = model::to_mms_data_set_reference(parsed("@Temp"));
  REQUIRE(s);
  CHECK(*s == "@Temp");
  CHECK(model::to_mms_data_set_reference(parsed("LD0/LLN0.Mod.stVal")).error() ==
        errc::invalid_state);

  r = model::from_mms_data_set_reference("LD0/LLN0$DataSet1");
  REQUIRE(r);
  CHECK(r->to_string() == "LD0/LLN0.DataSet1");
  r = model::from_mms_data_set_reference("@Temp");
  REQUIRE(r);
  CHECK(r->to_string() == "@Temp");
  CHECK(model::from_mms_data_set_reference("LD0/LLN0.DataSet1").error() ==
        errc::malformed_encoding);
  CHECK(model::from_mms_data_set_reference("@").error() == errc::malformed_encoding);
  CHECK(model::from_mms_data_set_reference("LLN0$DS").error() == errc::malformed_encoding);
  CHECK(model::from_mms_data_set_reference("@" + std::string(65, 'x')).error() ==
        errc::length_overflow);
}
