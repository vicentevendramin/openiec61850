#include <catch2/catch_test_macros.hpp>

#include <string>
#include <unordered_set>
#include <vector>

#include "openiec61850/model/object_reference.hpp"

namespace model = openiec61850::model;
using model::fc;
using model::object_reference;
using openiec61850::errc;

namespace {

object_reference parsed(std::string_view text, const model::parse_options& opts = {}) {
  auto r = object_reference::parse(text, opts);
  REQUIRE(r);
  return *r;
}

std::vector<model::path_element> path_of(const object_reference& r) {
  std::vector<model::path_element> out;
  for (auto e : r.path()) out.push_back(e);
  return out;
}

}  // namespace

TEST_CASE("Functional constraint codes", "[model]") {
  for (std::size_t i = 0; i < model::functional_constraint_count; ++i) {
    const auto f = static_cast<fc>(i);
    const auto code = model::to_string(f);
    REQUIRE(code.size() == 2);
    CHECK(model::parse_functional_constraint(code) == f);
  }
  CHECK(model::to_string(fc::ST) == "ST");
  CHECK(model::to_string(fc::BR) == "BR");
  CHECK(model::parse_functional_constraint("MX") == fc::MX);
  CHECK_FALSE(model::parse_functional_constraint("mx"));
  CHECK_FALSE(model::parse_functional_constraint("M"));
  CHECK_FALSE(model::parse_functional_constraint("MXX"));
  CHECK_FALSE(model::parse_functional_constraint("ZZ"));
  CHECK(model::is_control_block_fc(fc::BR));
  CHECK(model::is_control_block_fc(fc::GO));
  CHECK_FALSE(model::is_control_block_fc(fc::ST));
}

TEST_CASE("LN name decomposition", "[model]") {
  CHECK(model::split_ln_name("LLN0") == model::ln_name_parts{"", "LLN0", ""});
  CHECK(model::split_ln_name("XCBR1") == model::ln_name_parts{"", "XCBR", "1"});
  CHECK(model::split_ln_name("Q0XCBR12") == model::ln_name_parts{"Q0", "XCBR", "12"});
  CHECK(model::split_ln_name("PROT_PTOC3") == model::ln_name_parts{"PROT_", "PTOC", "3"});
  CHECK(model::split_ln_name("LPHD1") == model::ln_name_parts{"", "LPHD", "1"});
  CHECK_FALSE(model::split_ln_name("XCBR"));            // instance required
  CHECK_FALSE(model::split_ln_name("XCB1"));            // class too short
  CHECK_FALSE(model::split_ln_name("xcbr1"));           // class upper-case
  CHECK_FALSE(model::split_ln_name("1AXCBR1"));         // prefix starts with a digit
  CHECK_FALSE(model::split_ln_name("ABCDEFGHIJKLXCBR1"));  // prefix longer than 11
  CHECK_FALSE(model::split_ln_name("XCBR1234567890123"));  // instance longer than 12
  CHECK_FALSE(model::split_ln_name(""));
}

TEST_CASE("Object reference parse and accessors", "[model]") {
  const auto r = parsed("IED1LD0/Q0XCBR1.Pos.stVal");
  CHECK(r.text() == "IED1LD0/Q0XCBR1.Pos.stVal");
  CHECK(r.to_string() == "IED1LD0/Q0XCBR1.Pos.stVal");
  CHECK(r.ld() == "IED1LD0");
  CHECK(r.ln() == "Q0XCBR1");
  CHECK(r.has_ln());
  CHECK(r.ln_parts() == model::ln_name_parts{"Q0", "XCBR", "1"});
  CHECK_FALSE(r.fc());
  CHECK_FALSE(r.is_association_specific());
  CHECK_FALSE(r.has_index());
  CHECK(r.depth() == 2);
  CHECK(path_of(r) == std::vector<model::path_element>{{"Pos", {}}, {"stVal", {}}});
  CHECK(r.leaf() == model::path_element{"stVal", {}});

  const auto ld = parsed("LD0");
  CHECK(ld.ld() == "LD0");
  CHECK(ld.ln().empty());
  CHECK_FALSE(ld.has_ln());
  CHECK(ld.path().empty());
  CHECK_FALSE(ld.leaf());

  const auto ln = parsed("LD0/LLN0");
  CHECK(ln.ln() == "LLN0");
  CHECK(ln.depth() == 0);
}

TEST_CASE("Object reference with FC and array indices", "[model]") {
  const auto r = parsed("LD0/MMXU1.A.phsA.cVal.mag.f[MX]");
  CHECK(r.fc() == fc::MX);
  CHECK(r.text() == "LD0/MMXU1.A.phsA.cVal.mag.f");
  CHECK(r.to_string() == "LD0/MMXU1.A.phsA.cVal.mag.f[MX]");
  CHECK(r.depth() == 5);
  CHECK(parsed("LD0/MMXU1.A.phsA [MX]") == parsed("LD0/MMXU1.A.phsA[MX]"));

  const auto a = parsed("LD0/GGIO1.Arr(3).sub(0).x[ST]");
  CHECK(a.has_index());
  CHECK(path_of(a) == std::vector<model::path_element>{{"Arr", 3U}, {"sub", 0U}, {"x", {}}});
  CHECK(a.to_string() == "LD0/GGIO1.Arr(3).sub(0).x[ST]");
  CHECK(parsed("LD0/GGIO1.Arr(4294967295)").leaf()->index == 4294967295U);

  const auto ln_fc = parsed("LD0/LLN0[ST]");
  CHECK(ln_fc.fc() == fc::ST);
  CHECK(ln_fc.path().empty());
}

TEST_CASE("Association-specific data set reference", "[model]") {
  const auto r = parsed("@MyDataSet");
  CHECK(r.is_association_specific());
  CHECK(r.ld().empty());
  CHECK(r.ln().empty());
  CHECK(path_of(r) == std::vector<model::path_element>{{"MyDataSet", {}}});
  auto made = object_reference::association_specific("MyDataSet");
  REQUIRE(made);
  CHECK(*made == r);
  CHECK(object_reference::association_specific("1bad").error() == errc::malformed_encoding);
}

TEST_CASE("Object reference round trips", "[model]") {
  for (const char* text :
       {"LD0", "LD0/LLN0", "LD0/LLN0[ST]", "LD0/LLN0.Mod.stVal[ST]", "LD0/LLN0.brcb01[BR]",
        "LD0/LLN0.urcb01[RP]", "LD0/LLN0.DataSet1", "LD0/LLN0.SGCB[SP]", "LD0/LLN0.gcb01[GO]",
        "IED_A_PROT/PTOC1.Str.general[ST]", "LD0/MMXU1.PhV.phsA.cVal.mag.f[MX]",
        "LD0/GGIO1.Arr(12).sub[CF]", "@ds1", "LD0/LLN0.NamPlt.vendor[DC]"}) {
    INFO(text);
    const auto r = parsed(text);
    CHECK(r.to_string() == text);
    CHECK(parsed(r.to_string()) == r);
  }
}

TEST_CASE("Object reference make, child and parent", "[model]") {
  auto r = object_reference::make("LD0", "XCBR1", {{"Pos", {}}, {"stVal", {}}}, fc::ST);
  REQUIRE(r);
  CHECK(r->to_string() == "LD0/XCBR1.Pos.stVal[ST]");
  CHECK(object_reference::make("LD0", "XCBR1", {{"Pos.x", {}}}).error() ==
        errc::malformed_encoding);
  CHECK(object_reference::make("LD0", "", {{"Pos", {}}}).error() == errc::malformed_encoding);
  auto arr = object_reference::make("LD0", "GGIO1", {{"Arr", 7U}});
  REQUIRE(arr);
  CHECK(arr->text() == "LD0/GGIO1.Arr(7)");

  auto ld = parsed("LD0");
  auto ln = ld.child("LLN0");
  REQUIRE(ln);
  CHECK(ln->text() == "LD0/LLN0");
  auto mod = ln->with_fc(fc::ST).child("Mod");
  REQUIRE(mod);
  CHECK(mod->to_string() == "LD0/LLN0.Mod[ST]");
  auto idx = mod->child("x", 2);
  REQUIRE(idx);
  CHECK(idx->to_string() == "LD0/LLN0.Mod.x(2)[ST]");
  CHECK(ld.child("LLN0", 1).error() == errc::invalid_state);
  CHECK(ln->child("bad.name").error() == errc::invalid_state);

  auto p = idx->parent();
  REQUIRE(p);
  CHECK(*p == *mod);
  auto p2 = p->parent();
  REQUIRE(p2);
  CHECK(p2->to_string() == "LD0/LLN0[ST]");
  auto p3 = p2->parent();
  REQUIRE(p3);
  CHECK(p3->to_string() == "LD0");
  CHECK(p3->parent().error() == errc::invalid_state);
  CHECK(parsed("@ds").parent().error() == errc::invalid_state);
  CHECK(object_reference{}.parent().error() == errc::invalid_state);
}

TEST_CASE("Object reference containment, ordering and hashing", "[model]") {
  const auto da = parsed("LD0/XCBR1.Pos.stVal[ST]");
  CHECK(da.is_within(parsed("LD0")));
  CHECK(da.is_within(parsed("LD0/XCBR1")));
  CHECK(da.is_within(parsed("LD0/XCBR1.Pos[CO]")));
  CHECK(da.is_within(da));
  CHECK_FALSE(da.is_within(parsed("LD0/XCBR1.Po")));
  CHECK_FALSE(da.is_within(parsed("LD")));
  CHECK_FALSE(parsed("LD0/XCBR10.Pos").is_within(parsed("LD0/XCBR1")));
  CHECK(parsed("LD0/GGIO1.Arr(2).x").is_within(parsed("LD0/GGIO1.Arr")));

  CHECK(parsed("LD0/ABCD1.x[ST]") != parsed("LD0/ABCD1.x[MX]"));
  CHECK(parsed("LD0/ABCD1.x") != parsed("LD0/ABCD1.x[MX]"));
  CHECK(parsed("LD0/ABCD1.x") < parsed("LD0/ABCD1.y"));
  CHECK(parsed("LD0/ABCD1.x") < parsed("LD0/ABCD1.x[ST]"));

  std::unordered_set<object_reference> set{parsed("LD0/ABCD1.x[ST]"), parsed("LD0/ABCD1.x[MX]"),
                                           parsed("LD0/ABCD1.x[ST]")};
  CHECK(set.size() == 2);
}

TEST_CASE("Invalid object references", "[model]") {
  for (const char* text : {
           "",             "/",              "LD0/",           "/LLN0",
           "LD0//LLN0",    "LD0/LLN0.",      "LD0/LLN0..Mod",  "LD0/LLN0.Mod.",
           "0LD/LLN0",     "_LD/LLN0",       "LD-0/LLN0",      "LD0/LLN0.0Mod",
           "LD0/LLN0.Mod$stVal", "LD0/LLN0/Mod", "LD0/LLN0.Mod stVal", "LD0 /LLN0",
           "LD0/LLN0.Mod[st]", "LD0/LLN0.Mod[ZZ]", "LD0/LLN0.Mod[ST", "LD0/LLN0.Mod]",
           "LD0/LLN0.Mod[]", "LD0/LLN0.Mod[ST][MX]", "LD0[ST]", "@ds[ST]",
           "@",            "@1ds",           "@ds.x",          "LD0/LLN0(1)",
           "LD0/LLN0.Arr()", "LD0/LLN0.Arr(01)", "LD0/LLN0.Arr(-1)", "LD0/LLN0.Arr(4294967296)",
           "LD0/LLN0.Arr(12345678901)", "LD0/LLN0.Arr(1)(2)", "LD0/LLN0.Arr(1)x", "LD0/LLN0.Arr(1",
           "LD0/LLN0.(1)", "LD0/xcbr1.Pos", "LD0/XCBR.Pos", "LD0/LLN0.Mod\xC3\xA9",
           "LD0/LLN0.Mod.stVal ", "LD0/LLN0.Mod.stVal\t[ST]"}) {
    INFO(text);
    auto r = object_reference::parse(text);
    REQUIRE_FALSE(r);
    CHECK(r.error() == errc::malformed_encoding);
  }
  // Embedded NUL inside the view.
  CHECK(object_reference::parse(std::string_view{"LD0/LLN0\0", 9}).error() ==
        errc::malformed_encoding);
}

TEST_CASE("Object reference lenient LN names", "[model]") {
  model::parse_options lenient;
  lenient.strict_ln_names = false;
  CHECK(object_reference::parse("LD0/xcbr1.Pos").error() == errc::malformed_encoding);
  const auto r = parsed("LD0/myNode.Pos", lenient);
  CHECK(r.ln() == "myNode");
  CHECK(r.ln_parts() == model::ln_name_parts{"", "myNode", ""});
  CHECK(object_reference::parse("LD0/my-node.Pos", lenient).error() == errc::malformed_encoding);
}

TEST_CASE("Object reference edition limits", "[model]") {
  const auto ed1 = model::parse_options_for(model::edition::ed1);
  const auto ed2 = model::parse_options_for(model::edition::ed2);
  const std::string ld32(32, 'L');
  const std::string ld33(33, 'L');
  const std::string ld64(64, 'L');
  const std::string ld65(65, 'L');

  CHECK(object_reference::parse(ld32 + "/LLN0", ed1));
  CHECK(object_reference::parse(ld33 + "/LLN0", ed1).error() == errc::length_overflow);
  CHECK(object_reference::parse(ld64 + "/LLN0", ed2));
  CHECK(object_reference::parse(ld65 + "/LLN0", ed2).error() == errc::length_overflow);

  // Ed.1: VISIBLE STRING65; Ed.2: VISIBLE STRING129. The FC suffix does not count.
  const std::string base = "LD0/LLN0.";
  const std::string r65 = base + std::string(65 - base.size(), 'a');
  const std::string r66 = base + std::string(66 - base.size(), 'a');
  CHECK(object_reference::parse(r65 + "[ST]", ed1));
  CHECK(object_reference::parse(r66, ed1).error() == errc::length_overflow);
  CHECK(object_reference::parse(r66, ed2));
  const std::string r129 = base + std::string(129 - base.size(), 'a');
  const std::string r130 = base + std::string(130 - base.size(), 'a');
  CHECK(object_reference::parse(r129, ed2));
  CHECK(object_reference::parse(r130, ed2).error() == errc::length_overflow);

  CHECK(object_reference::parse("@" + std::string(64, 'd'), ed2));
  CHECK(object_reference::parse("@" + std::string(33, 'd'), ed1).error() == errc::length_overflow);

  model::parse_options unlimited{model::name_limits::unlimited(), true};
  CHECK(object_reference::parse(base + std::string(1000, 'a'), unlimited));
  CHECK(object_reference::parse(base + std::string(70000, 'a'), unlimited).error() ==
        errc::length_overflow);
}
