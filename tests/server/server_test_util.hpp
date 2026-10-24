#pragma once

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <exception>
#include <string>
#include <string_view>
#include <vector>

#include <asio/co_spawn.hpp>
#include <asio/io_context.hpp>
#include <asio/post.hpp>
#include <asio/steady_timer.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>

#include "openiec61850/client/client.hpp"
#include "openiec61850/server/server.hpp"

// Note: GCC evaluates a co_await inside a Catch2 assertion macro twice, so results are always
// stored in a variable before being checked.

namespace server_test {

using namespace std::chrono_literals;
namespace srv = openiec61850::server;
namespace mms = openiec61850::mms;
namespace model = openiec61850::model;
namespace client = openiec61850::client;

// Runs a test coroutine on a fresh io_context; the context is stopped as soon as it finishes.
inline void run(asio::awaitable<void> (*test)()) {
  asio::io_context ctx;
  std::exception_ptr failure;
  bool done = false;
  asio::co_spawn(ctx, test(), [&](std::exception_ptr e) {
    failure = e;
    done = true;
    ctx.stop();
  });
  ctx.run_for(15s);
  REQUIRE(done);
  if (failure) std::rethrow_exception(failure);
}

inline asio::awaitable<void> sleep(std::chrono::milliseconds d) {
  asio::steady_timer t(co_await asio::this_coro::executor, d);
  co_await t.async_wait(asio::use_awaitable);
}

inline model::object_reference oref(std::string_view text) {
  auto r = model::object_reference::parse(text);
  REQUIRE(r);
  return *r;
}

inline const asio::ip::tcp::endpoint loopback{asio::ip::address_v4::loopback(), 0};

inline constexpr std::size_t big_members = 12;

// Domain IED1LD0:
//   LLN0   Mod{stVal ENUM [ST], q, t, ctlModel [CF]}, NamPlt{vendor [DC]}
//          data sets DS1 = MMXU1.TotW[MX], XCBR1.Pos.stVal[ST], XCBR1.Pos.q[ST], GGIO1.Ind1[ST]
//                    DSBIG = GGIO1.Str1..Str12 [ST]
//          brcb01 (DS1), urcb01 (DS1), urcb02 (DSBIG), urcb03 (no data set)
//   MMXU1  TotW{mag{f} [MX], q, t, db [CF]}, PhV.phsA{cVal{mag{f}} [MX], q, t}
//   XCBR1  Pos{stVal Dbpos [ST], q, t, ctlModel = direct-normal [CF], Oper [CO]}
//   CSWI1  Pos{stVal, q, t, ctlModel = sbo-normal, sboTimeout [CF], SBO, Oper, Cancel [CO]}
//   GGIO1  Ind1..Ind4{stVal BOOLEAN [ST], q, t}, Str1..Str12{stVal VisString255 [ST]},
//          Arr{vals INT32[4] [SP]}
// Domain IED1LD1: LLN0 Mod{stVal [ST]}.
inline void add_controllable(srv::ln_handle ln, model::ctl_model ctl) {
  using model::basic_type;
  using model::fc;
  auto pos = ln.data_object("Pos");
  pos.attribute("stVal", fc::ST, basic_type::dbpos, srv::attribute_options{}.with_triggers(srv::on_dchg));
  pos.attribute("q", fc::ST, basic_type::quality, srv::attribute_options{}.with_triggers(srv::on_qchg));
  pos.attribute("t", fc::ST, basic_type::timestamp);
  pos.attribute("ctlModel", fc::CF, basic_type::enumerated,
                srv::attribute_options{}.with_value(mms::data::integer(static_cast<std::int64_t>(ctl))));
  if (ctl == model::ctl_model::sbo_with_normal_security) {
    pos.attribute("sboTimeout", fc::CF, basic_type::int32u, srv::attribute_options{}.with_value(mms::data::unsigned_integer(500)));
    pos.attribute("SBO", fc::CO, basic_type::object_reference);
  }
  auto oper = [&](std::string_view name) {
    auto o = pos.structure(name, fc::CO);
    o.attribute("ctlVal", basic_type::boolean);
    auto origin = o.structure("origin");
    origin.attribute("orCat", basic_type::enumerated);
    origin.attribute("orIdent", basic_type::octet_string, srv::attribute_options{}.with_size(64));
    o.attribute("ctlNum", basic_type::int8u);
    o.attribute("T", basic_type::timestamp);
    o.attribute("Test", basic_type::boolean);
    if (name == "Oper") o.attribute("Check", basic_type::check);
  };
  oper("Oper");
  if (ctl == model::ctl_model::sbo_with_normal_security) oper("Cancel");
}

inline srv::data_model make_model() {
  using model::basic_type;
  using model::fc;
  using model::optional_field;
  using model::trigger;
  srv::model_builder b;
  auto ld = b.logical_device("IED1LD0");
  auto lln0 = ld.logical_node("LLN0");
  auto mod = lln0.data_object("Mod");
  mod.attribute("stVal", fc::ST, basic_type::enumerated,
                srv::attribute_options{}.with_triggers(srv::on_dchg).with_value(mms::data::integer(1)));
  mod.attribute("q", fc::ST, basic_type::quality, srv::attribute_options{}.with_triggers(srv::on_qchg));
  mod.attribute("t", fc::ST, basic_type::timestamp);
  mod.attribute("ctlModel", fc::CF, basic_type::enumerated, srv::attribute_options{}.with_value(mms::data::integer(0)));
  lln0.data_object("NamPlt").attribute("vendor", fc::DC, basic_type::visible_string,
                                       srv::attribute_options{}.with_size(64).with_value(mms::data::visible_string("acme")));

  auto mmxu = ld.logical_node("MMXU1");
  auto totw = mmxu.data_object("TotW");
  totw.structure("mag", fc::MX).attribute("f", basic_type::float32, srv::attribute_options{}.with_triggers(srv::on_dchg));
  totw.attribute("q", fc::MX, basic_type::quality, srv::attribute_options{}.with_triggers(srv::on_qchg));
  totw.attribute("t", fc::MX, basic_type::timestamp);
  totw.attribute("db", fc::CF, basic_type::int32u, srv::attribute_options{}.with_triggers(srv::on_dchg));
  auto phsa = mmxu.data_object("PhV").sub_object("phsA");
  phsa.structure("cVal", fc::MX).structure("mag").attribute("f", basic_type::float32,
                                                             srv::attribute_options{}.with_triggers(srv::on_dchg));
  phsa.attribute("q", fc::MX, basic_type::quality, srv::attribute_options{}.with_triggers(srv::on_qchg));
  phsa.attribute("t", fc::MX, basic_type::timestamp);

  add_controllable(ld.logical_node("XCBR1"), model::ctl_model::direct_with_normal_security);
  add_controllable(ld.logical_node("CSWI1"), model::ctl_model::sbo_with_normal_security);

  auto ggio = ld.logical_node("GGIO1");
  for (int i = 1; i <= 4; ++i) {
    auto ind = ggio.data_object("Ind" + std::to_string(i));
    ind.attribute("stVal", fc::ST, basic_type::boolean, srv::attribute_options{}.with_triggers(srv::on_dchg));
    ind.attribute("q", fc::ST, basic_type::quality, srv::attribute_options{}.with_triggers(srv::on_qchg));
    ind.attribute("t", fc::ST, basic_type::timestamp);
  }
  std::vector<model::object_reference> big;
  for (std::size_t i = 1; i <= big_members; ++i) {
    const auto name = "Str" + std::to_string(i);
    ggio.data_object(name).attribute("stVal", fc::ST, basic_type::visible_string,
                                     srv::attribute_options{}.with_triggers(srv::on_dchg).with_size(255));
    big.push_back(oref("IED1LD0/GGIO1." + name + ".stVal[ST]"));
  }
  ggio.data_object("Arr").attribute("vals", fc::SP, basic_type::int32, srv::attribute_options{}.with_count(4));

  lln0.data_set("DS1", {oref("IED1LD0/MMXU1.TotW[MX]"), oref("IED1LD0/XCBR1.Pos.stVal[ST]"),
                        oref("IED1LD0/XCBR1.Pos.q[ST]"), oref("IED1LD0/GGIO1.Ind1[ST]")});
  lln0.data_set("DSBIG", std::move(big));
  const auto opt = model::optional_fields::of(
      {optional_field::sequence_number, optional_field::report_time_stamp,
       optional_field::reason_for_inclusion, optional_field::data_set_name,
       optional_field::data_reference, optional_field::buffer_overflow, optional_field::entry_id,
       optional_field::conf_revision});
  const auto trg = model::trigger_conditions::of(
      {trigger::data_change, trigger::quality_change, trigger::general_interrogation});
  auto rcb = [&](std::string name, bool buffered, std::string rpt_id, std::string ds) {
    srv::report_control_settings rc;
    rc.name = std::move(name);
    rc.buffered = buffered;
    rc.rpt_id = std::move(rpt_id);
    rc.data_set = std::move(ds);
    rc.opt_flds = opt;
    rc.trg_ops = trg;
    lln0.report_control(std::move(rc));
  };
  rcb("brcb01", true, "brcb01-id", "DS1");
  rcb("urcb01", false, "", "DS1");
  rcb("urcb02", false, "big", "DSBIG");
  rcb("urcb03", false, "free", "");

  b.logical_device("IED1LD1").logical_node("LLN0").data_object("Mod").attribute(
      "stVal", fc::ST, basic_type::enumerated);
  auto m = b.build();
  REQUIRE(m);
  return std::move(*m);
}

inline srv::server start(asio::any_io_executor ex, srv::server_options o = {}) {
  o.association.transport.handshake_timeout = 2s;
  o.association.association_timeout = 2s;
  auto s = srv::server::start(std::move(ex), make_model(), loopback, std::move(o));
  REQUIRE(s);
  return std::move(*s);
}

inline client::client_options options_for(const srv::server& s) {
  client::client_options o;
  o.association.port = s.local_endpoint().port();
  o.association.transport.connect_timeout = 2s;
  o.association.transport.handshake_timeout = 2s;
  o.association.association_timeout = 2s;
  o.association.request_timeout = 3s;
  o.association.release_timeout = 2s;
  return o;
}

inline asio::awaitable<client::client> connect(const client::client_options& o) {
  auto c = co_await client::client::connect(co_await asio::this_coro::executor, o);
  REQUIRE(c);
  co_return std::move(*c);
}

inline asio::awaitable<client::report> next_report(client::client& c) {
  auto r = co_await c.next_report();
  REQUIRE(r);
  co_return std::move(*r);
}

}  // namespace server_test
