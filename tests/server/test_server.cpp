#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <atomic>
#include <future>
#include <thread>

#include <asio/detached.hpp>
#include <asio/use_future.hpp>

#include "openiec61850/transport/io_runtime.hpp"
#include "server_test_util.hpp"

using namespace server_test;
using asio::awaitable;
using model::fc;

TEST_CASE("Discovery: directory services against our client", "[server]") {
  run([]() -> awaitable<void> {
    auto s = start(co_await asio::this_coro::executor);
    auto c = co_await connect(options_for(s));

    auto lds = co_await c.get_server_directory();
    REQUIRE(lds);
    CHECK(*lds == std::vector<std::string>{"IED1LD0", "IED1LD1"});

    auto lns = co_await c.get_logical_device_directory("IED1LD0");
    REQUIRE(lns);
    CHECK(*lns == std::vector<std::string>{"CSWI1", "GGIO1", "LLN0", "MMXU1", "XCBR1"});

    auto dir = co_await c.get_logical_node_directory(oref("IED1LD0/LLN0"));
    REQUIRE(dir);
    CHECK(dir->data_objects == std::vector<std::string>{"Mod", "NamPlt"});
    CHECK(dir->data_sets == std::vector<std::string>{"DS1", "DSBIG"});
    CHECK(dir->brcbs == std::vector<std::string>{"brcb01"});
    CHECK(dir->urcbs == std::vector<std::string>{"urcb01", "urcb02", "urcb03"});

    auto def = co_await c.get_data_definition(oref("IED1LD0/MMXU1.TotW"));
    REQUIRE(def);
    REQUIRE(def->find("mag") != nullptr);
    CHECK(def->find("db") != nullptr);
    CHECK(def->find("mag")->fc == fc::MX);
    CHECK(def->find("db")->fc == fc::CF);

    auto entries = co_await c.get_data_directory(oref("IED1LD0/XCBR1.Pos"));
    REQUIRE(entries);
    CHECK(entries->size() == 5);  // stVal q t ctlModel Oper

    auto unknown = co_await c.get_logical_device_directory("NOPE");
    CHECK(unknown.error() == client::errc::object_not_found);
    auto unknown_ln = co_await c.get_logical_node_directory(oref("IED1LD0/NOPE1"));
    CHECK(unknown_ln.error() == client::errc::object_not_found);

    auto closed = co_await c.release();
    CHECK(closed);
    s.stop();
    co_await s.wait_stopped();
  });
}

TEST_CASE("Discovery: GetNameList continuation", "[server]") {
  run([]() -> awaitable<void> {
    srv::server_options o;
    o.max_names_per_response = 3;
    auto s = start(co_await asio::this_coro::executor, o);
    auto c = co_await connect(options_for(s));
    auto paged = co_await c.get_name_list(mms::object_class::named_variable, "IED1LD0");
    REQUIRE(paged);
    CHECK(paged->size() > 50);
    CHECK(std::is_sorted(paged->begin(), paged->end()));
    CHECK(std::find(paged->begin(), paged->end(), "MMXU1$MX$TotW$mag$f") != paged->end());
    CHECK(std::find(paged->begin(), paged->end(), "LLN0$BR$brcb01$EntryID") != paged->end());
    CHECK(std::find(paged->begin(), paged->end(), "MMXU1$CF$TotW$db") != paged->end());
    CHECK(std::find(paged->begin(), paged->end(), "GGIO1$SP$Arr$vals") != paged->end());
    auto lists = co_await c.get_name_list(mms::object_class::named_variable_list, "IED1LD0");
    REQUIRE(lists);
    CHECK(*lists == std::vector<std::string>{"LLN0$DS1", "LLN0$DSBIG"});
    s.stop();
  });
}

TEST_CASE("Read and write with access checks", "[server]") {
  run([]() -> awaitable<void> {
    srv::server_options o;
    o.on_write = [](const srv::write_event& e) -> std::optional<mms::data_access_error> {
      if (e.reference.to_string() == "IED1LD0/LLN0.NamPlt.vendor[DC]" &&
          e.value == mms::data::visible_string("forbidden")) {
        return mms::data_access_error::object_value_invalid;
      }
      return std::nullopt;
    };
    auto s = start(co_await asio::this_coro::executor, o);
    auto c = co_await connect(options_for(s));

    auto mod = co_await c.read(oref("IED1LD0/LLN0.Mod.stVal[ST]"));
    REQUIRE(mod);
    CHECK(*mod == mms::data::integer(1));
    auto totw = co_await c.read(oref("IED1LD0/MMXU1.TotW[MX]"));
    REQUIRE(totw);
    CHECK(totw->elements().size() == 3);
    std::vector<model::object_reference> refs{oref("IED1LD0/MMXU1.TotW.mag.f[MX]"),
                                              oref("IED1LD0/NOPE1.X[ST]"),
                                              oref("IED1LD0/MMXU1.TotW.q[ST]")};
    auto ln = co_await c.read_many(std::move(refs));
    REQUIRE(ln);
    REQUIRE(ln->size() == 3);
    CHECK((*ln)[0]);
    CHECK((*ln)[1].error() == client::errc::object_not_found);
    CHECK((*ln)[2].error() == client::errc::object_not_found);

    // Writable FCs.
    auto w = co_await c.write(oref("IED1LD0/MMXU1.TotW.db[CF]"), mms::data::unsigned_integer(250));
    CHECK(w);
    auto db = co_await s.read(oref("IED1LD0/MMXU1.TotW.db[CF]"));
    REQUIRE(db);
    CHECK(*db == mms::data::unsigned_integer(250));
    auto vendor = co_await c.write(oref("IED1LD0/LLN0.NamPlt.vendor[DC]"), mms::data::visible_string("x"));
    CHECK(vendor);
    auto refused = co_await c.write(oref("IED1LD0/LLN0.NamPlt.vendor[DC]"),
                                    mms::data::visible_string("forbidden"));
    CHECK(refused.error() == client::errc::value_invalid);

    // Read-only FCs, type and range errors.
    auto st = co_await c.write(oref("IED1LD0/LLN0.Mod.stVal[ST]"), mms::data::integer(2));
    CHECK(st.error() == client::errc::access_denied);
    auto type = co_await c.write(oref("IED1LD0/MMXU1.TotW.db[CF]"), mms::data::boolean(true));
    CHECK(type.error() == client::errc::type_inconsistent);
    auto range = co_await c.write(oref("IED1LD0/MMXU1.TotW.db[CF]"), mms::data::integer(-1));
    CHECK(range.error() == client::errc::value_invalid);
    auto missing = co_await c.write(oref("IED1LD0/MMXU1.Nope[CF]"), mms::data::integer(1));
    CHECK(missing.error() == client::errc::object_not_found);
    auto rcb = co_await c.write(oref("IED1LD0/LLN0.urcb01.ConfRev[RP]"), mms::data::unsigned_integer(9));
    CHECK(rcb.error() == client::errc::access_denied);

    // Arrays: whole value and element access (AlternateAccess).
    auto el = co_await c.write(oref("IED1LD0/GGIO1.Arr.vals(2)[SP]"), mms::data::integer(42));
    CHECK(el);
    auto arr = co_await c.read(oref("IED1LD0/GGIO1.Arr.vals[SP]"));
    REQUIRE(arr);
    REQUIRE(arr->elements().size() == 4);
    CHECK(arr->elements()[2] == mms::data::integer(42));
    auto one = co_await c.read(oref("IED1LD0/GGIO1.Arr.vals(2)[SP]"));
    REQUIRE(one);
    CHECK(*one == mms::data::integer(42));

    // Whole structure write (all CF attributes of TotW).
    std::vector<mms::data> cf{mms::data::unsigned_integer(7)};
    auto whole = co_await c.write(oref("IED1LD0/MMXU1.TotW[CF]"), mms::data::structure(std::move(cf)));
    CHECK(whole);
    s.stop();
  });
}

TEST_CASE("Data sets: persistent, association specific, deletion rules", "[server]") {
  run([]() -> awaitable<void> {
    auto s = start(co_await asio::this_coro::executor);
    auto c = co_await connect(options_for(s));

    auto ds1 = co_await c.get_data_set_directory(oref("IED1LD0/LLN0.DS1"));
    REQUIRE(ds1);
    CHECK(!ds1->deletable);
    REQUIRE(ds1->members.size() == 4);
    CHECK(ds1->members[0] == oref("IED1LD0/MMXU1.TotW[MX]"));
    auto values = co_await c.get_data_set_values(oref("IED1LD0/LLN0.DS1"));
    REQUIRE(values);
    CHECK(values->size() == 4);
    auto keep = co_await c.delete_data_set(oref("IED1LD0/LLN0.DS1"));
    CHECK(keep.error() == client::errc::not_deleted);

    // Persistent (domain-specific) data set created by a client.
    const std::vector<model::object_reference> members{oref("IED1LD0/GGIO1.Ind1.stVal[ST]"),
                                                       oref("IED1LD0/GGIO1.Arr.vals(1)[SP]")};
    auto created = co_await c.create_data_set(oref("IED1LD0/GGIO1.dyn"), members);
    CHECK(created);
    auto again = co_await c.create_data_set(oref("IED1LD0/GGIO1.dyn"), members);
    CHECK(again.error() == client::errc::object_exists);
    std::vector<model::object_reference> bad_members{oref("IED1LD0/GGIO1.Nope[ST]")};
    auto bad = co_await c.create_data_set(oref("IED1LD0/GGIO1.bad"), std::move(bad_members));
    CHECK(bad.error() == client::errc::object_not_found);
    auto dir = co_await c.get_data_set_directory(oref("IED1LD0/GGIO1.dyn"));
    REQUIRE(dir);
    CHECK(dir->deletable);
    CHECK(dir->members == members);
    std::vector<mms::data> dyn_values{mms::data::boolean(true), mms::data::integer(5)};
    auto set = co_await c.set_data_set_values(oref("IED1LD0/GGIO1.dyn"), std::move(dyn_values));
    REQUIRE(set);
    CHECK((*set)[0].error() == client::errc::access_denied);  // ST is not writable
    CHECK((*set)[1]);

    // Association-specific data set: visible to its association only, gone with it.
    std::vector<model::object_reference> aa_members{oref("IED1LD0/MMXU1.TotW.mag[MX]")};
    auto aa = co_await c.create_data_set(*model::object_reference::association_specific("mine"),
                                         std::move(aa_members));
    CHECK(aa);
    auto aa_values = co_await c.get_data_set_values(*model::object_reference::association_specific("mine"));
    REQUIRE(aa_values);
    CHECK(aa_values->size() == 1);
    auto aa_names = co_await c.get_name_list(mms::object_class::named_variable_list, std::string{});
    REQUIRE(aa_names);  // VMD scope: no lists

    auto other = co_await connect(options_for(s));
    auto not_there = co_await other.get_data_set_directory(
        *model::object_reference::association_specific("mine"));
    CHECK(not_there.error() == client::errc::object_not_found);
    auto shared = co_await other.get_data_set_directory(oref("IED1LD0/GGIO1.dyn"));
    CHECK(shared);

    // A data set used by an RCB cannot be deleted.
    client::rcb_settings w;
    w.dat_set = *model::object_reference::association_specific("mine");
    auto use = co_await c.set_rcb_values(oref("IED1LD0/LLN0.urcb03[RP]"), w);
    CHECK(use);
    auto in_use = co_await c.delete_data_set(*model::object_reference::association_specific("mine"));
    CHECK(in_use.error() == client::errc::not_deleted);
    auto rcb = co_await c.get_rcb_values(oref("IED1LD0/LLN0.urcb03[RP]"));
    REQUIRE(rcb);
    CHECK(rcb->dat_set == "@mine");
    CHECK(rcb->conf_rev == 2U);

    auto del = co_await other.delete_data_set(oref("IED1LD0/GGIO1.dyn"));
    CHECK(del);
    auto gone = co_await c.get_data_set_directory(oref("IED1LD0/GGIO1.dyn"));
    CHECK(gone.error() == client::errc::object_not_found);

    // When `c` goes away its "@" list goes too, and the URCB referencing it is cleared.
    c.abort();
    co_await sleep(50ms);
    auto after = co_await other.get_rcb_values(oref("IED1LD0/LLN0.urcb03[RP]"));
    REQUIRE(after);
    CHECK(after->dat_set == "");
    CHECK(after->resv == false);
    s.stop();
  });
}

TEST_CASE("Association limit and authentication hook", "[server]") {
  run([]() -> awaitable<void> {
    srv::server_options o;
    o.max_associations = 2;
    o.association.authorize = [](const openiec61850::association::association_request& r,
                                 mms::initiate_response&) {
      if (r.password == std::optional<std::string>("secret")) {
        return openiec61850::association::association_decision::accepted();
      }
      return openiec61850::association::association_decision::rejected(
          openiec61850::iso::acse::service_user_diagnostic::authentication_failure);
    };
    auto s = start(co_await asio::this_coro::executor, o);
    auto opts = options_for(s);
    auto denied = co_await client::client::connect(co_await asio::this_coro::executor, opts);
    CHECK(denied.error() == openiec61850::association::errc::authentication_failed);

    opts.association.password = "secret";
    auto a = co_await connect(opts);
    auto b = co_await connect(opts);
    CHECK(s.association_count() == 2);
    auto third = co_await client::client::connect(co_await asio::this_coro::executor, opts);
    CHECK(third.error() == openiec61850::association::errc::association_rejected);
    CHECK(s.association_count() == 2);

    auto released = co_await a.release();
    CHECK(released);
    co_await sleep(30ms);
    CHECK(s.association_count() == 1);
    auto fourth = co_await connect(opts);
    auto id = co_await fourth.read(oref("IED1LD0/LLN0.Mod.stVal[ST]"));
    CHECK(id);
    s.stop();
    co_await s.wait_stopped();
    CHECK(s.association_count() == 0);
  });
}

TEST_CASE("Concurrent associations issuing requests in parallel", "[server]") {
  run([]() -> awaitable<void> {
    const auto ex = co_await asio::this_coro::executor;
    auto s = start(ex);
    std::vector<client::client> clients;
    for (int i = 0; i < 6; ++i) clients.push_back(co_await connect(options_for(s)));
    int done = 0;
    for (auto& c : clients) {
      asio::co_spawn(
          ex,
          [](client::client& cl, int& counter) -> awaitable<void> {
            for (int k = 0; k < 20; ++k) {
              auto v = co_await cl.read(oref("IED1LD0/MMXU1.TotW[MX]"));
              REQUIRE(v);
              auto w = co_await cl.write(oref("IED1LD0/MMXU1.TotW.db[CF]"),
                                         mms::data::unsigned_integer(static_cast<std::uint64_t>(k)));
              REQUIRE(w);
            }
            ++counter;
          }(c, done),
          asio::detached);
    }
    while (done < 6) co_await sleep(5ms);
    CHECK(s.association_count() == 6);
    s.stop();
  });
}

TEST_CASE("update() from another thread is applied on the server strand", "[server]") {
  openiec61850::transport::io_runtime rt;
  rt.start();
  auto s = start(rt.get_executor());
  auto connected = asio::co_spawn(
                       rt.get_executor(),
                       [&]() -> awaitable<std::optional<client::client>> {
                         co_return co_await connect(options_for(s));
                       }(),
                       asio::use_future)
                       .get();
  REQUIRE(connected);
  auto& c = *connected;

  const auto target = oref("IED1LD0/MMXU1.TotW.mag.f[MX]");
  std::atomic<int> failures{0};
  std::thread writer([&] {
    for (int i = 0; i < 200; ++i) {
      auto r = s.update(target, mms::data::floating_point(static_cast<float>(i)), model::quality{},
                        std::nullopt);
      if (!r) ++failures;
    }
  });
  writer.join();
  CHECK(failures == 0);
  CHECK(s.update(oref("IED1LD0/MMXU1.Nope.f[MX]"), mms::data::floating_point(1.0F)).error() ==
        srv::errc::object_not_found);
  CHECK(s.update(oref("IED1LD0/MMXU1.TotW.mag.f[MX]"), mms::data::boolean(true)).error() ==
        srv::errc::type_mismatch);
  CHECK(s.update(oref("IED1LD0/LLN0.urcb01.RptID[RP]"), mms::data::visible_string("x")).error() ==
        srv::errc::access_denied);

  auto value = asio::co_spawn(
                   rt.get_executor(),
                   [&]() -> awaitable<mms::data> {
                     auto v = co_await c.read(oref("IED1LD0/MMXU1.TotW[MX]"));
                     REQUIRE(v);
                     co_return std::move(*v);
                   }(),
                   asio::use_future)
                   .get();
  CHECK(value.elements()[0].elements()[0] == mms::data::floating_point(199.0F));
  // auto_timestamp: t was set by the updates.
  auto t = model::timestamp::from_mms(value.elements()[2]);
  REQUIRE(t);
  CHECK(t->seconds() > 0);

  asio::co_spawn(rt.get_executor(), [&]() -> awaitable<void> { (void)co_await c.release(); }(),
                 asio::use_future)
      .get();
  s.stop();
  asio::co_spawn(rt.get_executor(), s.wait_stopped(), asio::use_future).get();
  CHECK(s.update(oref("IED1LD0/MMXU1.TotW.mag.f[MX]"), mms::data::floating_point(1.0F)).error() ==
        srv::errc::not_running);
  rt.stop();
  rt.join();
}
