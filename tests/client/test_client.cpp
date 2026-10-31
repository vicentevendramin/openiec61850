#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <optional>
#include <string>
#include <vector>

#include "client_test_util.hpp"
#include "openiec61850/transport/spawn.hpp"

namespace client = openiec61850::client;
namespace mms = openiec61850::mms;
namespace model = openiec61850::model;
namespace testing = openiec61850::testing;
using asio::awaitable;
using client_test::connect;
using client_test::options_for;
using client_test::ref;
using client_test::run;
using model::fc;
using openiec61850::result;

// Note: GCC evaluates a co_await inside a Catch2 assertion macro twice, so results are always
// stored in a variable before being checked.

namespace {

template <typename T>
bool contains(const std::vector<T>& v, const T& x) {
  return std::find(v.begin(), v.end(), x) != v.end();
}

std::vector<std::string> texts(const std::vector<model::object_reference>& refs) {
  std::vector<std::string> out;
  for (const auto& r : refs) out.push_back(r.to_string());
  return out;
}

}  // namespace

TEST_CASE("directory discovery follows GetNameList continuations", "[client]") {
  run([]() -> awaitable<void> {
    testing::fake_server_options so;
    so.name_list_page = 1;
    testing::fake_server server(co_await asio::this_coro::executor, so);
    REQUIRE(server.start());
    auto c = co_await connect(options_for(server));

    auto lds = co_await c.get_server_directory();
    REQUIRE(lds);
    CHECK(*lds == std::vector<std::string>{"IED1LD0", "IED1LD1"});
    CHECK(server.requests(mms::confirmed_service::get_name_list) == 2);

    auto lns = co_await c.get_logical_device_directory("IED1LD0");
    REQUIRE(lns);
    CHECK(*lns == std::vector<std::string>{"LLN0", "MMXU1", "XCBR1"});
    CHECK(server.requests(mms::confirmed_service::get_name_list) > 20);

    auto missing = co_await c.get_logical_device_directory("NOPE");
    CHECK(missing.error() == client::errc::object_not_found);

    auto vmd = co_await c.get_name_list(mms::object_class::domain);
    REQUIRE(vmd);
    CHECK(vmd->size() == 2);
  });
}

TEST_CASE("logical node and data directories", "[client]") {
  run([]() -> awaitable<void> {
    testing::fake_server server(co_await asio::this_coro::executor);
    REQUIRE(server.start());
    auto c = co_await connect(options_for(server));

    auto lln0 = co_await c.get_logical_node_directory(ref("IED1LD0/LLN0"));
    REQUIRE(lln0);
    CHECK(lln0->data_objects == std::vector<std::string>{"Mod"});
    CHECK(lln0->brcbs == std::vector<std::string>{"brcb01"});
    CHECK(lln0->urcbs == std::vector<std::string>{"urcb01"});
    CHECK(lln0->data_sets == std::vector<std::string>{"DS1"});
    CHECK(lln0->gocbs.empty());

    auto mmxu = co_await c.get_logical_node_directory(ref("IED1LD0/MMXU1"));
    REQUIRE(mmxu);
    CHECK(mmxu->data_objects == std::vector<std::string>{"TotW", "PhV"});
    CHECK(mmxu->data_sets.empty());

    auto all = co_await c.get_data_directory(ref("IED1LD0/MMXU1.TotW"));
    REQUIRE(all);
    REQUIRE(all->size() == 4);
    CHECK((*all)[0] == client::data_directory_entry{"mag", {fc::MX}});
    CHECK((*all)[3] == client::data_directory_entry{"db", {fc::CF}});

    auto cf = co_await c.get_data_directory(ref("IED1LD0/MMXU1.TotW[CF]"));
    REQUIRE(cf);
    CHECK(*cf == std::vector<client::data_directory_entry>{{"db", {fc::CF}}});

    auto ln = co_await c.get_data_directory(ref("IED1LD0/XCBR1"));
    REQUIRE(ln);
    REQUIRE(ln->size() == 1);
    CHECK((*ln)[0] == client::data_directory_entry{"Pos", {fc::ST, fc::CF}});

    auto bad = co_await c.get_logical_node_directory(ref("IED1LD0/MMXU1.TotW"));
    CHECK(bad.error() == openiec61850::errc::invalid_state);
  });
}

TEST_CASE("data definitions", "[client]") {
  run([]() -> awaitable<void> {
    testing::fake_server server(co_await asio::this_coro::executor);
    REQUIRE(server.start());
    auto c = co_await connect(options_for(server));
    using kind = client::data_definition::kind;

    auto totw = co_await c.get_data_definition(ref("IED1LD0/MMXU1.TotW[MX]"));
    REQUIRE(totw);
    CHECK(totw->name == "TotW");
    CHECK(totw->fc == fc::MX);
    CHECK(totw->type == kind::structure);
    const auto* q = totw->find("q");
    REQUIRE(q != nullptr);
    CHECK(q->basic_type == model::basic_type::quality);
    CHECK(q->fc == fc::MX);
    CHECK(totw->find("t")->basic_type == model::basic_type::timestamp);
    const auto* f = totw->find("mag")->find("f");
    REQUIRE(f != nullptr);
    CHECK(f->basic_type == model::basic_type::float32);
    CHECK(f->mms_type == mms::data_type::floating_point);

    // Without an FC the attributes of every FC are merged.
    auto pos = co_await c.get_data_definition(ref("IED1LD0/XCBR1.Pos"));
    REQUIRE(pos);
    CHECK(!pos->fc);
    REQUIRE(pos->children.size() == 4);
    CHECK(pos->find("stVal")->basic_type == model::basic_type::dbpos);
    CHECK(pos->find("stVal")->fc == fc::ST);
    CHECK(pos->find("ctlModel")->fc == fc::CF);

    auto brcb = co_await c.get_data_definition(ref("IED1LD0/LLN0.brcb01[BR]"));
    REQUIRE(brcb);
    CHECK(brcb->find("OptFlds")->basic_type == model::basic_type::optional_fields);
    CHECK(brcb->find("TrgOps")->basic_type == model::basic_type::trigger_conditions);
    CHECK(brcb->find("EntryID")->basic_type == model::basic_type::entry_id);
    CHECK(brcb->find("TimeOfEntry")->basic_type == model::basic_type::entry_time);
    const auto* rpt_id = brcb->find("RptID");
    CHECK(rpt_id->size == 129);
    CHECK(rpt_id->variable_length);

    auto leaf = co_await c.get_data_definition(ref("IED1LD0/MMXU1.TotW.mag.f"));
    REQUIRE(leaf);
    CHECK(leaf->type == kind::basic);
    CHECK(leaf->fc == fc::MX);

    auto missing = co_await c.get_data_definition(ref("IED1LD0/MMXU9.TotW[MX]"));
    CHECK(missing.error() == client::errc::object_not_found);
    auto missing_do = co_await c.get_data_definition(ref("IED1LD0/MMXU1.Hz"));
    CHECK(missing_do.error() == client::errc::object_not_found);
  });
}

TEST_CASE("read and write data values", "[client]") {
  run([]() -> awaitable<void> {
    testing::fake_server server(co_await asio::this_coro::executor);
    REQUIRE(server.start());
    auto c = co_await connect(options_for(server));

    auto mag = co_await c.read(ref("IED1LD0/MMXU1.TotW.mag.f[MX]"));
    REQUIRE(mag);
    CHECK(client::to_float(*mag).value() == 1.5F);
    CHECK(client::to_bool(*mag).error() == client::errc::type_mismatch);

    auto pos = co_await c.read(ref("IED1LD0/XCBR1.Pos.stVal[ST]"));
    REQUIRE(pos);
    CHECK(client::to_dbpos(*pos).value() == model::dbpos::off);

    auto totw = co_await c.read(ref("IED1LD0/MMXU1.TotW[MX]"));
    REQUIRE(totw);
    REQUIRE(totw->elements().size() == 3);
    CHECK(client::to_quality(totw->elements()[1]).value().is_good());
    CHECK(client::to_timestamp(totw->elements()[2]));
    auto first = client::component(*totw, 0);
    REQUIRE(first);
    CHECK(client::to_float(client::component(*first, 0).value()).value() == 1.5F);
    CHECK(client::component(*totw, 3).error() == openiec61850::errc::value_out_of_range);

    std::vector<model::object_reference> refs{ref("IED1LD0/MMXU1.TotW.mag.f[MX]"),
                                              ref("IED1LD0/MMXU1.Foo[MX]"),
                                              ref("IED1LD0/XCBR1.Pos.q[ST]")};
    auto many = co_await c.read_many(refs);
    REQUIRE(many);
    REQUIRE(many->size() == 3);
    CHECK((*many)[0]);
    CHECK((*many)[1].error() == client::errc::object_not_found);
    CHECK(client::to_quality(*(*many)[2]));
    CHECK(server.requests(mms::confirmed_service::read) == 4);

    auto no_fc = co_await c.read(ref("IED1LD0/MMXU1.TotW"));
    CHECK(no_fc.error() == openiec61850::errc::invalid_state);

    auto w = co_await c.write(ref("IED1LD0/MMXU1.TotW.db[CF]"), mms::data::unsigned_integer(100));
    CHECK(w);
    CHECK(server.value("IED1LD0", "MMXU1$CF$TotW$db") == mms::data::unsigned_integer(100));
    auto mismatch = co_await c.write(ref("IED1LD0/MMXU1.TotW.db[CF]"), mms::data::boolean(true));
    CHECK(mismatch.error() == client::errc::type_inconsistent);
    auto absent = co_await c.write(ref("IED1LD0/MMXU1.TotW.zz[CF]"), mms::data::boolean(true));
    CHECK(absent.error() == client::errc::object_not_found);
    const mms::data nothing;
    auto invalid = co_await c.write(ref("IED1LD0/MMXU1.TotW.db[CF]"), nothing);
    CHECK(invalid.error() == openiec61850::errc::invalid_state);

    std::vector<client::write_item> items;
    items.push_back({ref("IED1LD0/MMXU1.TotW.db[CF]"), mms::data::unsigned_integer(7)});
    items.push_back({ref("IED1LD0/XCBR1.Pos.ctlModel[CF]"), mms::data::visible_string("x")});
    auto both = co_await c.write_many(items);
    REQUIRE(both);
    REQUIRE(both->size() == 2);
    CHECK((*both)[0]);
    CHECK((*both)[1].error() == client::errc::type_inconsistent);
    CHECK(server.value("IED1LD0", "MMXU1$CF$TotW$db") == mms::data::unsigned_integer(7));
  });
}

TEST_CASE("data set services", "[client]") {
  run([]() -> awaitable<void> {
    testing::fake_server server(co_await asio::this_coro::executor);
    REQUIRE(server.start());
    auto c = co_await connect(options_for(server));

    auto dir = co_await c.get_data_set_directory(ref("IED1LD0/LLN0.DS1"));
    REQUIRE(dir);
    CHECK(!dir->deletable);
    CHECK(texts(dir->members) ==
          std::vector<std::string>{"IED1LD0/MMXU1.TotW[MX]", "IED1LD0/XCBR1.Pos.stVal[ST]",
                                   "IED1LD0/XCBR1.Pos.q[ST]",
                                   "IED1LD0/MMXU1.PhV.phsA.cVal.mag.f[MX]"});
    auto values = co_await c.get_data_set_values(ref("IED1LD0/LLN0.DS1"));
    REQUIRE(values);
    REQUIRE(values->size() == 4);
    CHECK(client::to_dbpos(*(*values)[1]).value() == model::dbpos::off);

    const std::vector<model::object_reference> members{ref("IED1LD0/XCBR1.Pos.stVal[ST]"),
                                                       ref("IED1LD0/MMXU1.TotW.db[CF]")};
    auto created = co_await c.create_data_set(ref("IED1LD0/LLN0.DS2"), members);
    CHECK(created);
    auto again = co_await c.create_data_set(ref("IED1LD0/LLN0.DS2"), members);
    CHECK(again.error() == client::errc::object_exists);
    auto ln = co_await c.get_logical_node_directory(ref("IED1LD0/LLN0"));
    REQUIRE(ln);
    CHECK(ln->data_sets == std::vector<std::string>{"DS1", "DS2"});
    auto dir2 = co_await c.get_data_set_directory(ref("IED1LD0/LLN0.DS2"));
    REQUIRE(dir2);
    CHECK(dir2->deletable);
    CHECK(dir2->members == members);
    const std::vector<model::object_reference> nope{ref("IED1LD0/MMXU1.Nope[MX]")};
    auto bad_member = co_await c.create_data_set(ref("IED1LD0/LLN0.DS3"), nope);
    CHECK(bad_member.error() == client::errc::object_not_found);

    auto deleted = co_await c.delete_data_set(ref("IED1LD0/LLN0.DS2"));
    CHECK(deleted);
    auto gone = co_await c.delete_data_set(ref("IED1LD0/LLN0.DS2"));
    CHECK(gone.error() == client::errc::object_not_found);
    auto fixed = co_await c.delete_data_set(ref("IED1LD0/LLN0.DS1"));
    CHECK(fixed.error() == client::errc::not_deleted);
    auto missing = co_await c.get_data_set_directory(ref("IED1LD0/LLN0.DS9"));
    CHECK(missing.error() == client::errc::object_not_found);

    // Association-specific (non-persistent) data set.
    auto tmp = ref("@tmp");
    auto made = co_await c.create_data_set(tmp, members);
    CHECK(made);
    auto vmd_lists = co_await c.get_name_list(mms::object_class::named_variable_list);
    REQUIRE(vmd_lists);
    CHECK(vmd_lists->empty());
    auto tmp_dir = co_await c.get_data_set_directory(tmp);
    REQUIRE(tmp_dir);
    CHECK(tmp_dir->members == members);
    const std::vector<mms::data> new_values{model::to_mms(model::dbpos::on),
                                            mms::data::unsigned_integer(5)};
    auto set = co_await c.set_data_set_values(tmp, new_values);
    REQUIRE(set);
    CHECK((*set)[0]);
    CHECK((*set)[1]);
    auto tmp_values = co_await c.get_data_set_values(tmp);
    REQUIRE(tmp_values);
    CHECK(client::to_dbpos(*(*tmp_values)[0]).value() == model::dbpos::on);
    CHECK(client::to_uint64(*(*tmp_values)[1]).value() == 5);
    auto tmp_deleted = co_await c.delete_data_set(tmp);
    CHECK(tmp_deleted);
  });
}

TEST_CASE("client lifecycle", "[client]") {
  run([]() -> awaitable<void> {
    testing::fake_server server(co_await asio::this_coro::executor);
    REQUIRE(server.start());
    auto o = options_for(server);

    auto c = co_await connect(o);
    CHECK(c.state() == client::connection_state::established);
    CHECK(c.association_info().negotiated.max_serv_outstanding_calling >= 1);
    auto released = co_await c.release();
    CHECK(released);
    CHECK(c.state() == client::connection_state::closed);
    const auto why = co_await c.wait_closed();
    CHECK(why == openiec61850::association::errc::released);
    auto after = co_await c.read(ref("IED1LD0/MMXU1.TotW.mag.f[MX]"));
    CHECK(after.error() == client::errc::not_connected);
    auto report = co_await c.next_report();
    CHECK(report.error() == openiec61850::association::errc::released);

    auto d = co_await connect(o);
    d.abort();
    const auto aborted = co_await d.wait_closed();
    CHECK(aborted == openiec61850::association::errc::aborted);

    // Without recovery a loss closes the client.
    auto e = co_await connect(o);
    server.drop_connections();
    const auto lost = co_await e.wait_closed();
    CHECK(lost);
    CHECK(lost != openiec61850::association::errc::released);
    auto ev = co_await e.next_event();
    REQUIRE(ev);
    CHECK(ev->type == client::connection_event::kind::lost);
    CHECK(ev->error == lost);
    auto end = co_await e.next_event();
    CHECK(end.error() == lost);

    o.association.port = 1;  // nothing listens there
    auto refused = co_await client::client::connect(co_await asio::this_coro::executor, o);
    CHECK(!refused);

    client::client moved = std::move(d);
    auto none = co_await d.read(ref("IED1LD0/MMXU1.TotW.mag.f[MX]"));  // NOLINT(bugprone-use-after-move)
    CHECK(none.error() == openiec61850::errc::invalid_state);
  });
}

TEST_CASE("callback bridge for code without coroutines", "[client]") {
  run([]() -> awaitable<void> {
    testing::fake_server server(co_await asio::this_coro::executor);
    REQUIRE(server.start());
    auto c = co_await connect(options_for(server));

    std::optional<result<mms::data>> got;
    openiec61850::transport::spawn(c.get_executor(), c.read(ref("IED1LD0/MMXU1.TotW.mag.f[MX]")),
                                   [&](result<mms::data> r) { got.emplace(std::move(r)); });
    while (!got) co_await client_test::yield();
    REQUIRE(*got);
    CHECK(client::to_float(**got).value() == 1.5F);
  });
}

TEST_CASE("data set values from a server that needs specificationWithResult", "[client]") {
  run([]() -> awaitable<void> {
    testing::fake_server_options so;
    so.list_read_needs_result = true;  // and its response has no specification, like IEC61850bean
    testing::fake_server server(co_await asio::this_coro::executor, so);
    REQUIRE(server.start());
    auto c = co_await connect(options_for(server));
    auto values = co_await c.get_data_set_values(ref("IED1LD0/LLN0.DS1"));
    REQUIRE(values);
    CHECK(values->size() == 4);
    (void)co_await c.release();
  });
}
