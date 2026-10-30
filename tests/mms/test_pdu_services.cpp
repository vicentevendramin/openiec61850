// Journal and file services of the MMS codec (ISO 9506-2 §19, Annex C).

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "mms_test_util.hpp"
#include "openiec61850/mms/pdu.hpp"

namespace mms = openiec61850::mms;
using mms_test::hex;
using openiec61850::byte_buffer;
using openiec61850::byte_view;
using openiec61850::errc;

namespace {

byte_buffer encode(const mms::mms_pdu& pdu) {
  byte_buffer out;
  REQUIRE(mms::encode_pdu(pdu, out));
  return out;
}

template <typename S>
S request_service(const byte_buffer& bytes, std::uint32_t invoke_id) {
  auto pdu = mms::decode_pdu(bytes);
  REQUIRE(pdu);
  const auto* req = std::get_if<mms::confirmed_request>(&*pdu);
  REQUIRE(req != nullptr);
  CHECK(req->invoke_id == invoke_id);
  REQUIRE(std::holds_alternative<S>(req->service));
  return std::get<S>(req->service);
}

template <typename S>
S response_service(const byte_buffer& bytes, std::uint32_t invoke_id) {
  auto pdu = mms::decode_pdu(bytes);
  REQUIRE(pdu);
  const auto* resp = std::get_if<mms::confirmed_response>(&*pdu);
  REQUIRE(resp != nullptr);
  CHECK(resp->invoke_id == invoke_id);
  REQUIRE(std::holds_alternative<S>(resp->service));
  return std::get<S>(resp->service);
}

void check_canonical(const byte_buffer& bytes) {
  auto pdu = mms::decode_pdu(bytes);
  REQUIRE(pdu);
  CHECK(encode(*pdu) == bytes);
  for (std::size_t n = 0; n < bytes.size(); ++n) {
    CHECK_FALSE(mms::decode_pdu(byte_view{bytes.data(), n}));
  }
}

template <typename T>
std::vector<T> collect(const mms::list_view<T>& l) {
  std::vector<T> out;
  for (const auto& x : l) out.push_back(x);
  return out;
}

std::vector<std::string> names(const mms::list_view<std::string_view>& l) {
  std::vector<std::string> out;
  for (const auto s : l) out.emplace_back(s);
  return out;
}

const std::array<std::string_view, 1> a_txt{"a.txt"};
const std::array<std::string_view, 1> b_txt{"b.txt"};

}  // namespace

TEST_CASE("File services: open, read, close", "[mms]") {
  const auto open_req = encode(mms::confirmed_request{1, {}, mms::file_open_request{a_txt, 0}});
  CHECK(open_req == hex("A0 12 02 01 01 BF 48 0C A0 07 19 05 'a.txt' 81 01 00"));
  check_canonical(open_req);
  const auto o = request_service<mms::file_open_request>(open_req, 1);
  CHECK(names(o.file_name) == std::vector<std::string>{"a.txt"});
  CHECK(o.initial_position == 0U);
  CHECK(mms::service_tag(mms::confirmed_service_request{o}) == 72U);

  mms::file_open_response or_{1, {300, std::string_view("20240101000000Z")}};
  const auto open_resp = encode(mms::confirmed_response{1, or_});
  CHECK(open_resp ==
        hex("A1 20 02 01 01 BF 48 1A 80 01 01 A1 15 80 02 01 2C 81 0F '20240101000000Z'"));
  check_canonical(open_resp);
  const auto orr = response_service<mms::file_open_response>(open_resp, 1);
  CHECK(orr.frsm_id == 1);
  CHECK(orr.attributes.size == 300U);
  CHECK(orr.attributes.last_modified == "20240101000000Z");

  const auto read_req = encode(mms::confirmed_request{2, {}, mms::file_read_request{1}});
  CHECK(read_req == hex("A0 07 02 01 02 9F 49 01 01"));
  check_canonical(read_req);
  CHECK(request_service<mms::file_read_request>(read_req, 2).frsm_id == 1);

  const std::string_view hello = "hello";
  const byte_view data{reinterpret_cast<const std::uint8_t*>(hello.data()), hello.size()};
  const auto read_resp = encode(mms::confirmed_response{2, mms::file_read_response{data, false}});
  CHECK(read_resp == hex("A1 10 02 01 02 BF 49 0A 80 05 'hello' 81 01 00"));
  check_canonical(read_resp);
  const auto rr = response_service<mms::file_read_response>(read_resp, 2);
  CHECK(rr.data.size() == 5);
  CHECK_FALSE(rr.more_follows);
  // moreFollows defaults to TRUE.
  const auto more = response_service<mms::file_read_response>(hex("A1 0D 02 01 02 BF 49 07 80 05 'hello'"), 2);
  CHECK(more.more_follows);

  const auto close_req = encode(mms::confirmed_request{3, {}, mms::file_close_request{1}});
  CHECK(close_req == hex("A0 07 02 01 03 9F 4A 01 01"));
  CHECK(request_service<mms::file_close_request>(close_req, 3).frsm_id == 1);
  const auto close_resp = encode(mms::confirmed_response{3, mms::file_close_response{}});
  CHECK(close_resp == hex("A1 06 02 01 03 9F 4A 00"));
  CHECK(mms::decode_pdu(close_resp));
}

TEST_CASE("File services: delete, rename, directory", "[mms]") {
  const auto del = encode(mms::confirmed_request{4, {}, mms::file_delete_request{a_txt}});
  CHECK(del == hex("A0 0D 02 01 04 BF 4C 07 19 05 'a.txt'"));
  check_canonical(del);
  CHECK(names(request_service<mms::file_delete_request>(del, 4).file_name) ==
        std::vector<std::string>{"a.txt"});
  CHECK(encode(mms::confirmed_response{4, mms::file_delete_response{}}) == hex("A1 06 02 01 04 9F 4C 00"));

  const auto ren = encode(mms::confirmed_request{5, {}, mms::file_rename_request{a_txt, b_txt}});
  CHECK(ren == hex("A0 18 02 01 05 BF 4B 12 A0 07 19 05 'a.txt' A1 07 19 05 'b.txt'"));
  check_canonical(ren);
  const auto r = request_service<mms::file_rename_request>(ren, 5);
  CHECK(names(r.new_name) == std::vector<std::string>{"b.txt"});
  CHECK(mms::decode_pdu(hex("A1 06 02 01 05 9F 4B 00")));

  const auto dir_req = encode(mms::confirmed_request{6, {}, mms::file_directory_request{}});
  CHECK(dir_req == hex("A0 06 02 01 06 BF 4D 00"));
  const auto d0 = request_service<mms::file_directory_request>(dir_req, 6);
  CHECK_FALSE(d0.file_specification);
  CHECK_FALSE(d0.continue_after);
  mms::file_directory_request after;
  after.continue_after = mms::list_view<std::string_view>(a_txt);
  const auto dir_after = encode(mms::confirmed_request{6, {}, after});
  CHECK(dir_after == hex("A0 0F 02 01 06 BF 4D 09 A1 07 19 05 'a.txt'"));
  check_canonical(dir_after);
  const auto d1 = request_service<mms::file_directory_request>(dir_after, 6);
  REQUIRE(d1.continue_after);
  CHECK(names(*d1.continue_after) == std::vector<std::string>{"a.txt"});

  const std::array<mms::directory_entry, 1> entries{mms::directory_entry{a_txt, {5, std::nullopt}}};
  const auto dir_resp = encode(mms::confirmed_response{6, mms::file_directory_response{entries, true}});
  CHECK(dir_resp == hex("A1 1D 02 01 06 BF 4D 17 A0 12 30 10 30 0E A0 07 19 05 'a.txt'"
                        " A1 03 80 01 05 81 01 FF"));
  check_canonical(dir_resp);
  const auto dr = response_service<mms::file_directory_response>(dir_resp, 6);
  CHECK(dr.more_follows);
  const auto list = collect(dr.entries);
  REQUIRE(list.size() == 1);
  CHECK(names(list[0].file_name) == std::vector<std::string>{"a.txt"});
  CHECK(list[0].attributes.size == 5U);
  CHECK_FALSE(list[0].attributes.last_modified);
  // moreFollows defaults to FALSE; a VisibleString file name is accepted.
  const auto lenient = response_service<mms::file_directory_response>(
      hex("A1 13 02 01 06 BF 4D 0D A0 0B 30 09 30 07 A0 00 A1 03 80 01 00"), 6);
  CHECK_FALSE(lenient.more_follows);
  CHECK(mms::decode_pdu(hex("A1 17 02 01 06 BF 4D 11 A0 0F 30 0D 30 0B A0 04 1A 02 'ab' A1 03 80 01 00")));
  // Wrong element type in a FileName.
  CHECK(mms::decode_pdu(hex("A0 0A 02 01 04 BF 4C 04 04 02 'ab'")).error() == errc::malformed_encoding);
}

TEST_CASE("Journal services: ReadJournal", "[mms]") {
  mms::read_journal_request req;
  req.journal_name = mms::object_name::domain("LD0", "LLN0$Log");
  req.starting_time = mms::binary_time{1, std::uint16_t{1}};
  req.ending_time = mms::binary_time{1, std::uint16_t{1}};
  const auto bytes = encode(mms::confirmed_request{7, {}, req});
  CHECK(bytes == hex("A0 2D 02 01 07 BF 41 27 A0 11 A1 0F 1A 03 'LD0' 1A 08 'LLN0$Log'"
                     " A1 08 80 06 00 00 00 01 00 01 A2 08 80 06 00 00 00 01 00 01"));
  check_canonical(bytes);
  const auto r = request_service<mms::read_journal_request>(bytes, 7);
  CHECK(r.journal_name == mms::object_name::domain("LD0", "LLN0$Log"));
  CHECK(r.starting_time == mms::binary_time{1, std::uint16_t{1}});
  CHECK(r.ending_time == mms::binary_time{1, std::uint16_t{1}});
  CHECK_FALSE(r.starting_entry);
  CHECK_FALSE(r.number_of_entries);
  CHECK_FALSE(r.variables);
  CHECK_FALSE(r.start_after);
  CHECK(mms::service_tag(mms::confirmed_service_request{r}) == 65U);

  // Entry-based range, a variable filter and entryToStartAfter.
  const std::array<std::uint8_t, 8> id{0, 0, 0, 0, 0, 0, 0, 9};
  const std::array<std::string_view, 1> vars{"LLN0$ST$Mod$stVal"};
  mms::read_journal_request q;
  q.journal_name = req.journal_name;
  q.starting_entry = byte_view{id};
  q.number_of_entries = 10;
  q.variables = mms::list_view<std::string_view>(vars);
  q.start_after = mms::journal_start_after{mms::binary_time{5, std::uint16_t{2}}, id};
  const auto qb = encode(mms::confirmed_request{8, {}, q});
  check_canonical(qb);
  const auto q2 = request_service<mms::read_journal_request>(qb, 8);
  REQUIRE(q2.starting_entry);
  CHECK(q2.starting_entry->size() == 8);
  CHECK(q2.number_of_entries == 10);
  REQUIRE(q2.variables);
  CHECK(names(*q2.variables) == std::vector<std::string>{"LLN0$ST$Mod$stVal"});
  REQUIRE(q2.start_after);
  CHECK(q2.start_after->time == mms::binary_time{5, std::uint16_t{2}});
  CHECK(q2.start_after->entry.size() == 8);

  // Both alternatives of a CHOICE cannot be encoded.
  mms::read_journal_request bad = q;
  bad.starting_time = mms::binary_time{};
  byte_buffer out;
  CHECK(mms::encode_pdu(mms::confirmed_request{1, {}, bad}, out).error() == errc::invalid_state);
  CHECK(out.empty());
  // A TimeOfDay of 5 octets.
  CHECK(mms::decode_pdu(hex("A0 1D 02 01 07 BF 41 17 A0 0C A1 0A 1A 01 'L' 1A 05 'LLN0$'"
                            " A1 07 80 05 00 00 00 01 00"))
            .error() == errc::malformed_encoding);
}

TEST_CASE("Journal services: ReadJournal response", "[mms]") {
  const auto bytes = hex(
      "A1 32 02 01 07 BF 41 2C A0 2A 30 28 80 08 00 00 00 00 00 00 00 01 A1 02 30 00"
      " A2 18 80 06 00 00 00 01 00 01 A2 0E A1 0C 30 0A 80 03 'Ind' A1 03 83 01 FF");
  check_canonical(bytes);
  const auto r = response_service<mms::read_journal_response>(bytes, 7);
  CHECK_FALSE(r.more_follows);
  const auto entries = collect(r.entries);
  REQUIRE(entries.size() == 1);
  CHECK(entries[0].entry_id.size() == 8);
  CHECK(entries[0].occurrence_time == mms::binary_time{1, std::uint16_t{1}});
  CHECK_FALSE(entries[0].annotation);
  const auto vars = collect(entries[0].variables);
  REQUIRE(vars.size() == 1);
  CHECK(vars[0].tag == "Ind");
  CHECK(*vars[0].value.view().as_boolean());

  // Built from values: the originating application defaults to an empty SEQUENCE.
  const std::array<std::uint8_t, 8> id{0, 0, 0, 0, 0, 0, 0, 1};
  const auto value = mms::data::boolean(true);
  const std::array<mms::journal_variable, 1> jv{mms::journal_variable{"Ind", value}};
  mms::journal_entry e;
  e.entry_id = id;
  e.occurrence_time = mms::binary_time{1, std::uint16_t{1}};
  e.variables = jv;
  const std::array<mms::journal_entry, 1> list{e};
  const auto built = encode(mms::confirmed_response{7, mms::read_journal_response{list, false}});
  CHECK(built.size() == bytes.size());
  CHECK(response_service<mms::read_journal_response>(built, 7).entries.size() == 1);

  // An annotation entry, and moreFollows.
  mms::journal_entry note;
  note.entry_id = id;
  note.annotation = "restart";
  const std::array<mms::journal_entry, 1> notes{note};
  const auto nb = encode(mms::confirmed_response{9, mms::read_journal_response{notes, true}});
  check_canonical(nb);
  const auto nr = response_service<mms::read_journal_response>(nb, 9);
  CHECK(nr.more_follows);
  CHECK(collect(nr.entries)[0].annotation == "restart");

  // An invalid Data value inside a journal variable is rejected up front.
  CHECK_FALSE(mms::decode_pdu(hex(
      "A1 32 02 01 07 BF 41 2C A0 2A 30 28 80 08 00 00 00 00 00 00 00 01 A1 02 30 00"
      " A2 18 80 06 00 00 00 01 00 01 A2 0E A1 0C 30 0A 80 03 'Ind' A1 03 8C 01 FF")));
}

TEST_CASE("Journal services: InitializeJournal and ReportJournalStatus", "[mms]") {
  mms::initialize_journal_request init;
  init.journal_name = mms::object_name::domain("LD0", "LLN0$Log");
  const auto ib = encode(mms::confirmed_request{1, {}, init});
  CHECK(ib == hex("A0 19 02 01 01 BF 43 13 A0 11 A1 0F 1A 03 'LD0' 1A 08 'LLN0$Log'"));
  check_canonical(ib);
  const auto i0 = request_service<mms::initialize_journal_request>(ib, 1);
  CHECK_FALSE(i0.limiting_time);
  const std::array<std::uint8_t, 8> id{1, 2, 3, 4, 5, 6, 7, 8};
  init.limiting_time = mms::binary_time{100, std::nullopt};
  init.limiting_entry = byte_view{id};
  const auto lb = encode(mms::confirmed_request{1, {}, init});
  check_canonical(lb);
  const auto i1 = request_service<mms::initialize_journal_request>(lb, 1);
  CHECK(i1.limiting_time == mms::binary_time{100, std::nullopt});
  CHECK(i1.limiting_entry->size() == 8);
  init.limiting_time.reset();
  byte_buffer out;
  CHECK(mms::encode_pdu(mms::confirmed_request{1, {}, init}, out).error() == errc::invalid_state);

  const auto ir = encode(mms::confirmed_response{1, mms::initialize_journal_response{3}});
  CHECK(ir == hex("A1 07 02 01 01 9F 43 01 03"));
  CHECK(response_service<mms::initialize_journal_response>(ir, 1).deleted == 3U);

  const auto sb = encode(mms::confirmed_request{2, {}, mms::report_journal_status_request{
                                                           mms::object_name::domain("LD0", "L$G")}});
  CHECK(sb == hex("A0 12 02 01 02 BF 44 0C A1 0A 1A 03 'LD0' 1A 03 'L$G'") );
  check_canonical(sb);
  const auto sr = encode(mms::confirmed_response{2, mms::report_journal_status_response{42, false}});
  CHECK(sr == hex("A1 0C 02 01 02 BF 44 06 80 01 2A 81 01 00"));
  check_canonical(sr);
  const auto st = response_service<mms::report_journal_status_response>(sr, 2);
  CHECK(st.current_entries == 42U);
  CHECK_FALSE(st.mms_deletable);
}

TEST_CASE("The server advertises the journal and file services", "[mms]") {
  CHECK(mms::iec61850_server_services.test(mms::service_bit::file_directory));
  CHECK(mms::iec61850_server_services.test(mms::service_bit::read_journal));
  // obtainFile depends on the file store: the server adds it when it can serve it.
  CHECK_FALSE(mms::iec61850_server_services.test(mms::service_bit::obtain_file));
  // What a server issues back during obtainFile.
  for (const auto bit : {mms::service_bit::file_open, mms::service_bit::file_read, mms::service_bit::file_close}) {
    CHECK(mms::iec61850_client_services.test(bit));
    CHECK_FALSE(mms::iec61850_services.test(bit));
  }
}

TEST_CASE("ObtainFile: request and response", "[mms]") {
  const auto req = encode(mms::confirmed_request{7, {}, mms::obtain_file_request{std::nullopt, a_txt, b_txt}});
  CHECK(req == hex("A0 18 02 01 07 BF 2E 12 A1 07 19 05 'a.txt' A2 07 19 05 'b.txt'"));
  check_canonical(req);
  const auto o = request_service<mms::obtain_file_request>(req, 7);
  CHECK_FALSE(o.source_file_server);
  CHECK(names(o.source_file) == std::vector<std::string>{"a.txt"});
  CHECK(names(o.destination_file) == std::vector<std::string>{"b.txt"});
  CHECK(mms::service_tag(mms::confirmed_service_request{o}) == 46U);

  // sourceFileServer is carried opaque; several name segments are accepted, GraphicString or
  // VisibleString.
  const auto third = hex("A0 20 02 01 01 BF 2E 1A A0 03 A2 01 05 A1 0A 1A 03 'dir' 1A 03 'x.y' A2 07 19 05 'b.txt'");
  const auto t = request_service<mms::obtain_file_request>(third, 1);
  REQUIRE(t.source_file_server);
  CHECK(byte_buffer(t.source_file_server->begin(), t.source_file_server->end()) == hex("A2 01 05"));
  CHECK(names(t.source_file) == std::vector<std::string>{"dir", "x.y"});
  const auto rebuilt = request_service<mms::obtain_file_request>(encode(mms::confirmed_request{1, {}, t}), 1);
  CHECK(rebuilt.source_file_server.has_value());
  check_canonical(encode(mms::confirmed_request{1, {}, t}));

  const auto empty_server = encode(mms::confirmed_request{
      1, {}, mms::obtain_file_request{byte_view{}, a_txt, b_txt}});
  CHECK(request_service<mms::obtain_file_request>(empty_server, 1).source_file_server.has_value());

  const auto resp = encode(mms::confirmed_response{7, mms::obtain_file_response{}});
  CHECK(resp == hex("A1 06 02 01 07 9F 2E 00"));
  check_canonical(resp);
  CHECK(mms::service_tag(mms::confirmed_service_response{mms::obtain_file_response{}}) == 46U);
  (void)response_service<mms::obtain_file_response>(resp, 7);
}

TEST_CASE("ObtainFile: malformed encodings", "[mms]") {
  const auto bad = [](const char* text) { CHECK_FALSE(mms::decode_pdu(hex(text))); };
  bad("A0 06 02 01 01 BF 2E 00");                                           // both names missing
  bad("A0 0F 02 01 01 BF 2E 09 A1 07 19 05 'a.txt'");                       // no destinationFile
  bad("A0 0F 02 01 01 BF 2E 09 A2 07 19 05 'b.txt'");                       // no sourceFile
  bad("A0 18 02 01 01 BF 2E 12 A2 07 19 05 'b.txt' A1 07 19 05 'a.txt'");   // out of order
  bad("A0 18 02 01 01 9F 2E 12 A1 07 19 05 'a.txt' A2 07 19 05 'b.txt'");   // primitive service
  bad("A0 16 02 01 01 BF 2E 10 81 05 'a.txt' A2 07 19 05 'b.txt'");         // primitive FileName
  bad("A0 1A 02 01 01 BF 2E 14 A1 07 19 05 'a.txt' A2 07 19 05 'b.txt' 05 00");  // trailing field
  bad("A0 18 02 01 01 BF 2E 12 A1 07 04 05 'a.txt' A2 07 19 05 'b.txt'");   // not a string
  bad("A0 18 02 01 01 BF 2E 12 A1 09 19 05 'a.txt' A2 07 19 05 'b.txt'");   // overruns [1]
  bad("A0 18 02 01 01 BF 2E 12 A1 07 19 07 'a.txt' A2 07 19 05 'b.txt'");   // overruns the string
  bad("A0 1B 02 01 01 BF 2E 15 80 01 00 A1 07 19 05 'a.txt' A2 07 19 05 'b.txt'");  // primitive [0]
  bad("A1 07 02 01 07 9F 2E 01 00");                                        // response is NULL
  bad("A1 06 02 01 07 BF 2E 00");                                           // response constructed
}
