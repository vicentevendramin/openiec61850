#include <catch2/catch_test_macros.hpp>

#include <system_error>

#include "goose_test_util.hpp"
#include "openiec61850/goose/pdu.hpp"

namespace goose = openiec61850::goose;
namespace mms = openiec61850::mms;
using namespace std::chrono_literals;

namespace {

bool not_permitted(const std::error_code& ec) {
  return ec == std::errc::operation_not_permitted || ec == std::errc::permission_denied ||
         ec == openiec61850::errc::unsupported;
}

}  // namespace

TEST_CASE("Raw socket link on the loopback interface", "[goose]") {
  asio::io_context ctx;
  goose::raw_socket_options opts;
  opts.interface_name = "lo";
  opts.all_multicast = false;
  auto rx = goose::raw_socket_link::open(ctx.get_executor(), opts);
  if (!rx && not_permitted(rx.error())) SKIP("CAP_NET_RAW not available: " << rx.error().message());
  REQUIRE(rx);
  auto tx = goose::raw_socket_link::open(ctx.get_executor(), opts);
  REQUIRE(tx);
  CHECK((*rx)->interface_index() > 0);

  auto cap = goose_test::start_capture(ctx, *rx);
  goose::frame_header h;
  h.destination = goose::goose_multicast_base;
  h.source = goose_test::mac_a;
  h.vlan.reset();
  h.app_id = 0x3001;
  goose::pdu_fields f;
  f.gocb_ref = "RAW/LLN0$GO$g";
  f.dat_set = "RAW/LLN0$DS";
  openiec61850::byte_buffer frame;
  const std::vector<mms::data> values{mms::data::boolean(true)};
  REQUIRE(goose::encode(h, f, values, frame));
  REQUIRE((*tx)->send(frame));
  goose_test::run_for(ctx, 100ms);

  // Other traffic on lo is filtered by EtherType; other GOOSE senders may exist.
  bool found = false;
  for (const auto& got : cap->frames) {
    auto m = goose::decode(got);
    if (m && m->frame.app_id == 0x3001 && m->pdu.gocb_ref == "RAW/LLN0$GO$g") found = true;
  }
  CHECK(found);
  (*rx)->close();
  (*tx)->close();
  goose_test::run_for(ctx, 5ms);
}

TEST_CASE("Raw socket link errors", "[goose]") {
  asio::io_context ctx;
  goose::raw_socket_options opts;
  opts.interface_name = "no-such-if0";
  auto l = goose::raw_socket_link::open(ctx.get_executor(), opts);
  REQUIRE_FALSE(l);
  // Without privileges the socket call fails first.
  CHECK((l.error() == std::errc::no_such_device || not_permitted(l.error())));
}
