#include <cstddef>
#include <cstdint>

#include "openiec61850/iso/session/connection.hpp"

namespace ss = openiec61850::iso::session;

// Input layout: one control octet (bit 0: role, bit 1: establish the session first), then TSDUs
// framed as a two-octet big-endian length followed by that many octets.
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  if (size < 1) return 0;
  const bool responder = (data[0] & 0x01) != 0;
  const bool establish = (data[0] & 0x02) != 0;
  openiec61850::byte_view rest{data + 1, size - 1};

  ss::connection_options options;
  options.local_selector = {0x00, 0x01};
  options.remote_selector = {0x00, 0x01};
  ss::connection c{responder ? ss::role::responder : ss::role::initiator, options};
  openiec61850::byte_buffer out;

  if (establish) {
    if (responder) {
      ss::connection peer{ss::role::initiator, options};
      openiec61850::byte_buffer cn;
      if (!peer.connect({}, cn)) __builtin_trap();
      if (!c.on_tsdu(cn, out)) __builtin_trap();
      (void)c.accept({}, out);
    } else {
      (void)c.connect({}, out);
    }
  }

  while (rest.size() >= 2) {
    const std::size_t length = (std::size_t{rest[0]} << 8) | rest[1];
    rest = rest.subspan(2);
    if (length > rest.size()) break;
    out.clear();
    auto ev = c.on_tsdu(rest.first(length), out);
    rest = rest.subspan(length);
    if (!ev) {
      if (c.current_state() != ss::state::closed) __builtin_trap();
      break;
    }
    // Exercise local requests in whatever state the peer drove us to; failures are expected.
    out.clear();
    if (std::holds_alternative<ss::connect_indication>(*ev)) (void)c.accept({}, out);
    if (std::holds_alternative<ss::release_indication>(*ev)) (void)c.release_response({}, out);
    if (c.current_state() == ss::state::data_transfer) (void)c.send_data(rest.first(0), out);
  }
  (void)c.on_transport_disconnect();
  return 0;
}
