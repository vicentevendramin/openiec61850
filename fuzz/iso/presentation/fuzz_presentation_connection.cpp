#include <cstddef>
#include <cstdint>

#include "openiec61850/iso/presentation/connection.hpp"

namespace ps = openiec61850::iso::presentation;

// Input layout: one control octet (bit 0: role, bit 1: establish the connection first), then TSDUs
// framed as a two-octet big-endian length followed by that many octets.
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  if (size < 1) return 0;
  const bool responder = (data[0] & 0x01) != 0;
  const bool establish = (data[0] & 0x02) != 0;
  openiec61850::byte_view rest{data + 1, size - 1};

  ps::connection_options options;
  options.session.local_selector = {0x00, 0x01};
  options.session.remote_selector = {0x00, 0x01};
  options.local_selector = {0x00, 0x00, 0x00, 0x01};
  options.remote_selector = {0x00, 0x00, 0x00, 0x01};
  options.contexts = {{1, ps::acse_abstract_syntax}, {3, ps::mms_abstract_syntax}};
  ps::connection c{responder ? ps::role::responder : ps::role::initiator, options};
  openiec61850::byte_buffer out;

  if (establish) {
    if (responder) {
      ps::connection peer{ps::role::initiator, options};
      openiec61850::byte_buffer cn;
      if (!peer.connect({}, cn)) __builtin_trap();
      if (!c.on_tsdu(cn, out)) __builtin_trap();
      (void)c.accept({}, out);
    } else {
      (void)c.connect({}, out);
    }
  }

  const std::uint8_t apdu[] = {0x05, 0x00};
  while (rest.size() >= 2) {
    const std::size_t length = (std::size_t{rest[0]} << 8) | rest[1];
    rest = rest.subspan(2);
    if (length > rest.size()) break;
    out.clear();
    auto ev = c.on_tsdu(rest.first(length), out);
    rest = rest.subspan(length);
    if (!ev) {
      if (c.current_state() != ps::state::closed) __builtin_trap();
      break;
    }
    // Every PDV handed up must belong to the defined context set.
    if (const auto* d = std::get_if<ps::data_indication>(&*ev)) {
      for (const auto& p : d->user_data) {
        if (!c.is_accepted(p.context_id)) __builtin_trap();
      }
    }
    out.clear();
    if (std::holds_alternative<ps::connect_indication>(*ev)) (void)c.accept({}, out);
    if (std::holds_alternative<ps::release_indication>(*ev)) (void)c.release_response({}, out);
    if (c.current_state() == ps::state::data_transfer) (void)c.send_data(3, apdu, out);
  }
  (void)c.on_transport_disconnect();
  return 0;
}
