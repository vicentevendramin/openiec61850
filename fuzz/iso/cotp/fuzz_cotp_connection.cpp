// libFuzzer harness: class 0 connection state machine fed with arbitrary bytes.
#include <cstddef>
#include <cstdint>
#include <variant>
#include <vector>

#include "openiec61850/iso/cotp/connection.hpp"

using namespace openiec61850;
using namespace openiec61850::iso::cotp;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  if (size == 0) return 0;
  // First octet: bit 0 role, bits 1-3 TPDU size, bits 4-7 chunk size.
  const std::uint8_t control = data[0];
  const byte_view stream{data + 1, size - 1};

  connection_config config;
  config.max_tpdu_size = std::size_t{1} << (7 + ((control >> 1) & 0x07) % 5);
  config.max_tsdu_size = 8192;
  config.calling_tsap = byte_buffer{0x00, 0x01};
  config.called_tsap = byte_buffer{0x00, 0x01};
  if (control & 0x08) {
    config.accept_connection = [](const connection_request& cr) -> std::optional<std::uint8_t> {
      if (cr.called_tsap && !cr.called_tsap->empty() && (*cr.called_tsap)[0] == 0xFF) {
        return disconnect_reason::address_unknown;
      }
      return std::nullopt;
    };
  }
  const role r = (control & 0x01) ? role::initiator : role::responder;
  auto conn = connection::create(r, std::move(config));
  if (!conn) __builtin_trap();
  if (r == role::initiator && !conn->connect()) __builtin_trap();
  (void)conn->take_output();

  const std::size_t chunk = (std::size_t{control} >> 4) * 7 + 1;
  std::vector<event> events;
  for (std::size_t off = 0; off < stream.size(); off += chunk) {
    const std::size_t n = stream.size() - off < chunk ? stream.size() - off : chunk;
    events.clear();
    conn->feed(stream.subspan(off, n), events);
    for (const auto& e : events) {
      // Echo received TSDUs to exercise segmentation.
      if (const auto* d = std::get_if<data_indication>(&e)) {
        if (!conn->send(d->tsdu) && conn->state() == connection_state::open) __builtin_trap();
      }
    }
    if (conn->has_output()) (void)conn->take_output();
    if (conn->state() == connection_state::closed) break;
  }
  events.clear();
  conn->network_closed(events);
  return 0;
}
