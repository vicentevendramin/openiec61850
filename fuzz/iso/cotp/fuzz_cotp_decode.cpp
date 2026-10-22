// libFuzzer harness: TPKT framer and TPDU decoder, with an encode/decode round trip.
#include <cstddef>
#include <cstdint>

#include "openiec61850/iso/cotp/tpdu.hpp"
#include "openiec61850/iso/cotp/tpkt.hpp"

using namespace openiec61850;
using namespace openiec61850::iso::cotp;

namespace {

void check_tpdu(byte_view in) {
  auto decoded = decode_tpdu(in);
  if (!decoded) return;
  // A decoded TPDU must re-encode, and its encoding must be a fixed point.
  byte_buffer first;
  if (!encode(*decoded, first)) __builtin_trap();
  auto again = decode_tpdu(first);
  if (!again) __builtin_trap();
  byte_buffer second;
  if (!encode(*again, second) || first != second) __builtin_trap();
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  const byte_view input{data, size};
  check_tpdu(input);
  if (input.empty()) return 0;

  // The first octet selects the chunk size used to feed the framer.
  const std::size_t chunk = std::size_t{input[0]} % 16 + 1;
  const byte_view stream = input.subspan(1);
  tpkt_framer framer{std::size_t{input[0]} * 64};
  for (std::size_t off = 0; off < stream.size(); off += chunk) {
    const std::size_t n = stream.size() - off < chunk ? stream.size() - off : chunk;
    framer.feed(stream.subspan(off, n));
    while (true) {
      auto packet = framer.next();
      if (!packet) return 0;
      if (!*packet) break;
      check_tpdu(**packet);
    }
  }
  return 0;
}
