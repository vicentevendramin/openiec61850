#include <cstddef>
#include <cstdint>

#include "openiec61850/iso/session/spdu.hpp"

namespace ss = openiec61850::iso::session;

// Decodes arbitrary TSDUs; whatever decodes must re-encode and decode again to the same SPDU kind.
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  const openiec61850::byte_view input{data, size};
  auto decoded = ss::decode_tsdu(input);
  if (!decoded) return 0;
  openiec61850::byte_buffer out;
  if (!ss::encode(*decoded, out)) return 0;
  auto again = ss::decode_tsdu(out);
  if (!again || again->index() != decoded->index()) __builtin_trap();
  return 0;
}
