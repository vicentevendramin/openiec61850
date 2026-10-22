#include <cstddef>
#include <cstdint>

#include "openiec61850/iso/acse/apdu.hpp"

namespace acse = openiec61850::iso::acse;

// Decodes arbitrary APDUs; whatever decodes must re-encode, and the re-encoding must decode to the
// same APDU kind and re-encode to identical bytes (the encoder output is canonical).
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  const openiec61850::byte_view input{data, size};
  auto decoded = acse::decode(input);
  if (!decoded) return 0;
  openiec61850::byte_buffer out;
  if (!acse::encode(*decoded, out)) return 0;
  auto again = acse::decode(out);
  if (!again || again->index() != decoded->index()) __builtin_trap();
  openiec61850::byte_buffer out2;
  if (!acse::encode(*again, out2) || out2 != out) __builtin_trap();
  return 0;
}
