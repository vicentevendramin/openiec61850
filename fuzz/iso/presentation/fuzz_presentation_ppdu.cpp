#include <cstddef>
#include <cstdint>
#include <variant>
#include <vector>

#include "openiec61850/iso/presentation/ppdu.hpp"

namespace ps = openiec61850::iso::presentation;

// Feeds the input to every PPDU decoder; whatever decodes must re-encode and decode again.
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  const openiec61850::byte_view input{data, size};
  openiec61850::byte_buffer out;

  if (auto cp = ps::decode_connect(input)) {
    out.clear();
    if (ps::encode(*cp, out) && !ps::decode_connect(out)) __builtin_trap();
  }
  if (auto cpa = ps::decode_accept(input)) {
    out.clear();
    if (ps::encode(*cpa, out) && !ps::decode_accept(out)) __builtin_trap();
  }
  if (auto cpr = ps::decode_refuse(input)) {
    out.clear();
    if (ps::encode(*cpr, out) && !ps::decode_refuse(out)) __builtin_trap();
  }
  if (auto ab = ps::decode_abort(input)) {
    out.clear();
    const bool encoded = std::visit([&](const auto& p) { return bool(ps::encode(p, out)); }, *ab);
    auto again = ps::decode_abort(out);
    if (encoded && (!again || again->index() != ab->index())) __builtin_trap();
  }
  std::vector<ps::pdv> pdvs;
  if (ps::decode_user_data(input, pdvs)) {
    out.clear();
    std::vector<ps::pdv> again;
    if (!ps::encode_user_data(pdvs, out) || !ps::decode_user_data(out, again) ||
        again.size() != pdvs.size()) {
      __builtin_trap();
    }
  }
  return 0;
}
