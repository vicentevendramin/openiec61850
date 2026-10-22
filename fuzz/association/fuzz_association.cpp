#include <cstddef>
#include <cstdint>
#include <memory>
#include <variant>

#include "../../src/association/handshake.hpp"
#include "openiec61850/association/types.hpp"

namespace assoc = openiec61850::association;
namespace detail = openiec61850::association::detail;
namespace ps = openiec61850::iso::presentation;
using openiec61850::byte_buffer;
using openiec61850::byte_view;

namespace {

// What the association layer does with each PDV of a P-DATA: decode it as an owning MMS PDU.
void decode_data(const ps::event& ev, byte_view tsdu, std::uint32_t mms_context) {
  const auto* d = std::get_if<ps::data_indication>(&ev);
  if (d == nullptr) return;
  const auto buffer = std::make_shared<const byte_buffer>(tsdu.begin(), tsdu.end());
  for (const auto& p : d->user_data) {
    if (p.context_id != mms_context) continue;
    // Re-point the PDV into the owned copy, as the reader does with the received TSDU.
    const auto offset = static_cast<std::size_t>(p.data.data() - tsdu.data());
    if (offset + p.data.size() > tsdu.size()) __builtin_trap();
    const byte_view inside{buffer->data() + offset, p.data.size()};
    if (auto m = assoc::received_pdu::decode(buffer, inside)) {
      if (m->encoding().data() != inside.data()) __builtin_trap();
      (void)openiec61850::mms::invoke_id(m->pdu());
    } else {
      (void)openiec61850::mms::peek_invoke_id(inside);
    }
  }
}

}  // namespace

// Input layout: one control octet (bit 0: responder), then TSDUs framed as a two-octet big-endian
// length followed by that many octets. The responder parses the CP(AARQ(Initiate)) and accepts
// or refuses it like server_association; the initiator sends the default CP and interprets the
// answer like client_association. Later TSDUs go through the data-transfer path.
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  if (size < 1) return 0;
  const bool responder = (data[0] & 0x01) != 0;
  byte_view rest{data + 1, size - 1};

  const assoc::association_params params;
  const assoc::server_options options;
  ps::connection c = responder ? ps::connection(ps::role::responder, detail::responder_options(options))
                               : ps::connection(ps::role::initiator, detail::initiator_options(params));
  byte_buffer out;
  if (!responder && !detail::connect_request(c, params, out)) __builtin_trap();
  std::uint32_t mms_context = assoc::mms_context_id;
  bool established = false;

  while (rest.size() >= 2) {
    const std::size_t length = (std::size_t{rest[0]} << 8) | rest[1];
    rest = rest.subspan(2);
    if (length > rest.size()) break;
    const byte_view tsdu = rest.first(length);
    rest = rest.subspan(length);
    out.clear();
    auto ev = c.on_tsdu(tsdu, out);
    if (!ev) break;
    out.clear();
    if (!established) {
      if (responder) {
        const auto* ci = std::get_if<ps::connect_indication>(&*ev);
        if (ci == nullptr) continue;
        const auto ind = detail::parse_associate_request(*ci, {});
        if (ind.request) {
          if (!ind.acse_context || !ind.mms_context) __builtin_trap();
          const auto n = assoc::negotiate(ind.request->initiate, options.limits);
          if (!detail::accept_association(c, ind, options, n, out)) __builtin_trap();
          mms_context = *ind.mms_context;
          established = true;
        } else {
          (void)detail::refuse_association(c, ind, options, ind.diagnostic, out);
        }
      } else {
        const auto r = detail::parse_associate_response(*ev, params.initiate, {});
        if (!r.error) {
          const auto& n = r.negotiated;
          if (n.max_serv_outstanding_calling < 1 ||
              n.max_serv_outstanding_calling > params.initiate.max_serv_outstanding_calling) {
            __builtin_trap();
          }
          established = true;
        }
      }
      continue;
    }
    decode_data(*ev, tsdu, mms_context);
  }
  (void)c.on_transport_disconnect();
  return 0;
}
