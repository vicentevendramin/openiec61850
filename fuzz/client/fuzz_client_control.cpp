// Decodes arbitrary input as an MMSpdu and, when it is an InformationReport, parses it as a
// control message (LastApplError / CommandTermination, IEC 61850-8-1 §20) and derives the key
// the client routes it by.
// Seed corpus: fuzz/corpus/client_control/

#include <cstddef>
#include <cstdint>
#include <variant>

#include "openiec61850/client/control.hpp"
#include "openiec61850/mms/pdu.hpp"

namespace client = openiec61850::client;
namespace mms = openiec61850::mms;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  auto pdu = mms::decode_pdu({data, size});
  if (!pdu) return 0;
  const auto* u = std::get_if<mms::unconfirmed_pdu>(&*pdu);
  if (u == nullptr) return 0;
  const auto* ir = std::get_if<mms::information_report>(&u->service);
  if (ir == nullptr) return 0;
  const bool control = client::is_control_message(*ir);
  auto m = client::parse_control_message(*ir);
  if (m && !control) __builtin_trap();
  if (m) {
    if (m->type == client::control_message::kind::last_appl_error && !m->error) __builtin_trap();
    (void)client::to_string(m->error ? m->error->cause : client::add_cause::none);
  }
  return 0;
}
