// Decodes arbitrary input as an MMSpdu and, when it is an InformationReport, parses it as an
// IEC 61850 report, with and without a data set directory to name the entries.
// Seed corpus: fuzz/corpus/client_report/

#include <cstddef>
#include <cstdint>
#include <variant>
#include <vector>

#include "openiec61850/client/report.hpp"
#include "openiec61850/mms/pdu.hpp"
#include "openiec61850/model/object_reference.hpp"

namespace client = openiec61850::client;
namespace mms = openiec61850::mms;
namespace model = openiec61850::model;

namespace {

const std::vector<model::object_reference>& members() {
  static const std::vector<model::object_reference> m = [] {
    std::vector<model::object_reference> v;
    for (const char* text : {"IED1LD0/MMXU1.TotW[MX]", "IED1LD0/XCBR1.Pos.stVal[ST]",
                             "IED1LD0/XCBR1.Pos.q[ST]", "IED1LD0/GGIO1.Ind1.stVal[ST]"}) {
      if (auto r = model::object_reference::parse(text)) v.push_back(*r);
    }
    return v;
  }();
  return m;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  auto pdu = mms::decode_pdu({data, size});
  if (!pdu) return 0;
  const auto* u = std::get_if<mms::unconfirmed_pdu>(&*pdu);
  if (u == nullptr) return 0;
  const auto* ir = std::get_if<mms::information_report>(&u->service);
  if (ir == nullptr) return 0;
  if (auto r = client::parse_report(*ir)) {
    std::size_t included = 0;
    for (const bool b : r->inclusion) included += b ? 1 : 0;
    if (included != r->entries.size()) __builtin_trap();
  }
  (void)client::parse_report(*ir, members());
  return 0;
}
