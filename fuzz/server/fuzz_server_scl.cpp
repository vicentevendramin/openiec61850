// Feeds SCL text to the SCL loader and maps every IED of the document onto a server data model
// (scl::instantiate + model_builder), lenient and strict.

#include <cstddef>
#include <cstdint>
#include <string_view>

#include "openiec61850/scl/scl.hpp"
#include "openiec61850/server/scl_model.hpp"

namespace scl = openiec61850::scl;
namespace srv = openiec61850::server;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  scl::load_options lo;
  lo.max_input_size = 1 << 20;
  lo.max_diagnostics = 100;
  const std::string_view text(reinterpret_cast<const char*>(data), size);
  auto r = scl::load_string(text, lo);
  if (!r.doc) return 0;
  srv::scl_load_options o;
  o.instantiate.max_nodes = 20000;
  o.max_report_instances = 5;
  std::size_t ieds = 0;
  for (const auto& ied : r.doc->ieds) {
    if (++ieds > 4) break;
    scl::diagnostics diags;
    diags.set_limit(100);
    (void)srv::load_model(*r.doc, ied.name, {}, o, &diags);
    o.strict = true;
    (void)srv::load_model(*r.doc, ied.name, {}, o, &diags);
    o.strict = false;
  }
  return 0;
}
