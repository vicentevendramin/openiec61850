// SCL loading and instantiation: the input is an SCL document. Every IED that loads is
// instantiated at each access point (with small limits), its data sets are checked against the
// tree and the address helpers run on every ConnectedAP / GSE / SMV.
// Seed corpus: fuzz/corpus/scl_load/

#include <cstddef>
#include <cstdint>
#include <string_view>

#include "openiec61850/scl/scl.hpp"

namespace scl = openiec61850::scl;

namespace {

void check(bool condition) {
  if (!condition) __builtin_trap();
}

void exercise(const scl::document& doc) {
  scl::instantiate_options opts;
  opts.max_nodes = 20000;
  opts.max_depth = 16;
  for (const auto& ied : doc.ieds) {
    for (const auto& ap : ied.access_points) {
      scl::diagnostics diags;
      auto r = scl::instantiate(doc, ied.name, ap.name, &diags, opts);
      if (!r) continue;
      check(r->node_count() <= opts.max_nodes);
      for (const auto& ld : r->lds) {
        for (const auto& ln : ld.lns) {
          for (const auto& ds : ln.data_sets) {
            for (const auto& m : ds.members) check(r->find(m) != nullptr);
          }
        }
      }
    }
  }
  for (const auto& sn : doc.comm.sub_networks) {
    for (const auto& cap : sn.connected_aps) {
      (void)scl::parse_ap_address(cap.addr);
      for (const auto& g : cap.gse) (void)scl::parse_l2_address(g.addr);
      for (const auto& s : cap.smv) (void)scl::parse_l2_address(s.addr);
    }
  }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  const std::string_view input{reinterpret_cast<const char*>(data), size};
  scl::load_options opts;
  opts.max_input_size = 1U << 20;
  opts.max_depth = 16;
  opts.max_diagnostics = 100;
  const auto lenient = scl::load_string(input, opts);
  if (lenient.ok()) exercise(*lenient.doc);

  opts.strict = true;
  const auto strict = scl::load_string(input, opts);
  // Strict loading succeeds exactly when lenient loading has no errors.
  check(strict.ok() == (lenient.ok() && !lenient.diags.has_errors()));
  return 0;
}
