// Parses arbitrary input as a GOOSE frame, walks every allData value, re-encodes the PDU and
// feeds the counters to the subscriber's sequence tracker.
// Seed corpus: fuzz/corpus/goose_frame/

#include <cstddef>
#include <cstdint>
#include <vector>

#include "../mms/fuzz_util.hpp"
#include "openiec61850/goose/pdu.hpp"
#include "openiec61850/goose/subscriber.hpp"

namespace goose = openiec61850::goose;
namespace mms = openiec61850::mms;
using openiec61850::byte_buffer;
using openiec61850::byte_view;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  const byte_view input{data, size};
  (void)goose::peek_ether_type(input);
  auto m = goose::decode(input);
  if (!m) {
    // Also try the input as a bare APDU.
    if (auto p = goose::decode_pdu(input, {.max_nesting = 4})) {
      for (const auto& v : p->all_data) mms_fuzz::walk(v);
    }
    return 0;
  }
  const auto& p = m->pdu;
  std::vector<mms::data_view> values;
  for (const auto& v : p.all_data) {
    mms_fuzz::walk(v);
    values.push_back(v);
  }

  // Re-encoding the decoded fields gives a PDU that decodes to the same fields.
  goose::pdu_fields f;
  f.gocb_ref = p.gocb_ref;
  f.time_allowed_to_live = p.time_allowed_to_live;
  f.dat_set = p.dat_set;
  f.go_id = p.go_id.value_or("");
  f.t = p.t;
  f.st_num = p.st_num;
  f.sq_num = p.sq_num;
  f.simulation = p.simulation;
  f.conf_rev = p.conf_rev;
  f.nds_com = p.nds_com;
  f.num_dat_set_entries = p.num_dat_set_entries;
  byte_buffer out;
  mms_fuzz::check(static_cast<bool>(goose::encode_pdu(f, values, out)));
  auto back = goose::decode_pdu(out, {.max_nesting = 1024});
  mms_fuzz::check(back.has_value());
  mms_fuzz::check(back->gocb_ref == p.gocb_ref && back->st_num == p.st_num &&
                  back->sq_num == p.sq_num && back->conf_rev == p.conf_rev &&
                  back->t == p.t && back->all_data.size() == values.size());

  auto msg = goose::to_message(*m);
  goose::sequence_tracker t;
  (void)t.on_message(p.st_num, p.sq_num, p.time_allowed_to_live, {});
  (void)t.on_message(p.conf_rev, p.num_dat_set_entries, p.time_allowed_to_live, {});
  (void)t.expired({});
  return 0;
}
