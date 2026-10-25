// Parses arbitrary input as a Sampled Values frame, walks the ASDUs (9-2 LE values included),
// re-encodes them and checks the result decodes to the same ASDUs.
// Seed corpus: fuzz/corpus/goose_sv_frame/

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "openiec61850/goose/sv.hpp"
#include "openiec61850/goose/sv_subscriber.hpp"

namespace sv = openiec61850::sv;
using openiec61850::byte_buffer;
using openiec61850::byte_view;

namespace {
void check(bool condition) {
  if (!condition) __builtin_trap();
}
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  const byte_view input{data, size};
  auto m = sv::decode(input);
  if (!m) {
    (void)sv::decode_pdu(input);
    return 0;
  }
  std::vector<sv::asdu> asdus;
  sv::smp_cnt_tracker tracker{4000};
  std::array<sv::analog_sample, 16> samples{};
  for (const auto& a : m->pdu.asdus) {
    (void)tracker.on_sample(a.smp_cnt);
    (void)sv::decode_analog_samples(a.seq_data, samples);
    if (auto le = sv::le::decode(a.seq_data)) {
      check(sv::le::encode(*le).size() == a.seq_data.size());
      (void)le->current(0);
      (void)le->channels[0].q.to_quality();
    }
    sv::asdu e;
    e.sv_id = a.sv_id;
    e.dat_set = a.dat_set;
    e.smp_cnt = a.smp_cnt;
    e.conf_rev = a.conf_rev;
    e.refr_tm = a.refr_tm;
    e.smp_synch = a.smp_synch;
    e.smp_rate = a.smp_rate;
    e.seq_data = a.seq_data;
    e.smp_mod = a.smp_mod;
    e.gm_identity = a.gm_identity;
    asdus.push_back(e);
  }
  check(asdus.size() == m->pdu.no_asdu);
  byte_buffer out;
  check(static_cast<bool>(sv::encode(sv::frame_header{}, asdus, out)));
  auto back = sv::decode(out);
  check(back.has_value() && back->pdu.no_asdu == m->pdu.no_asdu);
  std::size_t i = 0;
  for (const auto& a : back->pdu.asdus) {
    check(a.sv_id == asdus[i].sv_id && a.smp_cnt == asdus[i].smp_cnt &&
          a.seq_data.size() == asdus[i].seq_data.size());
    ++i;
  }
  return 0;
}
