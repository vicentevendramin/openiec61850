// Codec micro-benchmarks: BER TLV walk, MMS PDU decode (zero-copy data_view vs owning data),
// report parsing and Read request encoding. Inputs are built once per benchmark (payloads.hpp);
// only the decode / encode work is timed.

#include <benchmark/benchmark.h>

#include <cstddef>
#include <cstdint>
#include <variant>
#include <vector>

#include "openiec61850/ber/decode.hpp"
#include "openiec61850/client/report.hpp"
#include "openiec61850/mms/data.hpp"
#include "openiec61850/mms/pdu.hpp"
#include "payloads.hpp"

namespace {

namespace ber = openiec61850::ber;
namespace client = openiec61850::client;
namespace mms = openiec61850::mms;
using openiec61850::byte_buffer;
using openiec61850::byte_view;

constexpr std::int64_t small = 10;
constexpr std::int64_t large = 1000;

void set_bytes(benchmark::State& state, std::size_t bytes_per_iteration) {
  state.SetBytesProcessed(state.iterations() * static_cast<std::int64_t>(bytes_per_iteration));
}

// Visits every TLV of the encoding (depth-first), as a decoder would.
std::size_t walk(byte_view data) {
  std::size_t count = 0;
  while (!data.empty()) {
    auto e = ber::decode_tlv(data);
    if (!e) return count;
    ++count;
    if (e->constructed()) count += walk(e->value);
    data = data.subspan(e->encoding.size());
  }
  return count;
}

// ---------------------------------------------------------------------------------------------
// BER

void BM_BerTlvWalk(benchmark::State& state) {
  const auto pdu = bench::read_response(static_cast<std::size_t>(state.range(0)));
  std::size_t tlvs = 0;
  for (auto _ : state) {
    tlvs = walk(pdu);
    benchmark::DoNotOptimize(tlvs);
  }
  set_bytes(state, pdu.size());
  state.SetItemsProcessed(state.iterations() * static_cast<std::int64_t>(tlvs));
  state.counters["tlvs"] = static_cast<double>(tlvs);
}
BENCHMARK(BM_BerTlvWalk)->Arg(small)->Arg(large);

// ---------------------------------------------------------------------------------------------
// MMS Read response

// Decodes the PDU and reads mag.f of every result through views (no allocation per value).
void BM_MmsDecodeReadResponse_View(benchmark::State& state) {
  const auto pdu = bench::read_response(static_cast<std::size_t>(state.range(0)));
  for (auto _ : state) {
    auto decoded = mms::decode_pdu(pdu);
    if (!decoded) {
      state.SkipWithError("decode_pdu failed");
      break;
    }
    const auto& rsp = std::get<mms::read_response>(std::get<mms::confirmed_response>(*decoded).service);
    float sum = 0;
    for (const auto& r : rsp.results) {
      auto mag = r.value.view().at(0);
      auto f = mag ? mag->at(0) : mag;
      if (f) {
        if (auto x = f->as_float()) sum += *x;
      }
    }
    benchmark::DoNotOptimize(sum);
  }
  set_bytes(state, pdu.size());
  state.SetItemsProcessed(state.iterations() * state.range(0));
}
BENCHMARK(BM_MmsDecodeReadResponse_View)->Arg(small)->Arg(large);

// Decodes the PDU and deep-copies every result into an owning mms::data tree (what client::read
// hands to the caller).
void BM_MmsDecodeReadResponse_Owning(benchmark::State& state) {
  const auto pdu = bench::read_response(static_cast<std::size_t>(state.range(0)));
  std::vector<mms::data> values;
  for (auto _ : state) {
    auto decoded = mms::decode_pdu(pdu);
    if (!decoded) {
      state.SkipWithError("decode_pdu failed");
      break;
    }
    const auto& rsp = std::get<mms::read_response>(std::get<mms::confirmed_response>(*decoded).service);
    values.clear();
    for (const auto& r : rsp.results) {
      auto d = mms::data::from_view(r.value.view());
      if (d) values.push_back(std::move(*d));
    }
    benchmark::DoNotOptimize(values.data());
  }
  set_bytes(state, pdu.size());
  state.SetItemsProcessed(state.iterations() * state.range(0));
}
BENCHMARK(BM_MmsDecodeReadResponse_Owning)->Arg(small)->Arg(large);

// ---------------------------------------------------------------------------------------------
// MMS InformationReport

void BM_MmsDecodeInformationReport_View(benchmark::State& state) {
  const auto pdu = bench::report(static_cast<std::size_t>(state.range(0)), true);
  for (auto _ : state) {
    auto decoded = mms::decode_pdu(pdu);
    if (!decoded) {
      state.SkipWithError("decode_pdu failed");
      break;
    }
    const auto& ir = std::get<mms::information_report>(std::get<mms::unconfirmed_pdu>(*decoded).service);
    std::size_t n = 0;
    for (const auto& r : ir.results) n += r.value.view().encoding().size();
    benchmark::DoNotOptimize(n);
  }
  set_bytes(state, pdu.size());
  state.SetItemsProcessed(state.iterations() * state.range(0));
}
BENCHMARK(BM_MmsDecodeInformationReport_View)->Arg(small)->Arg(large);

void BM_MmsDecodeInformationReport_Owning(benchmark::State& state) {
  const auto pdu = bench::report(static_cast<std::size_t>(state.range(0)), true);
  std::vector<mms::data> values;
  for (auto _ : state) {
    auto decoded = mms::decode_pdu(pdu);
    if (!decoded) {
      state.SkipWithError("decode_pdu failed");
      break;
    }
    const auto& ir = std::get<mms::information_report>(std::get<mms::unconfirmed_pdu>(*decoded).service);
    values.clear();
    for (const auto& r : ir.results) {
      auto d = mms::data::from_view(r.value.view());
      if (d) values.push_back(std::move(*d));
    }
    benchmark::DoNotOptimize(values.data());
  }
  set_bytes(state, pdu.size());
  state.SetItemsProcessed(state.iterations() * state.range(0));
}
BENCHMARK(BM_MmsDecodeInformationReport_Owning)->Arg(small)->Arg(large);

// ---------------------------------------------------------------------------------------------
// Reports: decode_pdu + client::parse_report. Arg 0 = entries, arg 1 = data-reference included.

void BM_ParseReport(benchmark::State& state) {
  const auto n = static_cast<std::size_t>(state.range(0));
  const bool with_refs = state.range(1) != 0;
  const auto pdu = bench::report(n, with_refs);
  for (auto _ : state) {
    auto decoded = mms::decode_pdu(pdu);
    if (!decoded) {
      state.SkipWithError("decode_pdu failed");
      break;
    }
    const auto& ir = std::get<mms::information_report>(std::get<mms::unconfirmed_pdu>(*decoded).service);
    auto r = client::parse_report(ir);
    if (!r || r->entries.size() != n) {
      state.SkipWithError("parse_report failed");
      break;
    }
    benchmark::DoNotOptimize(r->entries.data());
  }
  set_bytes(state, pdu.size());
  state.SetItemsProcessed(state.iterations() * state.range(0));
}
BENCHMARK(BM_ParseReport)->ArgNames({"entries", "refs"})->ArgsProduct({{1, 16, 256}, {0, 1}});

// ---------------------------------------------------------------------------------------------
// Read request encoding (what client::read_many puts on the wire per request).

void BM_EncodeReadRequest(benchmark::State& state) {
  const bench::read_request_input input(static_cast<std::size_t>(state.range(0)));
  byte_buffer out;
  std::uint32_t invoke_id = 0;
  for (auto _ : state) {
    out.clear();
    if (!mms::encode_pdu(input.pdu(++invoke_id), out)) {
      state.SkipWithError("encode_pdu failed");
      break;
    }
    benchmark::DoNotOptimize(out.data());
  }
  set_bytes(state, out.size());
  state.SetItemsProcessed(state.iterations() * state.range(0));
}
BENCHMARK(BM_EncodeReadRequest)->Arg(1)->Arg(16)->Arg(128);

}  // namespace
