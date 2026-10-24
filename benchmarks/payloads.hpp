#pragma once

// Synthetic, deterministic MMS payloads shaped like IEC 61850-8-1 traffic, shared by the codec
// benchmarks. Every builder returns the complete encoded MMSpdu.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <string>
#include <vector>

#include "openiec61850/core/bytes.hpp"
#include "openiec61850/mms/data.hpp"
#include "openiec61850/mms/pdu.hpp"
#include "openiec61850/model/rcb_options.hpp"

namespace bench {

namespace mms = openiec61850::mms;
namespace model = openiec61850::model;
using openiec61850::byte_buffer;

inline void check(bool ok, const char* what) {
  if (!ok) {
    std::fprintf(stderr, "benchmark fixture failed: %s\n", what);
    std::abort();
  }
}

// An MV-like value: { mag { f FLOAT32 }, q Quality BIT STRING(13), t UtcTime }.
inline mms::data measured_value(std::size_t i) {
  const std::uint8_t q[2] = {0x00, 0x00};
  return mms::data::structure({
      mms::data::structure({mms::data::floating_point(static_cast<float>(i) * 0.5F)}),
      mms::data::bit_string(q, 13),
      mms::data::utc_time(mms::utc_time{1'700'000'000U + static_cast<std::uint32_t>(i),
                                        0x800000U, 0x0A}),
  });
}

// Read response (confirmed-ResponsePDU) with `n` successful MV-like access results.
inline byte_buffer read_response(std::size_t n) {
  std::vector<mms::data> values;
  values.reserve(n);
  for (std::size_t i = 0; i < n; ++i) values.push_back(measured_value(i));
  std::vector<mms::access_result> results(values.begin(), values.end());
  mms::read_response rsp;
  rsp.results = results;
  byte_buffer out;
  check(bool(mms::encode_pdu(mms::confirmed_response{42, rsp}, out)), "encode read response");
  return out;
}

// Read request (confirmed-RequestPDU) for `n` domain-specific variables.
struct read_request_input {
  std::vector<std::string> items;
  std::vector<mms::variable_spec> specs;

  explicit read_request_input(std::size_t n) {
    items.reserve(n);
    for (std::size_t i = 0; i < n; ++i) {
      items.push_back("MMXU" + std::to_string(i + 1) + "$MX$TotW$mag$f");
    }
    specs.reserve(n);
    for (const auto& item : items) specs.emplace_back(mms::object_name::domain("IED1LD0", item));
  }

  [[nodiscard]] mms::mms_pdu pdu(std::uint32_t invoke_id) const {
    mms::read_request req;
    req.spec = mms::variable_access_specification::list(specs);
    return mms::confirmed_request{invoke_id, {}, req};
  }
};

// An IEC 61850 report (unconfirmed InformationReport on vmd-specific "RPT") with `n` included
// members of MV-like values. With `data_reference` every entry carries its data-reference, so
// parse_report() needs no data set directory.
inline byte_buffer report(std::size_t n, bool data_reference) {
  using model::optional_field;
  auto opt = model::optional_fields::of({optional_field::sequence_number,
                                         optional_field::report_time_stamp,
                                         optional_field::reason_for_inclusion,
                                         optional_field::data_set_name,
                                         optional_field::conf_revision});
  if (data_reference) opt.set(optional_field::data_reference);

  std::vector<mms::data> v;
  v.push_back(mms::data::visible_string("IED1LD0/LLN0$RP$urcb01"));
  v.push_back(opt.to_mms());
  v.push_back(mms::data::unsigned_integer(7));                          // SqNum
  v.push_back(mms::data::binary_time(mms::binary_time{3'600'000U, 14'000}));  // TimeOfEntry
  v.push_back(mms::data::visible_string("IED1LD0/LLN0$DS1"));           // DatSet
  v.push_back(mms::data::unsigned_integer(1));                          // ConfRev
  byte_buffer inclusion((n + 7) / 8, 0xFF);
  v.push_back(mms::data::bit_string(inclusion, n));
  if (data_reference) {
    for (std::size_t i = 0; i < n; ++i) {
      v.push_back(mms::data::visible_string("IED1LD0/MMXU" + std::to_string(i + 1) + "$MX$TotW"));
    }
  }
  for (std::size_t i = 0; i < n; ++i) v.push_back(measured_value(i));
  const auto reason =
      model::trigger_conditions::of({model::trigger::data_change}).to_mms_reason_code();
  check(bool(reason), "reason code");
  for (std::size_t i = 0; i < n; ++i) v.push_back(*reason);

  std::vector<mms::access_result> results(v.begin(), v.end());
  mms::information_report ir;
  ir.spec = mms::variable_access_specification::named(mms::object_name::vmd("RPT"));
  ir.results = results;
  byte_buffer out;
  check(bool(mms::encode_pdu(mms::unconfirmed_pdu{ir}, out)), "encode report");
  return out;
}

}  // namespace bench
