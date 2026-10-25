#pragma once

#include <cstdint>
#include <optional>
#include <string_view>

#include "openiec61850/core/bytes.hpp"
#include "openiec61850/core/result.hpp"
#include "openiec61850/goose/frame.hpp"
#include "openiec61850/mms/data.hpp"
#include "openiec61850/mms/list_view.hpp"

// GOOSE APDU (IEC 61850-8-1 Annex A, §A.3):
//
//   IECGoosePdu ::= [APPLICATION 1] IMPLICIT SEQUENCE {
//     gocbRef            [0]  IMPLICIT VISIBLE-STRING,
//     timeAllowedtoLive  [1]  IMPLICIT INTEGER,          -- ms
//     datSet             [2]  IMPLICIT VISIBLE-STRING,
//     goID               [3]  IMPLICIT VISIBLE-STRING OPTIONAL,
//     t                  [4]  IMPLICIT UtcTime,
//     stNum              [5]  IMPLICIT INTEGER,
//     sqNum              [6]  IMPLICIT INTEGER,
//     simulation         [7]  IMPLICIT BOOLEAN DEFAULT FALSE,  -- "test" in Ed.1
//     confRev            [8]  IMPLICIT INTEGER,
//     ndsCom             [9]  IMPLICIT BOOLEAN DEFAULT FALSE,
//     numDatSetEntries   [10] IMPLICIT INTEGER,
//     allData            [11] IMPLICIT SEQUENCE OF Data,     -- MMS Data, ISO 9506-2
//     security           [12] ANY OPTIONAL }                 -- reserved for IEC 62351-6
//
// stNum, sqNum, confRev, timeAllowedtoLive and numDatSetEntries are INT32U in IEC 61850-7-2.
// The encoder always writes goID (when not empty), simulation and ndsCom, so that consecutive
// messages of one control block have the same layout. The security extension is not supported:
// it is never generated and, on decode, only handed out as raw octets (no signature check).
// The fixed-length encoding of Ed.2 (GSEControl fixedOffs) is not generated either; it decodes
// like any other BER encoding.

namespace openiec61850::goose {

struct pdu_view {
  std::string_view gocb_ref;
  std::uint32_t time_allowed_to_live = 0;  // ms
  std::string_view dat_set;
  std::optional<std::string_view> go_id;
  mms::utc_time t;
  std::uint32_t st_num = 0;
  std::uint32_t sq_num = 0;
  bool simulation = false;
  std::uint32_t conf_rev = 0;
  bool nds_com = false;
  std::uint32_t num_dat_set_entries = 0;
  // Validated MMS Data values (iteration never fails).
  mms::list_view<mms::data_view> all_data;
  std::optional<byte_view> security;  // contents of [12], not interpreted
};

// Decodes one IECGoosePdu (trailing octets after it are malformed). Fields out of order,
// missing mandatory fields, integers above 2^32-1 and invalid Data fail with
// errc::malformed_encoding / errc::value_out_of_range (or the BER / Data error).
// numDatSetEntries is not required to match the number of allData values: check
// all_data.size() when it matters (the subscriber does).
[[nodiscard]] result<pdu_view> decode_pdu(byte_view apdu,
                                          const mms::decode_options& opts = {}) noexcept;

struct message_view {
  frame_view frame;
  pdu_view pdu;
};

// Decodes a whole GOOSE frame (errc::unsupported for another EtherType).
[[nodiscard]] result<message_view> decode(byte_view frame,
                                          const mms::decode_options& opts = {}) noexcept;

// Encoder input. The strings are borrowed.
struct pdu_fields {
  std::string_view gocb_ref;
  std::uint32_t time_allowed_to_live = 0;
  std::string_view dat_set;
  std::string_view go_id;  // omitted when empty
  mms::utc_time t;
  std::uint32_t st_num = 1;
  std::uint32_t sq_num = 0;
  bool simulation = false;
  std::uint32_t conf_rev = 1;
  bool nds_com = false;
  // numDatSetEntries; the number of values when unset.
  std::optional<std::uint32_t> num_dat_set_entries;
};

// Appends the IECGoosePdu. `values` may be a vector of mms::data or mms::data_view, or an encoded
// list (its contents are copied verbatim). errc::invalid_state for an invalid value.
[[nodiscard]] result<void> encode_pdu(const pdu_fields& f, mms::list_view<mms::data_ref> values,
                                      byte_buffer& out);
// Same, with allData given as the already encoded contents of the SEQUENCE OF (`count` values),
// e.g. cached by a publisher between retransmissions.
[[nodiscard]] result<void> encode_pdu_raw(const pdu_fields& f, byte_view all_data_contents,
                                          std::uint32_t count, byte_buffer& out);

// Appends a complete frame (header.ether_type is forced to ethertype_goose).
[[nodiscard]] result<void> encode(const frame_header& header, const pdu_fields& f,
                                  mms::list_view<mms::data_ref> values, byte_buffer& out);

}  // namespace openiec61850::goose
