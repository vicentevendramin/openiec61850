#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "openiec61850/core/result.hpp"
#include "openiec61850/mms/data.hpp"
#include "openiec61850/mms/pdu.hpp"
#include "openiec61850/model/basic_type.hpp"
#include "openiec61850/model/entry_id.hpp"
#include "openiec61850/model/object_reference.hpp"
#include "openiec61850/model/rcb_options.hpp"
#include "openiec61850/model/timestamp.hpp"

// IEC 61850 reports (IEC 61850-7-2 §17.2.3, IEC 61850-8-1 §17.2.3.2). A report is an MMS
// InformationReport whose variableAccessSpecification is variableListName = vmd-specific "RPT"
// and whose listOfAccessResult holds, in this order:
//
//   RptID                 visible-string
//   OptFlds               bit-string(10)
//   SeqNum                unsigned          if OptFlds.sequence-number
//   TimeOfEntry           binary-time       if OptFlds.report-time-stamp
//   DatSet                visible-string    if OptFlds.data-set-name
//   BufOvfl               boolean           if OptFlds.buffer-overflow
//   EntryID               octet-string(8)   if OptFlds.entryID
//   ConfRev               unsigned          if OptFlds.conf-revision
//   SubSeqNum             unsigned          if OptFlds.segmentation
//   MoreSegmentsFollow    boolean           if OptFlds.segmentation
//   Inclusion             bit-string(n)     one bit per data set member
//   data-reference        visible-string    one per included member, if OptFlds.data-reference
//   value                 Data              one per included member
//   ReasonCode            bit-string(6|7)   one per included member, if OptFlds.reason-for-inclusion
//
// A segmented report (OptFlds.segmentation) is delivered one segment at a time; each segment is
// self-contained (its own inclusion bit-string) and carries sub_seq_num / more_segments_follow.

namespace openiec61850::client {

struct report_entry {
  std::size_t index = 0;  // position of the member in the data set
  // The data-reference as sent (MMS form "LD/LN$FC$DO..."); empty when not included.
  std::string data_reference;
  // The member as an FCD/FCDA reference: parsed from data_reference, else taken from the data set
  // directory cached at enable time; unset when neither is available.
  std::optional<model::object_reference> reference;
  mms::data value;
  std::optional<model::trigger_conditions> reason;
};

struct report {
  std::string rpt_id;
  model::optional_fields opt_flds;
  std::optional<std::uint32_t> seq_num;
  std::optional<model::entry_time> time_of_entry;
  std::optional<std::string> data_set;  // MMS form, as sent
  std::optional<bool> buffer_overflow;
  std::optional<model::entry_id> entry_id;
  std::optional<std::uint32_t> conf_rev;
  std::optional<std::uint32_t> sub_seq_num;
  std::optional<bool> more_segments_follow;
  std::vector<bool> inclusion;
  std::vector<report_entry> entries;  // the included members, in data set order
  // The RCB this report was matched to (by RptID, then DatSet) among those enabled with
  // enable_reporting(); unset otherwise.
  std::optional<model::object_reference> rcb;
  // Reports dropped (queue overflow, or InformationReports that could not be parsed as a report)
  // immediately before this one.
  std::size_t lost_before = 0;
};

// True when the InformationReport is addressed to variableListName "RPT".
[[nodiscard]] bool is_report(const mms::information_report& ir) noexcept;

// Parses a report. `members` (the data set directory) names the entries whose data-reference was
// not sent. Errors: errc::protocol_violation when the access results do not follow the layout
// above (wrong count or type, a failure result, an inclusion bit-string longer than `members`
// when they are given), errc::unsupported unless is_report().
[[nodiscard]] result<report> parse_report(const mms::information_report& ir,
                                          std::span<const model::object_reference> members = {},
                                          const model::parse_options& opts = {});

}  // namespace openiec61850::client
