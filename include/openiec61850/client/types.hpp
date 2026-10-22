#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <system_error>
#include <vector>

#include "openiec61850/association/client_association.hpp"
#include "openiec61850/core/bytes.hpp"
#include "openiec61850/mms/data.hpp"
#include "openiec61850/mms/type_description.hpp"
#include "openiec61850/model/basic_type.hpp"
#include "openiec61850/model/entry_id.hpp"
#include "openiec61850/model/functional_constraint.hpp"
#include "openiec61850/model/object_reference.hpp"
#include "openiec61850/model/rcb_options.hpp"
#include "openiec61850/model/timestamp.hpp"

// Value types of the ACSI client API. All of them own their data (no views), so they can be
// copied across threads and into a language binding.

namespace openiec61850::client {

// ---------------------------------------------------------------------------------------------
// Connection

// Association recovery (GLOSSARY "Restauração de associação"). When the association is lost (not
// released or aborted locally), the client reconnects with the same parameters, re-enables the
// RCBs it had enabled with the same settings and, for BRCBs, writes the last EntryID received
// before RptEna so the stream resumes after it without loss. Requests pending at the time of the
// loss fail with the loss error and are not replayed; requests issued while reconnecting fail with
// errc::not_connected.
struct recovery_options {
  bool enabled = false;
  // Delay before each reconnection attempt; the last value repeats. Empty: no delay.
  std::vector<std::chrono::milliseconds> backoff{std::chrono::milliseconds{100},
                                                 std::chrono::milliseconds{500},
                                                 std::chrono::seconds{1}, std::chrono::seconds{2},
                                                 std::chrono::seconds{5}};
  // Attempts per loss before giving up (connection_event::failed); zero: unlimited.
  std::size_t max_attempts = 0;
};

struct client_options {
  // Host, port, ISO selectors, AP titles, password, Initiate proposal and timeouts.
  association::association_params association;
  // Edition of the server (GLOSSARY "Edição do Servidor"): name length limits used when mapping
  // and parsing references. Auto-detection is not implemented.
  model::edition edition = model::edition::ed2;
  // Strict [prefix]LNClass[inst] LN names when parsing references received from the server.
  bool strict_ln_names = false;
  recovery_options recovery;
  // Reports kept for next_report(); at least 1. On overflow the oldest is dropped and counted in
  // the next report's lost_before.
  std::size_t report_queue_capacity = 1024;
  // Connection events kept for next_event(); at least 1, oldest dropped on overflow.
  std::size_t event_queue_capacity = 64;
};

enum class connection_state : std::uint8_t {
  established,   // services may be invoked
  reconnecting,  // association lost, recovery in progress (requests fail with not_connected)
  closing,       // close() in progress
  closed,        // released, aborted, lost without recovery, or recovery failed; see wait_closed()
};

struct rcb_error {
  model::object_reference rcb;
  std::error_code error;
};

struct connection_event {
  enum class kind : std::uint8_t {
    lost,          // the association was lost; `error` is why
    reconnecting,  // attempt number `attempt` is about to start
    restored,      // reconnected; RCBs that could not be re-enabled are in `rcb_errors`
    failed,        // recovery gave up after `attempt` attempts; `error` is the last failure
  };

  kind type = kind::lost;
  std::error_code error;
  std::size_t attempt = 0;
  std::vector<rcb_error> rcb_errors;
};

// ---------------------------------------------------------------------------------------------
// Directory and definition (IEC 61850-7-2 §8, §10, §11; 8-1 §9 - §11)

// GetLogicalNodeDirectory: the names of each ACSI class in an LN.
struct logical_node_directory {
  std::vector<std::string> data_objects;
  std::vector<std::string> data_sets;
  std::vector<std::string> brcbs;
  std::vector<std::string> urcbs;
  std::vector<std::string> lcbs;
  std::vector<std::string> gocbs;
  std::vector<std::string> msvcbs;
  std::vector<std::string> usvcbs;
  bool sgcb = false;  // LLN0.SGCB [SP]
};

// One child of GetDataDirectory, with the FCs it appears under (sorted, unique).
struct data_directory_entry {
  std::string name;
  std::vector<model::functional_constraint> fcs;

  friend bool operator==(const data_directory_entry&, const data_directory_entry&) = default;
};

// GetDataDefinition: a tree mirroring the MMS TypeDescription, with the IEC 61850 names and FCs.
struct data_definition {
  enum class kind : std::uint8_t { structure, array, basic };

  std::string name;
  // The FC of this node and of everything below it; unset for a node that spans several FCs
  // (a data object or LN read without an FC).
  std::optional<model::functional_constraint> fc;
  kind type = kind::basic;
  mms::data_type mms_type = mms::data_type::structure;
  // When known: model::deduce_basic_type, refined by the attribute name for the bit-string and
  // octet-string types of control blocks (OptFlds, TrgOps, EntryID...) and stVal of Dbpos.
  std::optional<model::basic_type> basic_type;
  // String types: maximum length (negative in the TypeDescription for variable length is
  // reported here as positive with `variable_length` set); integer/unsigned: width in bits;
  // bit-string: number of bits.
  std::int32_t size = 0;
  bool variable_length = false;
  std::uint32_t array_size = 0;  // arrays: number of elements
  // Structure components, or the single element definition of an array.
  std::vector<data_definition> children;

  // Child by name; nullptr when absent.
  [[nodiscard]] const data_definition* find(std::string_view child) const noexcept;
};

// ---------------------------------------------------------------------------------------------
// Data access and data sets (7-2 §12, §13)

struct write_item {
  model::object_reference reference;  // functionally constrained
  mms::data value;
};

struct data_set_directory {
  std::vector<model::object_reference> members;  // FCD / FCDA references
  bool deletable = false;
};

// ---------------------------------------------------------------------------------------------
// Report control blocks (7-2 §17, 8-1 §17)

// Attributes of a BRCB or URCB as read with get_rcb_values(); attributes the server does not
// have (e.g. ResvTms and Owner in Ed.1, Resv of a BRCB) are left unset.
struct rcb_values {
  std::optional<std::string> rpt_id;
  std::optional<bool> rpt_ena;
  std::optional<bool> resv;                 // URCB
  std::optional<std::string> dat_set;       // MMS form: "LD/LN$DS" or "@DS"; empty: none
  std::optional<std::uint32_t> conf_rev;
  std::optional<model::optional_fields> opt_flds;
  std::optional<std::uint32_t> buf_tm;
  std::optional<std::uint32_t> sq_num;
  std::optional<model::trigger_conditions> trg_ops;
  std::optional<std::uint32_t> intg_pd;
  std::optional<bool> gi;
  std::optional<bool> purge_buf;                 // BRCB
  std::optional<model::entry_id> entry_id;       // BRCB
  std::optional<model::entry_time> time_of_entry;  // BRCB
  std::optional<std::int32_t> resv_tms;          // BRCB, Ed.2
  std::optional<byte_buffer> owner;              // Ed.2

  // DatSet as an object reference; unset when DatSet is absent, empty or not parseable.
  [[nodiscard]] std::optional<model::object_reference> data_set(
      const model::parse_options& opts = {}) const;
};

// Attributes written by set_rcb_values(); unset ones are not written. They are written one per
// Write request, in this order: Resv, ResvTms, RptID, DatSet, OptFlds, BufTm, TrgOps, IntgPd,
// PurgeBuf, EntryID, RptEna, GI.
struct rcb_settings {
  std::optional<bool> resv;
  std::optional<std::int32_t> resv_tms;
  std::optional<std::string> rpt_id;
  std::optional<model::object_reference> dat_set;  // FCD-free data set reference
  std::optional<model::optional_fields> opt_flds;
  std::optional<std::uint32_t> buf_tm;
  std::optional<model::trigger_conditions> trg_ops;
  std::optional<std::uint32_t> intg_pd;
  std::optional<bool> purge_buf;
  std::optional<model::entry_id> entry_id;
  std::optional<bool> rpt_ena;
  std::optional<bool> gi;
};

// What enable_reporting() configures before setting RptEna.
struct report_settings {
  std::optional<std::string> rpt_id;
  std::optional<model::object_reference> data_set;
  // Masked with optional_fields::configurable() for the RCB type.
  std::optional<model::optional_fields> opt_flds;
  std::optional<model::trigger_conditions> trg_ops;
  std::optional<std::uint32_t> buf_tm;
  std::optional<std::uint32_t> intg_pd;
  // URCB: write Resv = true first (and Resv = false in disable_reporting()).
  bool reserve = true;
  // BRCB, Ed.2: ResvTms written first.
  std::optional<std::int32_t> resv_tms;
  // BRCB: resume after this entry (written to EntryID before RptEna).
  std::optional<model::entry_id> entry_id;
  // BRCB: PurgeBuf = true before enabling.
  bool purge_buffer = false;
  // GI = true after enabling. On recovery a GI is re-issued for URCBs and for BRCBs without an
  // EntryID to resume from.
  bool general_interrogation = false;
};

}  // namespace openiec61850::client
