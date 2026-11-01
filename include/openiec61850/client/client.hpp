#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <system_error>
#include <vector>

#include <asio/any_io_executor.hpp>
#include <asio/awaitable.hpp>
#include <asio/strand.hpp>

#include "openiec61850/association/types.hpp"
#include "openiec61850/client/control.hpp"
#include "openiec61850/client/error.hpp"
#include "openiec61850/client/error_details.hpp"
#include "openiec61850/client/report.hpp"
#include "openiec61850/client/types.hpp"
#include "openiec61850/client/values.hpp"
#include "openiec61850/core/result.hpp"
#include "openiec61850/mms/data.hpp"
#include "openiec61850/model/object_reference.hpp"

namespace openiec61850::client {

namespace detail {
struct client_state;
}

// The IEC 61850 ACSI Client over MMS (IEC 61850-7-2 services mapped per IEC 61850-8-1).
//
// API shape (ADR 0002, binding parity): every argument is taken by value and every result owns
// its data, so an operation may be started from any thread and its result handed to another
// language. Each service is a coroutine; code without coroutines (e.g. the Python binding,
// which must not hold the GIL while waiting) uses the generic bridge
//
//     transport::spawn(c.get_executor(), c.read(ref), [](result<mms::data> r) { ... });
//
// whose handler runs on the I/O thread. Reports and connection events are delivered either by
// the async-iterator style next_report() / next_event() or by a callback (ADR 0004).
//
// Threading: the client state lives on its own strand (get_executor()); coroutine methods may be
// awaited from any executor and resume the caller on its own executor. Requests may be issued
// concurrently; they share the association's request slots. abort(), the setters, state(),
// last_entry_id() and the counters are safe from any thread. The handle is a move-only owner;
// destroying it aborts the association.
//
// Errors: see client/error.hpp. Every service fails with errc::not_connected while no
// association is established (recovery in progress, or closed) and with the association's
// closing error for requests that were pending when it was lost.
//
// Control (7-2 §20): get_control() / operate(), see client/control.hpp. LastApplError and
// CommandTermination InformationReports are routed to the control handles of this client; those
// for objects without a handle are discarded.
//
// Setting groups (§16), logs (§17.3, MMS journals), files (§23, MMS file services) and GoCB
// attributes (§18) are members below. SV control blocks are only listed in the LN directory.
class client {
 public:
  using executor_type = asio::strand<asio::any_io_executor>;

  // Establishes the association (association::client_association::connect errors). The first
  // connection is not retried by the recovery options.
  [[nodiscard]] static asio::awaitable<result<client>> connect(asio::any_io_executor ex,
                                                               client_options options);

  client(client&&) noexcept = default;
  client& operator=(client&& other) noexcept;
  client(const client&) = delete;
  client& operator=(const client&) = delete;
  ~client();

  // --- lifecycle

  // Orderly release (Conclude + A-RELEASE); stops recovery. While reconnecting, it just stops.
  [[nodiscard]] asio::awaitable<result<void>> release();
  [[nodiscard]] asio::awaitable<result<void>> close() { return release(); }
  // A-ABORT; stops recovery. Idempotent, any thread.
  void abort() noexcept;
  // Completes once the client is closed, with association::errc::released, aborted, or the error
  // that ended it (the loss error without recovery, errc::recovery_failed...).
  [[nodiscard]] asio::awaitable<std::error_code> wait_closed();
  [[nodiscard]] connection_state state() const noexcept;
  // Parameters negotiated by the current (or last) association.
  [[nodiscard]] association::association_info association_info() const;
  [[nodiscard]] const client_options& options() const noexcept;
  [[nodiscard]] executor_type get_executor() const noexcept;

  // --- directory and definition

  // GetServerDirectory(LOGICAL-DEVICE): GetNameList of the domains. Continuations (moreFollows /
  // continueAfter) are followed transparently by every name list.
  [[nodiscard]] asio::awaitable<result<std::vector<std::string>>> get_server_directory();
  // GetLogicalDeviceDirectory: the LN names (the domain's named variables without '$').
  [[nodiscard]] asio::awaitable<result<std::vector<std::string>>> get_logical_device_directory(
      std::string ld);
  // GetLogicalNodeDirectory for every ACSI class at once: from the LN's TypeDescription
  // (GetVariableAccessAttributes "LN") and the domain's named variable lists "LN$...".
  [[nodiscard]] asio::awaitable<result<logical_node_directory>> get_logical_node_directory(
      model::object_reference ln);
  // GetDataDirectory: the children of an LN, DO or structured DA (of the elements for an array of
  // data objects). With an FC only that FC is considered; without one the children under every FC
  // are merged.
  [[nodiscard]] asio::awaitable<result<std::vector<data_directory_entry>>> get_data_directory(
      model::object_reference ref);
  // GetDataDefinition, same FC rule as get_data_directory().
  [[nodiscard]] asio::awaitable<result<data_definition>> get_data_definition(
      model::object_reference ref);
  // Generic MMS GetNameList (all continuations), for diagnostics: `domain` empty is VMD scope.
  [[nodiscard]] asio::awaitable<result<std::vector<std::string>>> get_name_list(
      mms::object_class cls, std::string domain = {});

  // --- data access (GetDataValues / SetDataValues)

  // `ref` must be functionally constrained (openiec61850::errc::invalid_state otherwise).
  [[nodiscard]] asio::awaitable<result<mms::data>> read(model::object_reference ref);
  // One Read PDU; the outer result fails when the request does, the inner ones per variable.
  [[nodiscard]] asio::awaitable<result<std::vector<result<mms::data>>>> read_many(
      std::vector<model::object_reference> refs);
  [[nodiscard]] asio::awaitable<result<void>> write(model::object_reference ref, mms::data value);
  // One Write PDU.
  [[nodiscard]] asio::awaitable<result<std::vector<result<void>>>> write_many(
      std::vector<write_item> items);

  // --- data sets (7-2 §13)

  [[nodiscard]] asio::awaitable<result<data_set_directory>> get_data_set_directory(
      model::object_reference data_set);
  // "LD/LN.name" creates a persistent data set, "@name" one for this association only.
  [[nodiscard]] asio::awaitable<result<void>> create_data_set(
      model::object_reference data_set, std::vector<model::object_reference> members);
  [[nodiscard]] asio::awaitable<result<void>> delete_data_set(model::object_reference data_set);
  // GetDataSetValues / SetDataSetValues: Read / Write of the named variable list.
  [[nodiscard]] asio::awaitable<result<std::vector<result<mms::data>>>> get_data_set_values(
      model::object_reference data_set);
  [[nodiscard]] asio::awaitable<result<std::vector<result<void>>>> set_data_set_values(
      model::object_reference data_set, std::vector<mms::data> values);

  // --- reporting (7-2 §17.2)

  // `rcb` is "LD/LN.name[BR]" or "LD/LN.name[RP]".
  [[nodiscard]] asio::awaitable<result<rcb_values>> get_rcb_values(model::object_reference rcb);
  // Stops at the first failing attribute.
  [[nodiscard]] asio::awaitable<result<void>> set_rcb_values(model::object_reference rcb,
                                                             rcb_settings settings);
  // Reserves (URCB) and configures the RCB, reads it back, caches its data set directory (to name
  // the report entries), registers it for recovery and sets RptEna; then GI if requested.
  // Returns the values read back before enabling.
  [[nodiscard]] asio::awaitable<result<rcb_values>> enable_reporting(model::object_reference rcb,
                                                                     report_settings settings = {});
  // RptEna = false (and Resv = false for a URCB this client reserved); forgets the RCB.
  [[nodiscard]] asio::awaitable<result<void>> disable_reporting(model::object_reference rcb);
  [[nodiscard]] asio::awaitable<result<void>> trigger_gi(model::object_reference rcb);
  // --- control (7-2 §20, 8-1 §20; see client/control.hpp)

  // A handle on the controllable data object `object` ("LD/LN.DO" or an element of an array of
  // data objects "LD/LN.DO(i)", an FC is ignored): reads
  // CF.ctlModel, CF.sboTimeout and the CO structure as `config` says. Fails with the read error
  // of ctlModel (e.g. errc::object_not_found), or openiec61850::errc::invalid_state for a
  // reference that is not a data object.
  [[nodiscard]] asio::awaitable<result<control>> get_control(model::object_reference object,
                                                             control_config config = {});
  // One-shot control: get_control(object), then, by ctlModel, operate (direct), select + operate
  // (sbo-with-normal-security) or select_with_value + operate (sbo-with-enhanced-security,
  // which also waits for the CommandTermination). Errors as for control.
  [[nodiscard]] asio::awaitable<result<void>> operate(model::object_reference object,
                                                      mms::data value,
                                                      control_options options = {});


  // --- setting groups (7-2 §16, 8-1 §16), on the SGCB "ld/LLN0.SGCB[SP]"

  // GetSGCBValues.
  [[nodiscard]] asio::awaitable<result<sgcb_values>> get_sgcb_values(std::string ld);
  // SelectActiveSG: Write ActSG.
  [[nodiscard]] asio::awaitable<result<void>> select_active_sg(std::string ld, std::uint8_t sg);
  // SelectEditSG: Write EditSG (0 releases the edit buffer).
  [[nodiscard]] asio::awaitable<result<void>> select_edit_sg(std::string ld, std::uint8_t sg);
  // SetEditSGValue: Write of an FC SE reference (openiec61850::errc::invalid_state otherwise).
  [[nodiscard]] asio::awaitable<result<void>> set_edit_sg_value(model::object_reference ref,
                                                                mms::data value);
  // ConfirmEditSGValues: Write CnfEdit = true.
  [[nodiscard]] asio::awaitable<result<void>> confirm_edit_sg_values(std::string ld);
  // GetEditSGValue: Read of an FC SE or SG reference (invalid_state otherwise).
  [[nodiscard]] asio::awaitable<result<mms::data>> get_edit_sg_value(model::object_reference ref);

  // --- logs (7-2 §17.3, 8-1 §17.3). `lcb` is "LD/LN.name[LG]"; `log` is "LD/LN.LogName" (the
  // MMS journal "LN$LogName" of domain LD).

  [[nodiscard]] asio::awaitable<result<lcb_values>> get_lcb_values(model::object_reference lcb);
  // Stops at the first failing attribute.
  [[nodiscard]] asio::awaitable<result<void>> set_lcb_values(model::object_reference lcb,
                                                             lcb_settings settings);
  // QueryLogByTime: the entries from `start` to `stop` (unset: open ended), following
  // moreFollows with entryToStartAfter.
  [[nodiscard]] asio::awaitable<result<std::vector<log_entry>>> query_log_by_time(
      model::object_reference log, std::optional<model::entry_time> start,
      std::optional<model::entry_time> stop);
  // QueryLogAfter: the entries after the one identified by `entry` / `time` (the time is used
  // when the server no longer has the entry).
  [[nodiscard]] asio::awaitable<result<std::vector<log_entry>>> query_log_after(
      model::object_reference log, model::entry_time time, model::entry_id entry);
  // GetLogStatus (ReportJournalStatus): the number of entries in the log.
  [[nodiscard]] asio::awaitable<result<std::uint32_t>> get_log_status(model::object_reference log);

  // --- files (7-2 §23, 8-1 §23). Names are '/'-separated paths sent as one GraphicString.

  // GetServerDirectory(FILE) / FileDirectory, following moreFollows; `path` empty: everything.
  [[nodiscard]] asio::awaitable<result<std::vector<file_entry>>> get_file_directory(
      std::string path = {});
  // GetFile: FileOpen, FileRead until moreFollows is false, FileClose.
  [[nodiscard]] asio::awaitable<result<byte_buffer>> get_file(std::string name);
  // Streaming GetFile: each chunk is handed to `on_chunk` (on the client strand; it must not
  // block nor throw) as it arrives. Returns the number of octets read.
  [[nodiscard]] asio::awaitable<result<std::uint64_t>> get_file(
      std::string name, std::function<void(byte_buffer)> on_chunk);
  // SetFile: ObtainFile for `name` on the server, which reads the file back from this client
  // (FileOpen, FileRead, FileClose) before it answers. Only this file is offered, and only
  // for the duration of the call; any other name reads as file-non-existent. Bounded by
  // client_options::file_transfer_timeout. A refusal is a file error whose serviceSpecificInfo
  // (error_details) is one of mms::obtain_file_error. Concurrent calls need different source names
  // (openiec61850::errc::invalid_state otherwise).
  [[nodiscard]] asio::awaitable<result<void>> set_file(std::string name, byte_buffer content);
  [[nodiscard]] asio::awaitable<result<void>> set_file(std::string name, file_source source);
  [[nodiscard]] asio::awaitable<result<void>> delete_file(std::string name);
  [[nodiscard]] asio::awaitable<result<void>> rename_file(std::string from, std::string to);

  // --- GOOSE control blocks (7-2 §18.2, 8-1 §18.1). `gocb` is "LD/LN.name[GO]".

  [[nodiscard]] asio::awaitable<result<gocb_values>> get_gocb_values(model::object_reference gocb);
  // Stops at the first failing attribute.
  [[nodiscard]] asio::awaitable<result<void>> set_gocb_values(model::object_reference gocb,
                                                              gocb_settings settings);

  // --- the services with error details (client/error_details.hpp)

  // Each behaves exactly like the overload without `details` and also fills it: the
  // ServiceError (class, code, additionalCode/Description, modifierPosition) or Reject of the
  // request that failed, and the LastApplError of a refused control. `details` must stay alive
  // until the operation completes.
  [[nodiscard]] asio::awaitable<result<std::vector<std::string>>> get_server_directory(error_details& details);
  [[nodiscard]] asio::awaitable<result<std::vector<std::string>>> get_logical_device_directory(std::string ld, error_details& details);
  [[nodiscard]] asio::awaitable<result<logical_node_directory>> get_logical_node_directory(model::object_reference ln, error_details& details);
  [[nodiscard]] asio::awaitable<result<std::vector<data_directory_entry>>> get_data_directory(model::object_reference ref, error_details& details);
  [[nodiscard]] asio::awaitable<result<data_definition>> get_data_definition(model::object_reference ref, error_details& details);
  [[nodiscard]] asio::awaitable<result<std::vector<std::string>>> get_name_list(mms::object_class cls, std::string domain, error_details& details);
  [[nodiscard]] asio::awaitable<result<mms::data>> read(model::object_reference ref, error_details& details);
  [[nodiscard]] asio::awaitable<result<std::vector<result<mms::data>>>> read_many(std::vector<model::object_reference> refs, error_details& details);
  [[nodiscard]] asio::awaitable<result<void>> write(model::object_reference ref, mms::data value, error_details& details);
  [[nodiscard]] asio::awaitable<result<std::vector<result<void>>>> write_many(std::vector<write_item> items, error_details& details);
  [[nodiscard]] asio::awaitable<result<data_set_directory>> get_data_set_directory(model::object_reference data_set, error_details& details);
  [[nodiscard]] asio::awaitable<result<void>> create_data_set(model::object_reference data_set, std::vector<model::object_reference> members, error_details& details);
  [[nodiscard]] asio::awaitable<result<void>> delete_data_set(model::object_reference data_set, error_details& details);
  [[nodiscard]] asio::awaitable<result<std::vector<result<mms::data>>>> get_data_set_values(model::object_reference data_set, error_details& details);
  [[nodiscard]] asio::awaitable<result<std::vector<result<void>>>> set_data_set_values(model::object_reference data_set, std::vector<mms::data> values, error_details& details);
  [[nodiscard]] asio::awaitable<result<rcb_values>> get_rcb_values(model::object_reference rcb, error_details& details);
  [[nodiscard]] asio::awaitable<result<void>> set_rcb_values(model::object_reference rcb, rcb_settings settings, error_details& details);
  [[nodiscard]] asio::awaitable<result<rcb_values>> enable_reporting(model::object_reference rcb, report_settings settings, error_details& details);
  [[nodiscard]] asio::awaitable<result<void>> disable_reporting(model::object_reference rcb, error_details& details);
  [[nodiscard]] asio::awaitable<result<void>> trigger_gi(model::object_reference rcb, error_details& details);
  [[nodiscard]] asio::awaitable<result<control>> get_control(model::object_reference object, control_config config, error_details& details);
  [[nodiscard]] asio::awaitable<result<void>> operate(model::object_reference object, mms::data value, control_options options, error_details& details);
  [[nodiscard]] asio::awaitable<result<sgcb_values>> get_sgcb_values(std::string ld, error_details& details);
  [[nodiscard]] asio::awaitable<result<void>> select_active_sg(std::string ld, std::uint8_t sg, error_details& details);
  [[nodiscard]] asio::awaitable<result<void>> select_edit_sg(std::string ld, std::uint8_t sg, error_details& details);
  [[nodiscard]] asio::awaitable<result<void>> set_edit_sg_value(model::object_reference ref, mms::data value, error_details& details);
  [[nodiscard]] asio::awaitable<result<void>> confirm_edit_sg_values(std::string ld, error_details& details);
  [[nodiscard]] asio::awaitable<result<mms::data>> get_edit_sg_value(model::object_reference ref, error_details& details);
  [[nodiscard]] asio::awaitable<result<lcb_values>> get_lcb_values(model::object_reference lcb, error_details& details);
  [[nodiscard]] asio::awaitable<result<void>> set_lcb_values(model::object_reference lcb, lcb_settings settings, error_details& details);
  [[nodiscard]] asio::awaitable<result<std::vector<log_entry>>> query_log_by_time(model::object_reference log, std::optional<model::entry_time> start, std::optional<model::entry_time> stop, error_details& details);
  [[nodiscard]] asio::awaitable<result<std::vector<log_entry>>> query_log_after(model::object_reference log, model::entry_time time, model::entry_id entry, error_details& details);
  [[nodiscard]] asio::awaitable<result<std::uint32_t>> get_log_status(model::object_reference log, error_details& details);
  [[nodiscard]] asio::awaitable<result<std::vector<file_entry>>> get_file_directory(std::string path, error_details& details);
  [[nodiscard]] asio::awaitable<result<byte_buffer>> get_file(std::string name, error_details& details);
  [[nodiscard]] asio::awaitable<result<std::uint64_t>> get_file(std::string name, std::function<void(byte_buffer)> on_chunk, error_details& details);
  [[nodiscard]] asio::awaitable<result<void>> set_file(std::string name, byte_buffer content, error_details& details);
  [[nodiscard]] asio::awaitable<result<void>> set_file(std::string name, file_source source, error_details& details);
  [[nodiscard]] asio::awaitable<result<void>> delete_file(std::string name, error_details& details);
  [[nodiscard]] asio::awaitable<result<void>> rename_file(std::string from, std::string to, error_details& details);
  [[nodiscard]] asio::awaitable<result<gocb_values>> get_gocb_values(model::object_reference gocb, error_details& details);
  [[nodiscard]] asio::awaitable<result<void>> set_gocb_values(model::object_reference gocb, gocb_settings settings, error_details& details);

  // The EntryID of the last report received for a BRCB enabled with enable_reporting().
  [[nodiscard]] std::optional<model::entry_id> last_entry_id(
      const model::object_reference& rcb) const;

  // Next report. One consumer at a time (openiec61850::errc::invalid_state otherwise). Reports
  // keep flowing across recoveries; once the client is closed the queued reports are delivered,
  // then the closing error.
  [[nodiscard]] asio::awaitable<result<report>> next_report();
  // Alternative to next_report(): every report (including those queued) is handed to `handler`
  // on the client's strand; it must not throw nor block. An empty function restores the queue.
  void set_report_handler(std::function<void(report)> handler);
  // Reports dropped by the queue overflow policy or because they could not be parsed.
  [[nodiscard]] std::uint64_t reports_dropped() const noexcept;

  // Next connection event (same rules as next_report()).
  [[nodiscard]] asio::awaitable<result<connection_event>> next_event();
  void set_event_handler(std::function<void(connection_event)> handler);

 private:
  explicit client(std::shared_ptr<detail::client_state> state) noexcept;

  std::shared_ptr<detail::client_state> state_;
};

}  // namespace openiec61850::client
