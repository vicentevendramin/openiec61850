#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <asio/any_io_executor.hpp>
#include <asio/awaitable.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/strand.hpp>

// basic_type.hpp first (see the note in model/quality.hpp about -Wshadow).
#include "openiec61850/model/basic_type.hpp"
#include "openiec61850/association/server_association.hpp"
#include "openiec61850/core/bytes.hpp"
#include "openiec61850/core/result.hpp"
#include "openiec61850/mms/data.hpp"
#include "openiec61850/mms/pdu.hpp"
#include "openiec61850/model/enums.hpp"
#include "openiec61850/model/object_reference.hpp"
#include "openiec61850/model/quality.hpp"
#include "openiec61850/model/timestamp.hpp"
#include "openiec61850/server/error.hpp"
#include "openiec61850/server/files.hpp"
#include "openiec61850/server/model.hpp"

// The IEC 61850 ACSI Servidor over MMS (IEC 61850-7-2 services mapped per IEC 61850-8-1).
//
// Services: Identify; GetNameList (domains, named variables, named variable lists, with
// continuation); Read / Write of any variable (an LN, an FC of an LN, a DO, a DA or an RCB, array
// elements through AlternateAccess); GetVariableAccessAttributes; data sets (Define / Delete /
// GetNamedVariableListAttributes, Read / Write of a list, association-specific "@" lists);
// reporting (BRCB and URCB, 7-2 §17.2 / 8-1 §17.2); control with the four control models
// (direct / sbo, normal / enhanced security, 7-2 §20 / 8-1 §20) through an application handler,
// with asynchronous completion of enhanced-security operations (CommandTermination); setting
// groups (SGCB: SelectActiveSG, SelectEditSG, SetEditSGValue, ConfirmEditSGValues,
// GetEditSGValue, GetSGCBValues, 7-2 §16 / 8-1 §16); logs (LCBs and bounded in-memory logs fed by
// the reporting triggers, read with ReadJournal, 7-2 §17.3 / 8-1 §17.3); file transfer (MMS file
// services over a file_store, including SetFile, 7-2 §23 / 8-1 §23); GOOSE control blocks as MMS variables
// (7-2 §18 / 8-1 §18, publishing is done elsewhere).
//
// Threading (ADR 0004): all the server state lives on one strand on the given executor
// (typically a transport::io_runtime). update() and stop() may be called from any thread; the
// application handlers run on the strand and must neither block nor throw.

namespace openiec61850::server {

struct identity {
  std::string vendor = "openiec61850";
  std::string model = "openiec61850";
  std::string revision = "0.1";
};

// A Write by a client to a writable FC (SP, SV, CF, DC, BL; also SG/SE, not otherwise modelled).
struct write_event {
  std::uint64_t association = 0;
  model::object_reference reference;  // FC-constrained, as written (may name a structure)
  mms::data value;
};

// An ObtainFile (SetFile, 7-2 §23) by a client, before the server reads the file.
struct obtain_file_event {
  std::uint64_t association = 0;
  std::string source;       // the file's name at the client, as sent
  std::string destination;  // the normalised name in the file store; free when the hook runs
};

// AddCause (IEC 61850-7-2 Ed.2 §20.5.2.9).
enum class add_cause : std::uint8_t {
  unknown = 0,
  not_supported = 1,
  blocked_by_switching_hierarchy = 2,
  select_failed = 3,
  invalid_position = 4,
  position_reached = 5,
  parameter_change_in_execution = 6,
  step_limit = 7,
  blocked_by_mode = 8,
  blocked_by_process = 9,
  blocked_by_interlocking = 10,
  blocked_by_synchrocheck = 11,
  command_already_in_execution = 12,
  blocked_by_health = 13,
  one_of_n_control = 14,
  abortion_by_cancel = 15,
  time_limit_over = 16,
  abortion_by_trip = 17,
  object_not_selected = 18,
  object_already_selected = 19,
  no_access_authority = 20,
  ended_with_overshoot = 21,
  abortion_due_to_deviation = 22,
  abortion_by_communication_loss = 23,
  blocked_by_command = 24,
  none = 25,
  inconsistent_parameters = 26,
  locked_by_other_client = 27,
};

// Select: a Read of SBO (sbo-with-normal-security) or a Write of SBOw (SelectWithValue,
// sbo-with-enhanced-security; the request then carries the SBOw fields). Operate: a Write of Oper
// (with operTm: TimeActivatedOperate, reported when the activation time is reached). Cancel: a
// Write of Cancel.
enum class control_action : std::uint8_t { select, operate, cancel };

struct control_result;

// A setting group service invoked by a client (7-2 §16.3), before it is applied.
enum class setting_group_action : std::uint8_t { select_active, select_edit, confirm_edit };

struct setting_group_event {
  std::uint64_t association = 0;
  std::string logical_device;
  setting_group_action action = setting_group_action::select_active;
  std::uint8_t group = 0;  // the group selected (0 for SelectEditSG releasing the edit buffer)
};

// The current attributes of a GOOSE control block.
struct goose_control_state {
  model::object_reference reference;  // "LD/LN.name[GO]"
  bool go_ena = false;
  std::string go_id;
  std::string dat_set;  // MMS form "LD/LN$DS"; empty: none
  std::vector<model::object_reference> members;  // of the data set (FCD / FCDA)
  std::uint32_t conf_rev = 0;
  bool nds_com = false;
  std::array<std::uint8_t, 6> dst_mac{};
  std::uint8_t vlan_priority = 0;
  std::uint16_t vlan_id = 0;
  std::uint16_t app_id = 0;
  std::uint32_t min_time = 0;
  std::uint32_t max_time = 0;
  bool fixed_offs = false;
};

// A GoCB changed through a client's write (GoEna, GoID or DatSet).
struct goose_control_event {
  std::uint64_t association = 0;
  goose_control_state state;
};

namespace detail {
struct completion_state;
}

// Completes an Operate the application accepted as pending (control_result::pending()), typically
// once the physical action has ended. Copyable; any thread; only the first complete() counts, and
// it does nothing once the operation was abandoned (server stopped, operate_timeout elapsed).
// With enhanced security, complete(ok()) sends the positive CommandTermination and
// complete(refused(cause)) the negative one (LastApplError with the AddCause, then
// CommandTermination-), unless the client's association has closed meanwhile (the operation
// still ends). With normal security there is no termination: complete(ok()) only ends the
// execution (until then further Operates on the object are refused with
// command-already-in-execution) and complete(refused(cause)) sends a LastApplError report.
class control_completion {
 public:
  control_completion() = default;

  // False for a default-constructed handle (requests other than Operate).
  [[nodiscard]] bool valid() const noexcept { return state_ != nullptr; }
  // Returns false when the operation was already completed or abandoned, or the handle is empty.
  bool complete(const control_result& result) const;

 private:
  friend struct detail::completion_state;
  explicit control_completion(std::shared_ptr<detail::completion_state> s) noexcept
      : state_(std::move(s)) {}
  std::shared_ptr<detail::completion_state> state_;
};

// A control service on a controllable DO (7-2 §20).
struct control_request {
  std::uint64_t association = 0;
  control_action action = control_action::operate;
  model::object_reference object;  // the DO, without FC, e.g. "LD/CSWI1.Pos"
  model::ctl_model ctl_model = model::ctl_model::direct_with_normal_security;
  // Fields of the SBOw / Oper / Cancel structure (unset for a Select by Read of SBO).
  mms::data ctl_val;
  std::optional<model::timestamp> oper_time;  // operTm, when present and not zero
  std::optional<model::orcat> or_cat;
  byte_buffer or_ident;
  std::uint64_t ctl_num = 0;
  std::optional<model::timestamp> t;
  bool test = false;
  model::check_conditions check;
  // Operate only: completes an operation answered with control_result::pending().
  control_completion completion;
};

struct control_result {
  enum class kind : std::uint8_t { accepted, refused, pending };

  kind outcome = kind::accepted;
  add_cause cause = add_cause::unknown;  // refused

  [[nodiscard]] bool accepted() const noexcept { return outcome != kind::refused; }

  // Accepted; for an enhanced-security Operate the operation is also complete (the positive
  // CommandTermination follows the Write response).
  [[nodiscard]] static control_result ok() noexcept { return {}; }
  // Refused: negative response preceded by a LastApplError with `c` (or, from complete(), a
  // negative CommandTermination).
  [[nodiscard]] static control_result refused(add_cause c) noexcept { return {kind::refused, c}; }
  // Operate only (treated as ok() otherwise): accepted, positive Write response, the operation
  // runs until request.completion.complete() is called.
  [[nodiscard]] static control_result pending() noexcept { return {kind::pending, add_cause::unknown}; }
};

struct server_options {
  // Transport, ISO selectors, AP title, MMS limits (local_detail_called, max serv outstanding,
  // nesting level, services) and decode limits of each association. Its `authorize` hook is the
  // authentication hook: it is called (on the association's strand) for each association within
  // the max_associations limit and may refuse it, e.g. on peer_request().password.
  //
  // transport.max_output_bytes bounds the output of each association twice: the answers and
  // reports queued by the server (charged as their bytes plus 64 each) and what the protocol
  // layers queue on their own, like the rejects of a request flood; so at most about twice the
  // limit per association. Past it, or after transport.write_stall_timeout without progress, that
  // association alone is aborted without an ABRT, which a peer not reading would not get. The
  // queues of a client that reads slowly drain, so it only suffers if it keeps being outrun.
  //
  // Reports of that association: a URCB has no buffer, so what was queued is lost, the URCB is
  // disabled and its reservation released, as for any lost association. BRCBs stop at half the
  // limit and keep their entries in their buffer (brcb_buffer_capacity, BufOvfl beyond it), so
  // they alone never trigger the limit, only the stall timeout; entries queued but not written go
  // back to the buffer and are sent again when the BRCB is enabled again. A client may see an
  // entry twice, as when it resumes from an older EntryID.
  //
  // The queue drains on the association's own strand, whole, whatever else waits on the server's,
  // so that a client that keeps reading is not outrun by update() traffic for other clients.
  association::server_options association;
  // Concurrent associations; further ones are refused. Zero: unlimited.
  std::size_t max_associations = 16;
  // Changes accepted by update() and not applied yet (the items of a batch count one by one);
  // beyond it update() fails with errc::overloaded. See update(). Zero: unlimited.
  std::size_t max_pending_updates = 8192;
  identity ident;
  // Entries kept per BRCB; on overflow the oldest is dropped and the next report sent has
  // BufOvfl = true.
  std::size_t brcb_buffer_capacity = 1024;
  // Dynamic data sets: members per data set, persistent (domain-specific) ones per server and
  // association-specific ones per association.
  std::size_t max_data_set_members = 128;
  std::size_t max_persistent_data_sets = 64;
  std::size_t max_association_data_sets = 16;
  // Identifiers per GetNameList response besides the PDU size limit. Zero: no limit.
  std::size_t max_names_per_response = 0;
  // Set the DO's `t` (same FC) to the current time when update() changes a data attribute with a
  // dchg/qchg trigger and no timestamp is given.
  bool auto_timestamp = true;
  // Selection timeout (sbo-normal and sbo-enhanced) when the DO has no CF sboTimeout (or zero).
  std::chrono::milliseconds default_sbo_timeout{30000};
  // Pending operations (control_result::pending()) not completed within this time end as refused
  // with time-limit-over. Zero: no limit.
  std::chrono::milliseconds operate_timeout{0};
  // Test flag of control requests against the behaviour of the LN (IEC 61850-7-4 Annex A): Beh of
  // the LN, else Beh or Mod of LLN0 of its LD. Beh off refuses every command except on Mod;
  // on / on-blocked refuse Test = true; test / test-blocked refuse Test = false (AddCause
  // blocked-by-mode). No check when the LN has no such status or this is false.
  bool check_test_mode = true;
  // Called before a client's write to SP, SV, CF, DC, BL, SG or SE is applied; returning a
  // DataAccessError refuses it. Unset: such writes are accepted.
  std::function<std::optional<mms::data_access_error>(const write_event&)> on_write;
  // Control services, on the strand: return ok(), refused(cause) or, for an Operate, pending()
  // and complete it later through request.completion. The server checks the control model
  // before calling it: selection by the same association (sbo), consistency of Oper / Cancel
  // with the SBOw (ctlVal, origin, ctlNum: inconsistent-parameters), one execution at a time
  // (command-already-in-execution), the Test flag (check_test_mode). Unset: every Select /
  // Operate / Cancel is refused with not_supported.
  std::function<control_result(const control_request&)> on_control;
  // Setting groups: called before SelectActiveSG, SelectEditSG and ConfirmEditSGValues are
  // applied (the server has already checked the group range and the edit reservation);
  // returning a DataAccessError refuses the write. Unset: accepted.
  std::function<std::optional<mms::data_access_error>(const setting_group_event&)> on_setting_group;
  // Entries kept per log; on overflow the oldest are dropped.
  std::size_t log_capacity = 1024;
  // GoCB attributes written by a client (after the change, on the strand).
  std::function<void(const goose_control_event&)> on_goose_control;
  // The file store behind the MMS file services; unset: the services are rejected
  // (unrecognized-service).
  std::shared_ptr<file_store> files;
  // Files open at once per association (FileOpen beyond it: resource/capability-unavailable).
  std::size_t max_open_files = 8;
  // ObtainFile lets clients create files, so it is opt-in: it needs on_obtain_file, a store with
  // file_store::writable() and a non-zero max_obtain_file_size;
  // otherwise it is rejected (unrecognized-service) and not advertised in
  // servicesSupportedCalled. The server then reads the file from the client (fileOpen, fileRead,
  // fileClose, each bounded by association.request_timeout), keeping it in memory, and hands it
  // whole to the store. One at a time per association (resource/capability-unavailable); an
  // existing destination is refused (duplicate-filename).
  //
  // Called before the file is read, on the strand; returning an error refuses it (file_errc
  // mapped as for the file store). Unset: the service is off.
  std::function<std::optional<file_errc>(const obtain_file_event&)> on_obtain_file;
  // Largest file accepted (above it: insufficient-space-in-filestore).
  std::uint64_t max_obtain_file_size = 64 * 1024 * 1024;
  // The whole transfer. Zero disables it.
  std::chrono::milliseconds obtain_file_timeout{300000};
};

// One value change by the application (see server::update()).
struct data_update {
  // FC-constrained or not ("LD/GGIO1.Ind1.stVal[ST]"); a DA, a DO or a structured DA (the value is
  // then a structure of all its components with that FC), an array element with an index.
  model::object_reference reference;
  mms::data value;
  // Written to the sibling attributes `q` and `t` of the referenced DA (or of the DO when the
  // reference names one).
  std::optional<model::quality> quality;
  std::optional<model::timestamp> timestamp;
};

namespace detail {
struct server_state;
}

class server {
 public:
  using executor_type = asio::strand<asio::any_io_executor>;

  // Listens on `endpoint` (port 0: ephemeral) and serves `model`. Errors: socket errors (e.g.
  // address in use), errc::invalid_model for an empty model.
  [[nodiscard]] static result<server> start(asio::any_io_executor ex, data_model model,
                                            const asio::ip::tcp::endpoint& endpoint,
                                            server_options options = {});

  server(server&&) noexcept = default;
  server& operator=(server&& other) noexcept;
  server(const server&) = delete;
  server& operator=(const server&) = delete;
  // Stops the server.
  ~server();

  // Closes the listener and aborts every association. Idempotent, any thread.
  void stop() noexcept;
  // Completes once stop() has run and every association has ended.
  [[nodiscard]] asio::awaitable<void> wait_stopped();

  // Application updates, from any thread. The reference and the value are checked against the
  // model at once (errc::object_not_found, errc::type_mismatch, errc::access_denied for control
  // block attributes, errc::not_running after stop()); the change is then applied on the strand,
  // in call order, and triggers the reports (dchg when the value changed, qchg when a quality
  // changed, dupd always, per the attributes' trigger options).
  //
  // Backpressure: update() never blocks and never drops a change it accepted. The strand is shared
  // with the clients of the server, so an application producing faster than the strand applies
  // would otherwise delay them for good. When options.max_pending_updates changes are pending it
  // fails with errc::overloaded instead, applying nothing (a batch is taken or refused whole, and
  // always fits an empty queue): the caller keeps the state and tries again later, or sends the
  // latest value only, e.g. pacing itself with pending_updates(). A handler on the strand gets
  // the same error, as nothing drains while it runs.
  [[nodiscard]] result<void> update(const model::object_reference& ref, mms::data value,
                                    std::optional<model::quality> quality = std::nullopt,
                                    std::optional<model::timestamp> timestamp = std::nullopt);
  // All changes are applied in one step: the reports they trigger are generated together.
  [[nodiscard]] result<void> update(std::vector<data_update> batch);

  // The current value of a functionally constrained reference (or of an LN without FC).
  [[nodiscard]] asio::awaitable<result<mms::data>> read(model::object_reference ref) const;

  // Local SelectActiveSG (e.g. from an HMI), from any thread: `ld` must have an SGCB
  // (errc::object_not_found) and 1 <= sg <= NumOfSG (openiec61850::errc::value_out_of_range).
  // Applied on the strand like update(); the changed SG values trigger reports and logs.
  [[nodiscard]] result<void> select_active_setting_group(std::string_view ld, std::uint8_t sg);
  // The values of setting group `sg` (1-based) of an FC SG reference, as stored (the active group
  // equals the SG values read by clients).
  [[nodiscard]] asio::awaitable<result<mms::data>> read_setting_group(model::object_reference ref,
                                                                      std::uint8_t sg) const;

  // The GoCB "LD/LN.name[GO]" (errc::object_not_found), or all of them.
  [[nodiscard]] asio::awaitable<result<goose_control_state>> goose_control(
      model::object_reference ref) const;
  [[nodiscard]] asio::awaitable<std::vector<goose_control_state>> goose_controls() const;

  // Any thread.
  [[nodiscard]] std::size_t association_count() const noexcept;
  // Changes accepted by update() and not applied yet.
  [[nodiscard]] std::size_t pending_updates() const noexcept;
  // Associations ended so far because the peer stopped reading (output limit or stall timeout).
  [[nodiscard]] std::uint64_t slow_peer_aborts() const noexcept;
  [[nodiscard]] const asio::ip::tcp::endpoint& local_endpoint() const noexcept;
  // Immutable: the model structure and the initial values.
  [[nodiscard]] const data_model& model() const noexcept;
  [[nodiscard]] executor_type get_executor() const noexcept;

 private:
  explicit server(std::shared_ptr<detail::server_state> state) noexcept;

  std::shared_ptr<detail::server_state> state_;
};

}  // namespace openiec61850::server
