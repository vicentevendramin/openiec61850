#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
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
#include "openiec61850/server/model.hpp"

// The IEC 61850 ACSI Servidor over MMS (IEC 61850-7-2 services mapped per IEC 61850-8-1).
//
// Services: Identify; GetNameList (domains, named variables, named variable lists, with
// continuation); Read / Write of any variable (an LN, an FC of an LN, a DO, a DA or an RCB, array
// elements through AlternateAccess); GetVariableAccessAttributes; data sets (Define / Delete /
// GetNamedVariableListAttributes, Read / Write of a list, association-specific "@" lists);
// reporting (BRCB and URCB, 7-2 §17.2 / 8-1 §17.2); control with direct-normal and sbo-normal
// security (7-2 §20 / 8-1 §20) through an application handler.
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

enum class control_action : std::uint8_t { select, operate, cancel };

// A control service on a controllable DO (7-2 §20): Select (read of SBO), Operate (write of Oper),
// Cancel (write of Cancel).
struct control_request {
  std::uint64_t association = 0;
  control_action action = control_action::operate;
  model::object_reference object;  // the DO, without FC, e.g. "LD/CSWI1.Pos"
  model::ctl_model ctl_model = model::ctl_model::direct_with_normal_security;
  // Fields of the Oper / Cancel structure (unset for a Select).
  mms::data ctl_val;
  std::optional<model::orcat> or_cat;
  byte_buffer or_ident;
  std::uint64_t ctl_num = 0;
  std::optional<model::timestamp> t;
  bool test = false;
  model::check_conditions check;
};

struct control_result {
  bool accepted = true;
  add_cause cause = add_cause::unknown;

  [[nodiscard]] static control_result ok() noexcept { return {}; }
  [[nodiscard]] static control_result refused(add_cause c) noexcept { return {false, c}; }
};

struct server_options {
  // Transport, ISO selectors, AP title, MMS limits (local_detail_called, max serv outstanding,
  // nesting level, services) and decode limits of each association. Its `authorize` hook is the
  // authentication hook: it is called (on the association's strand) for each association within
  // the max_associations limit and may refuse it, e.g. on peer_request().password.
  association::server_options association;
  // Concurrent associations; further ones are refused. Zero: unlimited.
  std::size_t max_associations = 16;
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
  // sbo-normal selection timeout when the DO has no CF sboTimeout.
  std::chrono::milliseconds default_sbo_timeout{30000};
  // Called before a client's write to SP, SV, CF, DC, BL, SG or SE is applied; returning a
  // DataAccessError refuses it. Unset: such writes are accepted.
  std::function<std::optional<mms::data_access_error>(const write_event&)> on_write;
  // Control services. Unset: every Select / Operate / Cancel is refused with not_supported.
  std::function<control_result(const control_request&)> on_control;
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
  [[nodiscard]] result<void> update(const model::object_reference& ref, mms::data value,
                                    std::optional<model::quality> quality = std::nullopt,
                                    std::optional<model::timestamp> timestamp = std::nullopt);
  // All changes are applied in one step: the reports they trigger are generated together.
  [[nodiscard]] result<void> update(std::vector<data_update> batch);

  // The current value of a functionally constrained reference (or of an LN without FC).
  [[nodiscard]] asio::awaitable<result<mms::data>> read(model::object_reference ref) const;

  // Any thread.
  [[nodiscard]] std::size_t association_count() const noexcept;
  [[nodiscard]] const asio::ip::tcp::endpoint& local_endpoint() const noexcept;
  // Immutable: the model structure and the initial values.
  [[nodiscard]] const data_model& model() const noexcept;
  [[nodiscard]] executor_type get_executor() const noexcept;

 private:
  explicit server(std::shared_ptr<detail::server_state> state) noexcept;

  std::shared_ptr<detail::server_state> state_;
};

}  // namespace openiec61850::server
