#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>

#include <asio/awaitable.hpp>

#include "openiec61850/core/bytes.hpp"
#include "openiec61850/core/result.hpp"
#include "openiec61850/mms/data.hpp"
#include "openiec61850/mms/pdu.hpp"
#include "openiec61850/mms/type_description.hpp"
#include "openiec61850/model/enums.hpp"
#include "openiec61850/model/object_reference.hpp"
#include "openiec61850/model/timestamp.hpp"

// Control services (IEC 61850-7-2 §20) mapped onto MMS (IEC 61850-8-1 §20).
//
// An element "LD/LN.DO(i)" of an array of data objects is controlled the same way: its variables
// are "LN$CO$DO" with the AlternateAccess "(i) Oper", and its CntrlObj reads "LD/LN$CO$DO(i)$Oper".
//
// A controllable data object (SPC, DPC, INC, BSC, APC...) "LD/LN.DO" exposes, under FC CO:
//
//   LN$CO$DO$SBO      VisibleString129   sbo-with-normal-security: Select = Read; the server
//                                        returns the object reference when selected, "" otherwise
//   LN$CO$DO$SBOw     structure          sbo-with-enhanced-security: SelectWithValue = Write
//   LN$CO$DO$Oper     structure          Operate (and TimeActivatedOperate) = Write
//   LN$CO$DO$Cancel   structure          Cancel = Write
//
// and, under FC CF, ctlModel (ENUMERATED), sboTimeout (INT32U, ms) and sboClass.
//
// SBOw and Oper are { ctlVal, [operTm], origin{orCat, orIdent}, ctlNum, T, Test, Check } and
// Cancel is { ctlVal, [operTm], origin, ctlNum, T, Test } (no Check):
//
//   ctlVal   the CDC's control value type (BOOLEAN for SPC/DPC, INT32 for INC, Tcmd bit-string
//            for BSC, AnalogueValue structure for APC...)
//   operTm   TimeStamp; present only in objects that support time-activated control
//   origin   orCat ENUMERATED (model::orcat), orIdent OCTET STRING64
//   ctlNum   INT8U; the client increments it per control sequence, and SBOw / Oper / Cancel of
//            one sequence carry the same number
//   T        TimeStamp of the request (UtcTime)
//   Test     BOOLEAN
//   Check    PACKED LIST BIT STRING(2): synchrocheck, interlock-check (model::check_conditions)
//
// Edition differences (from the text of the editions as we understand it; not every vendor
// follows it, which is why the client reads the CO structure from the server by default and
// fills whatever components it finds, by name):
//   - Ed.1 and Ed.2 share the layout above. operTm is optional in both and present only when
//     time-activated control is supported.
//   - The AddCause enumeration of LastApplError was extended in Ed.2 (Ed.1 servers only send the
//     lower values); Ed.2.1 may define further values, which are kept as raw numbers.
//   - Some Ed.1 devices omit Check from Oper; it is only sent when the server's structure has it
//     (or, when the structure was not read, always for SBOw/Oper as in Ed.2).
//
// Errors of a control service (7-2 §20.5, 8-1 §20.7):
//   - a refused request is a negative Write response (or SBO = ""), preceded by an
//     InformationReport on the vmd-specific variable "LastApplError":
//         { CntrlObj VisibleString129 ("LD/LN$CO$DO$Oper"), Error ENUMERATED, Origin, ctlNum INT8U,
//           AddCause ENUMERATED }
//   - with enhanced security the server ends every accepted Operate with a CommandTermination,
//     an InformationReport on the domain variable "LN$CO$DO$Oper" carrying the Oper value
//     (positive), or on "LastApplError" followed by "LN$CO$DO$Oper" (negative).
// The client routes both to the control machinery (they are no longer discarded). A failure
// with a LastApplError for the object yields an error code of the add_cause category (compare it
// with an add_cause value: `r.error() == add_cause::blocked_by_interlocking`), and the whole
// LastApplError is available from control::last_error(). Without a LastApplError the request's
// own error is returned (client::errc::access_denied for object-access-denied, etc.).

namespace openiec61850::client {

namespace detail {
struct client_state;
struct control_state;
}  // namespace detail

struct error_details;  // client/error_details.hpp

// AddCause (IEC 61850-7-2 Ed.2 §20.5.2.9 / Table 103, as recalled; values beyond those listed
// here are kept as raw numbers in the enum). Ed.1 defines the subset up to
// abortion_by_communication_loss; Ed.2 added the rest. The exact numbering of the higher values
// (24..27) varies between editions/amendments and should be checked against the standard text.
enum class add_cause : std::int16_t {
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

// LastApplError.Error (IEC 61850-8-1 §20.7): ENUMERATED.
enum class control_error : std::uint8_t {
  no_error = 0,
  unknown = 1,
  timeout_test_not_ok = 2,
  operator_test_not_ok = 3,
};

// Spec names ("blocked-by-interlocking", "timeout-test-not-ok"...); "unknown-add-cause" for
// values not listed above.
[[nodiscard]] std::string_view to_string(add_cause v) noexcept;
[[nodiscard]] std::string_view to_string(control_error v) noexcept;

// Error category of add_cause. The error_code value is the AddCause plus one, so that
// add_cause::unknown is not "success"; compare codes with the enum instead of using value().
[[nodiscard]] const std::error_category& add_cause_category() noexcept;
[[nodiscard]] std::error_code make_error_code(add_cause c) noexcept;
// The AddCause carried by an error code of add_cause_category(); nullopt for other codes.
[[nodiscard]] std::optional<add_cause> to_add_cause(const std::error_code& ec) noexcept;

// Originator (7-3): who issues the command.
struct originator {
  model::orcat category = model::orcat::remote_control;
  byte_buffer identifier;  // orIdent, at most 64 octets

  friend bool operator==(const originator&, const originator&) = default;
};

// A LastApplError InformationReport.
struct last_appl_error {
  std::string control_object;  // CntrlObj as sent (usually "LD/LN$CO$DO$Oper")
  control_error error = control_error::unknown;
  originator origin;
  std::uint8_t ctl_num = 0;
  add_cause cause = add_cause::unknown;

  friend bool operator==(const last_appl_error&, const last_appl_error&) = default;
};

// A control-related InformationReport (see the header comment).
struct control_message {
  enum class kind : std::uint8_t {
    last_appl_error,      // a LastApplError alone (a refused request)
    command_termination,  // positive (no `error`) or negative (`error` set)
  };

  kind type = kind::last_appl_error;
  // MMS reference of the variable: the Oper of a termination ("LD/LN$CO$DO$Oper", or
  // "LD/LN$CO$DO(i)$Oper" for an element of an array of data objects), else CntrlObj.
  std::string control_object;
  std::optional<last_appl_error> error;
  std::optional<mms::data> oper;  // termination: the Oper value, when sent and readable

  [[nodiscard]] bool positive() const noexcept {
    return type == kind::command_termination && !error;
  }
};

// True for an InformationReport on "LastApplError" or on a "...$CO$...$Oper" variable (or
// "...$CO$DO" with the AlternateAccess "(i) Oper" of an element of an array of data objects).
[[nodiscard]] bool is_control_message(const mms::information_report& ir);
// Errors: errc::unsupported unless is_control_message(); errc::protocol_violation for a
// malformed LastApplError or a variable/result count mismatch.
[[nodiscard]] result<control_message> parse_control_message(const mms::information_report& ir);
// Parses a LastApplError value (errc::protocol_violation when malformed).
[[nodiscard]] result<last_appl_error> parse_last_appl_error(const mms::data& value);

// Per-request options of the control services.
struct control_options {
  originator origin;
  bool test = false;                // Test
  model::check_conditions check;    // Check (SBOw / Oper only)
  // operTm (time-activated operate). Fails with openiec61850::errc::unsupported when the
  // server's structure is known to lack operTm.
  std::optional<model::timestamp> oper_time;
  // ctlNum to send instead of the sequence's number (see control::ctl_num()).
  std::optional<std::uint8_t> ctl_num;
  // Enhanced security: how long operate() waits for the CommandTermination after the server
  // accepted the Oper (client::errc::termination_timeout).
  std::chrono::milliseconds termination_timeout{std::chrono::seconds{10}};
};

// What client::get_control() reads from the server.
struct control_config {
  // Use this ctlModel instead of reading CF.ctlModel.
  std::optional<model::ctl_model> ctl_model;
  // Read CF.sboTimeout (missing: not an error).
  bool read_sbo_timeout = true;
  // Read the CO structure (GetVariableAccessAttributes "LN$CO$DO") to learn the ctlVal type and
  // which of SBO/SBOw/Oper/Cancel/operTm/Check exist. Without it (or when it fails) the Ed.2
  // layout is assumed, operTm is sent only when requested, and ctlVal is sent as given.
  bool read_structure = true;
};

// A handle on one controllable data object, obtained from client::get_control(). Copies share
// the same state (ctlNum sequence, last error). Operations run on the client's strand and may be
// awaited from any executor; only one operation per object and client may be in progress at a
// time (openiec61850::errc::invalid_state otherwise).
//
// Sequences and ctlNum: select(), select_with_value() and an operate() or cancel() outside a
// selection start a new sequence with the next ctlNum (0, 1, ... 255, 0...); operate() and
// cancel() after a selection reuse its ctlNum (and cancel() its ctlVal). A successful operate()
// or cancel() ends the sequence; a refused one keeps it, so it can be retried.
//
// Errors besides those of read/write: client::errc::control_model_mismatch when the service does
// not exist in the object's ctlModel (select() on a direct or enhanced object, any service on a
// status-only one), client::errc::select_failed when the SBO read returns "", an add_cause code
// when the server sent a LastApplError or a negative CommandTermination,
// client::errc::termination_timeout, client::errc::type_mismatch when ctlVal does not have the
// server's type.
class control {
 public:
  // An empty handle: every operation fails with openiec61850::errc::invalid_state.
  control() = default;

  // The data object, without FC ("LD/LN.DO").
  [[nodiscard]] const model::object_reference& reference() const noexcept;
  [[nodiscard]] model::ctl_model ctl_model() const noexcept;
  // CF.sboTimeout when read and present.
  [[nodiscard]] std::optional<std::chrono::milliseconds> sbo_timeout() const noexcept;
  // The CO structure "LN$CO$DO" when read; nullopt otherwise.
  [[nodiscard]] const std::optional<mms::type_description>& structure() const noexcept;
  // The MMS type of ctlVal when the structure was read.
  [[nodiscard]] std::optional<mms::data_type> ctl_val_type() const noexcept;
  // Whether Oper has operTm (time-activated control); nullopt when the structure is unknown.
  [[nodiscard]] std::optional<bool> has_oper_time() const noexcept;
  // ctlNum of the current (or last) sequence. Any thread.
  [[nodiscard]] std::uint8_t ctl_num() const noexcept;
  // True between a successful select()/select_with_value() and the end of the sequence (as seen
  // by the client: the server may have deselected on sboTimeout). Any thread.
  [[nodiscard]] bool selected() const noexcept;
  // The last LastApplError received for this object (refusal or negative termination). Any
  // thread.
  [[nodiscard]] std::optional<last_appl_error> last_error() const;

  // Select (sbo-with-normal-security): Read of SBO.
  [[nodiscard]] asio::awaitable<result<void>> select(control_options options = {});
  // SelectWithValue (sbo-with-enhanced-security): Write of SBOw.
  [[nodiscard]] asio::awaitable<result<void>> select_with_value(mms::data value,
                                                                control_options options = {});
  // Operate / TimeActivatedOperate: Write of Oper. With enhanced security it completes when the
  // CommandTermination arrives.
  [[nodiscard]] asio::awaitable<result<void>> operate(mms::data value,
                                                      control_options options = {});
  // Cancel: Write of Cancel, with the ctlVal of the current sequence (or a default value of the
  // ctlVal type; openiec61850::errc::invalid_state when neither is known).
  [[nodiscard]] asio::awaitable<result<void>> cancel(control_options options = {});

  // The same services, also filling `details` (client/error_details.hpp): the ServiceError or
  // Reject of a refused request and the LastApplError of a refusal / negative termination.
  [[nodiscard]] asio::awaitable<result<void>> select(control_options options,
                                                     error_details& details);
  [[nodiscard]] asio::awaitable<result<void>> select_with_value(mms::data value,
                                                                control_options options,
                                                                error_details& details);
  [[nodiscard]] asio::awaitable<result<void>> operate(mms::data value, control_options options,
                                                      error_details& details);
  [[nodiscard]] asio::awaitable<result<void>> cancel(control_options options,
                                                     error_details& details);

 private:
  friend struct detail::control_state;
  explicit control(std::shared_ptr<detail::control_state> state) noexcept;

  std::shared_ptr<detail::control_state> state_;
};

}  // namespace openiec61850::client

template <>
struct std::is_error_code_enum<openiec61850::client::add_cause> : std::true_type {};
