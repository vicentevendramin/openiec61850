#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <optional>
#include <span>
#include <string_view>
#include <variant>

#include "openiec61850/ber/decode.hpp"
#include "openiec61850/ber/oid.hpp"
#include "openiec61850/core/bytes.hpp"
#include "openiec61850/core/result.hpp"
#include "openiec61850/mms/data.hpp"
#include "openiec61850/mms/list_view.hpp"
#include "openiec61850/mms/type_description.hpp"

// MMS PDU codec (ISO 9506-2), the subset used by IEC 61850-8-1 clients and servers.
//
//   MMSpdu ::= CHOICE {
//     confirmed-RequestPDU   [0]  IMPLICIT SEQUENCE { invokeID Unsigned32,
//                                   listOfModifier SEQUENCE OF Modifier OPTIONAL,
//                                   service ConfirmedServiceRequest,
//                                   service-ext [79] Request-Detail OPTIONAL },
//     confirmed-ResponsePDU  [1]  IMPLICIT SEQUENCE { invokeID Unsigned32,
//                                   service ConfirmedServiceResponse,
//                                   service-ext [79] Response-Detail OPTIONAL },
//     confirmed-ErrorPDU     [2]  IMPLICIT SEQUENCE { invokeID [0] IMPLICIT Unsigned32,
//                                   modifierPosition [1] IMPLICIT Unsigned32 OPTIONAL,
//                                   serviceError [2] IMPLICIT ServiceError },
//     unconfirmed-PDU        [3]  IMPLICIT SEQUENCE { service UnconfirmedService,
//                                   service-ext [79] Unconfirmed-Detail OPTIONAL },
//     rejectPDU              [4]  IMPLICIT RejectPDU,
//     cancel-RequestPDU      [5]  IMPLICIT Unsigned32,                 -- originalInvokeID
//     cancel-ResponsePDU     [6]  IMPLICIT Unsigned32,
//     cancel-ErrorPDU        [7]  IMPLICIT SEQUENCE { originalInvokeID [0] IMPLICIT Unsigned32,
//                                   serviceError [1] IMPLICIT ServiceError },
//     initiate-RequestPDU    [8]  IMPLICIT Initiate-RequestPDU,
//     initiate-ResponsePDU   [9]  IMPLICIT Initiate-ResponsePDU,
//     initiate-ErrorPDU      [10] IMPLICIT ServiceError,
//     conclude-RequestPDU    [11] IMPLICIT NULL,
//     conclude-ResponsePDU   [12] IMPLICIT NULL,
//     conclude-ErrorPDU      [13] IMPLICIT ServiceError }
//
// Confirmed services implemented (ConfirmedServiceRequest/-Response CHOICE tags):
//   getNameList [1] IMPLICIT, identify [2] IMPLICIT (request NULL), read [4] IMPLICIT,
//   write [5] IMPLICIT, getVariableAccessAttributes [6] (request: explicit tag around the
//   CHOICE; response IMPLICIT), defineNamedVariableList [11] IMPLICIT (response NULL),
//   getNamedVariableListAttributes [12] (request: explicit tag around ObjectName; response
//   IMPLICIT), deleteNamedVariableList [13] IMPLICIT, readJournal [65] IMPLICIT,
//   initializeJournal [67] IMPLICIT, reportJournalStatus [68] (request: explicit tag around
//   ObjectName; response IMPLICIT), obtainFile [46], fileOpen [72], fileRead [73], fileClose [74],
//   fileRename [75], fileDelete [76], fileDirectory [77] (all IMPLICIT).
// Any other service (e.g. takeControl) decodes to `other_service` with its raw encoding,
// so a server can answer with a reject (unrecognized-service) and new services can be added
// without changing the PDU layout. The listOfModifier and service-ext fields are carried opaque.
//
//   ObjectName ::= CHOICE { vmd-specific [0] IMPLICIT Identifier,
//     domain-specific [1] IMPLICIT SEQUENCE { domainID Identifier, itemID Identifier },
//     aa-specific [2] IMPLICIT Identifier }
//
//   VariableAccessSpecification ::= CHOICE {
//     listOfVariable   [0] IMPLICIT SEQUENCE OF SEQUENCE {
//                            variableSpecification VariableSpecification,
//                            alternateAccess [5] IMPLICIT AlternateAccess OPTIONAL },
//     variableListName [1] ObjectName }
//   VariableSpecification ::= CHOICE { name [0] ObjectName, ... }  -- only `name` is supported
//
//   AccessResult ::= CHOICE { failure [0] IMPLICIT DataAccessError, success Data }
//
// Decoding is zero-copy: every string_view, byte_view, list_view and data_view refers to the
// input buffer, which must outlive the decoded PDU. The decoders validate the whole PDU up
// front (including every nested Data value), so lazily iterating its lists never fails. Only
// the GetVariableAccessAttributes response allocates (its TypeDescription tree).
//
// Decode error mapping (besides the ber errors): errc::unsupported for valid MMS that is not
// implemented here (an unknown MMSpdu tag, VariableSpecification other than `name`, typeName
// references); errc::malformed_encoding for a wrong tag, form or a missing mandatory field;
// errc::value_out_of_range for an integer that does not fit its ASN.1 subtype.

namespace openiec61850::mms {

enum class pdu_type : std::uint8_t {
  confirmed_request = 0,
  confirmed_response = 1,
  confirmed_error = 2,
  unconfirmed = 3,
  reject = 4,
  cancel_request = 5,
  cancel_response = 6,
  cancel_error = 7,
  initiate_request = 8,
  initiate_response = 9,
  initiate_error = 10,
  conclude_request = 11,
  conclude_response = 12,
  conclude_error = 13,
};

// ConfirmedServiceRequest/-Response CHOICE tags (ISO 9506-2 §7.4). For 0..77 they coincide with
// the ServiceSupportOptions bit numbers.
enum class confirmed_service : std::uint8_t {
  status = 0,
  get_name_list = 1,
  identify = 2,
  rename = 3,
  read = 4,
  write = 5,
  get_variable_access_attributes = 6,
  define_named_variable = 7,
  define_scattered_access = 8,
  get_scattered_access_attributes = 9,
  delete_variable_access = 10,
  define_named_variable_list = 11,
  get_named_variable_list_attributes = 12,
  delete_named_variable_list = 13,
  define_named_type = 14,
  get_named_type_attributes = 15,
  delete_named_type = 16,
  get_domain_attributes = 37,
  obtain_file = 46,
  read_journal = 65,
  write_journal = 66,
  initialize_journal = 67,
  report_journal_status = 68,
  get_capability_list = 71,
  file_open = 72,
  file_read = 73,
  file_close = 74,
  file_rename = 75,
  file_delete = 76,
  file_directory = 77,
};

// ---------------------------------------------------------------------------------------------
// Initiate (ISO 9506-2 §8.2)

// Fixed-capacity BIT STRING used for ParameterSupportOptions and ServiceSupportOptions.
// Bits beyond max_bits received from a peer are ignored.
class support_options {
 public:
  static constexpr std::size_t max_bits = 128;

  constexpr support_options() noexcept = default;
  constexpr explicit support_options(std::size_t bit_count) noexcept
      : bit_count_(bit_count < max_bits ? bit_count : max_bits) {}
  constexpr support_options(std::size_t bit_count, std::initializer_list<std::size_t> set_bits) noexcept
      : support_options(bit_count) {
    for (auto b : set_bits) set(b);
  }
  [[nodiscard]] static support_options from_bits(const ber::bit_string_view& bits) noexcept;

  // Bits at or beyond bit_count() are ignored by set() and read as false by test().
  constexpr void set(std::size_t bit, bool value = true) noexcept {
    if (bit >= bit_count_) return;
    const auto mask = static_cast<std::uint8_t>(0x80U >> (bit % 8));
    if (value) {
      bytes_[bit / 8] = static_cast<std::uint8_t>(bytes_[bit / 8] | mask);
    } else {
      bytes_[bit / 8] = static_cast<std::uint8_t>(bytes_[bit / 8] & ~mask);
    }
  }
  [[nodiscard]] constexpr bool test(std::size_t bit) const noexcept {
    return bit < bit_count_ && (bytes_[bit / 8] & (0x80U >> (bit % 8))) != 0;
  }
  [[nodiscard]] constexpr std::size_t bit_count() const noexcept { return bit_count_; }
  [[nodiscard]] byte_view bytes() const noexcept { return {bytes_.data(), (bit_count_ + 7) / 8}; }

  // Bits set in both (the result has the larger bit count).
  [[nodiscard]] support_options intersect(const support_options& other) const noexcept;

  friend constexpr bool operator==(const support_options&, const support_options&) noexcept = default;

 private:
  std::array<std::uint8_t, max_bits / 8> bytes_{};
  std::size_t bit_count_ = 0;
};

// ParameterSupportOptions bit numbers.
namespace parameter_cbb {
inline constexpr std::size_t str1 = 0;  // arrays
inline constexpr std::size_t str2 = 1;  // structures
inline constexpr std::size_t vnam = 2;  // named variables
inline constexpr std::size_t valt = 3;  // alternate access
inline constexpr std::size_t vadr = 4;  // unnamed variables
inline constexpr std::size_t vsca = 5;  // scattered access
inline constexpr std::size_t tpy = 6;   // third party
inline constexpr std::size_t vlis = 7;  // named variable lists
inline constexpr std::size_t real = 8;
inline constexpr std::size_t cei = 10;  // condition event information
inline constexpr std::size_t bit_count = 11;
}  // namespace parameter_cbb

// ServiceSupportOptions bit numbers.
namespace service_bit {
inline constexpr std::size_t status = 0;
inline constexpr std::size_t get_name_list = 1;
inline constexpr std::size_t identify = 2;
inline constexpr std::size_t rename = 3;
inline constexpr std::size_t read = 4;
inline constexpr std::size_t write = 5;
inline constexpr std::size_t get_variable_access_attributes = 6;
inline constexpr std::size_t define_named_variable = 7;
inline constexpr std::size_t define_scattered_access = 8;
inline constexpr std::size_t get_scattered_access_attributes = 9;
inline constexpr std::size_t delete_variable_access = 10;
inline constexpr std::size_t define_named_variable_list = 11;
inline constexpr std::size_t get_named_variable_list_attributes = 12;
inline constexpr std::size_t delete_named_variable_list = 13;
inline constexpr std::size_t define_named_type = 14;
inline constexpr std::size_t get_named_type_attributes = 15;
inline constexpr std::size_t delete_named_type = 16;
inline constexpr std::size_t get_domain_attributes = 37;
inline constexpr std::size_t obtain_file = 46;
inline constexpr std::size_t read_journal = 65;
inline constexpr std::size_t write_journal = 66;
inline constexpr std::size_t initialize_journal = 67;
inline constexpr std::size_t report_journal_status = 68;
inline constexpr std::size_t create_journal = 69;
inline constexpr std::size_t delete_journal = 70;
inline constexpr std::size_t get_capability_list = 71;
inline constexpr std::size_t file_open = 72;
inline constexpr std::size_t file_read = 73;
inline constexpr std::size_t file_close = 74;
inline constexpr std::size_t file_rename = 75;
inline constexpr std::size_t file_delete = 76;
inline constexpr std::size_t file_directory = 77;
inline constexpr std::size_t unsolicited_status = 78;
inline constexpr std::size_t information_report = 79;
inline constexpr std::size_t event_notification = 80;
inline constexpr std::size_t attach_to_event_condition = 81;
inline constexpr std::size_t attach_to_semaphore = 82;
inline constexpr std::size_t conclude = 83;
inline constexpr std::size_t cancel = 84;
// ISO 9506:1990 defines bits 0..84; IEC 61850-8-1 peers send this length.
inline constexpr std::size_t bit_count = 85;
}  // namespace service_bit

// Profile values for IEC 61850-8-1 (§8.1.2 / table 3 "MMS Initiate"): str1, str2, vnam, valt, vlis.
inline constexpr support_options iec61850_parameter_cbb{
    parameter_cbb::bit_count,
    {parameter_cbb::str1, parameter_cbb::str2, parameter_cbb::vnam, parameter_cbb::valt,
     parameter_cbb::vlis}};

// The services implemented by this codec plus the IEC 61850 file services, informationReport,
// conclude and cancel.
inline constexpr support_options iec61850_services{
    service_bit::bit_count,
    {service_bit::get_name_list, service_bit::identify, service_bit::read, service_bit::write,
     service_bit::get_variable_access_attributes, service_bit::define_named_variable_list,
     service_bit::get_named_variable_list_attributes, service_bit::delete_named_variable_list,
     service_bit::information_report, service_bit::conclude, service_bit::cancel}};

// iec61850_services plus the journal (readJournal, initializeJournal, reportJournalStatus) and
// file services (fileOpen ... fileDirectory) implemented by the server.
inline constexpr support_options iec61850_server_services{
    service_bit::bit_count,
    {service_bit::get_name_list, service_bit::identify, service_bit::read, service_bit::write,
     service_bit::get_variable_access_attributes, service_bit::define_named_variable_list,
     service_bit::get_named_variable_list_attributes, service_bit::delete_named_variable_list,
     service_bit::read_journal, service_bit::initialize_journal,
     service_bit::report_journal_status, service_bit::file_open, service_bit::file_read,
     service_bit::file_close, service_bit::file_rename, service_bit::file_delete,
     service_bit::file_directory, service_bit::information_report, service_bit::conclude,
     service_bit::cancel}};

// What a client serves to the server: iec61850_services plus fileOpen, fileRead and fileClose, the
// services a server issues to pull a file during obtainFile (SetFile).
inline constexpr support_options iec61850_client_services{
    service_bit::bit_count,
    {service_bit::get_name_list, service_bit::identify, service_bit::read, service_bit::write,
     service_bit::get_variable_access_attributes, service_bit::define_named_variable_list,
     service_bit::get_named_variable_list_attributes, service_bit::delete_named_variable_list,
     service_bit::file_open, service_bit::file_read, service_bit::file_close,
     service_bit::information_report, service_bit::conclude, service_bit::cancel}};

struct init_detail {
  std::int16_t version_number = 1;
  support_options parameter_cbb = iec61850_parameter_cbb;
  support_options services = iec61850_services;
};

//   Initiate-RequestPDU ::= SEQUENCE {
//     localDetailCalling                [0] IMPLICIT Integer32 OPTIONAL,
//     proposedMaxServOutstandingCalling [1] IMPLICIT Integer16,
//     proposedMaxServOutstandingCalled  [2] IMPLICIT Integer16,
//     proposedDataStructureNestingLevel [3] IMPLICIT Integer8 OPTIONAL,
//     initRequestDetail                 [4] IMPLICIT SEQUENCE {
//       proposedVersionNumber    [0] IMPLICIT Integer16,
//       proposedParameterCBB     [1] IMPLICIT ParameterSupportOptions,
//       servicesSupportedCalling [2] IMPLICIT ServiceSupportOptions,
//       ... } }
// The response mirrors it (localDetailCalled, negotiated*, initResponseDetail with
// negotiatedVersionNumber, negotiatedParameterCBB, servicesSupportedCalled).
struct initiate_request {
  std::optional<std::int32_t> local_detail_calling = 65000;
  std::int16_t max_serv_outstanding_calling = 5;
  std::int16_t max_serv_outstanding_called = 5;
  std::optional<std::int8_t> data_structure_nesting_level = 10;
  init_detail detail;
};

struct initiate_response {
  std::optional<std::int32_t> local_detail_called = 65000;
  std::int16_t max_serv_outstanding_calling = 5;
  std::int16_t max_serv_outstanding_called = 5;
  std::optional<std::int8_t> data_structure_nesting_level = 10;
  init_detail detail;
};

// ---------------------------------------------------------------------------------------------
// Common types

enum class object_scope : std::uint8_t { vmd_specific = 0, domain_specific = 1, aa_specific = 2 };

struct object_name {
  object_scope scope = object_scope::vmd_specific;
  std::string_view domain_id;  // domain-specific only
  std::string_view item_id;

  [[nodiscard]] static constexpr object_name vmd(std::string_view item) noexcept {
    return {object_scope::vmd_specific, {}, item};
  }
  [[nodiscard]] static constexpr object_name domain(std::string_view domain_id,
                                                    std::string_view item) noexcept {
    return {object_scope::domain_specific, domain_id, item};
  }
  [[nodiscard]] static constexpr object_name aa(std::string_view item) noexcept {
    return {object_scope::aa_specific, {}, item};
  }

  friend constexpr bool operator==(const object_name&, const object_name&) noexcept = default;
};

// One entry of listOfVariable.
struct variable_spec {
  object_name name;
  // Contents octets of [5] IMPLICIT AlternateAccess, carried opaque; empty when absent.
  byte_view alternate_access;

  variable_spec() noexcept = default;
  variable_spec(object_name n, byte_view alt = {}) noexcept  // NOLINT(google-explicit-constructor)
      : name(n), alternate_access(alt) {}
};

struct variable_access_specification {
  enum class kind : std::uint8_t { list_of_variable = 0, variable_list_name = 1 };

  kind type = kind::list_of_variable;
  list_view<variable_spec> variables;  // list_of_variable
  object_name list_name;               // variable_list_name

  [[nodiscard]] static variable_access_specification list(list_view<variable_spec> v) noexcept {
    return {kind::list_of_variable, v, {}};
  }
  [[nodiscard]] static variable_access_specification named(const object_name& n) noexcept {
    return {kind::variable_list_name, {}, n};
  }
};

// DataAccessError (ISO 9506-2 §14.4.3).
enum class data_access_error : std::uint8_t {
  object_invalidated = 0,
  hardware_fault = 1,
  temporarily_unavailable = 2,
  object_access_denied = 3,
  object_undefined = 4,
  invalid_address = 5,
  type_unsupported = 6,
  type_inconsistent = 7,
  object_attribute_inconsistent = 8,
  object_access_unsupported = 9,
  object_non_existent = 10,
  object_value_invalid = 11,
};

struct access_result {
  std::optional<data_access_error> failure;  // empty: success
  data_ref value;                            // success

  access_result() noexcept = default;
  access_result(data_ref v) noexcept : value(v) {}  // NOLINT(google-explicit-constructor)
  access_result(data_access_error e) noexcept : failure(e) {}  // NOLINT(google-explicit-constructor)

  [[nodiscard]] bool success() const noexcept { return !failure.has_value(); }
};

// ---------------------------------------------------------------------------------------------
// ServiceError (ISO 9506-2 §7.5.4) and RejectPDU (§7.5.5)

//   ServiceError ::= SEQUENCE {
//     errorClass [0] CHOICE { vmd-state [0] IMPLICIT INTEGER, ... others [12] IMPLICIT INTEGER },
//     additionalCode        [1] IMPLICIT INTEGER OPTIONAL,
//     additionalDescription [2] IMPLICIT VisibleString OPTIONAL,
//     serviceSpecificInfo   [3] CHOICE { ... } OPTIONAL }
enum class error_class : std::uint8_t {
  vmd_state = 0,
  application_reference = 1,
  definition = 2,
  resource = 3,
  service = 4,
  service_preempt = 5,
  time_resolution = 6,
  access = 7,
  initiate = 8,
  conclude = 9,
  cancel = 10,
  file = 11,
  others = 12,
};

// Error codes per class.
namespace error_code {
namespace definition {
inline constexpr std::int64_t other = 0, object_undefined = 1, invalid_address = 2,
                              type_unsupported = 3, type_inconsistent = 4, object_exists = 5,
                              object_attribute_inconsistent = 6;
}
namespace resource {
inline constexpr std::int64_t other = 0, memory_unavailable = 1,
                              processor_resource_unavailable = 2, mass_storage_unavailable = 3,
                              capability_unavailable = 4, capability_unknown = 5;
}
namespace service {
inline constexpr std::int64_t other = 0, primitives_out_of_sequence = 1,
                              object_state_conflict = 2, continuation_invalid = 4,
                              object_constraint_conflict = 5;
}
namespace access {
inline constexpr std::int64_t other = 0, object_access_unsupported = 1, object_non_existent = 2,
                              object_access_denied = 3, object_invalidated = 4;
}
namespace initiate {
inline constexpr std::int64_t other = 0, max_services_outstanding_calling_insufficient = 3,
                              max_services_outstanding_called_insufficient = 4,
                              service_cbb_insufficient = 5, parameter_cbb_insufficient = 6,
                              nesting_level_insufficient = 7;
}
namespace conclude {
inline constexpr std::int64_t other = 0, further_communication_required = 1;
}
namespace cancel {
inline constexpr std::int64_t other = 0, invoke_id_unknown = 1, cancel_not_possible = 2;
}
namespace file {
inline constexpr std::int64_t other = 0, filename_ambiguous = 1, file_busy = 2,
                              filename_syntax_error = 3, content_type_invalid = 4,
                              position_invalid = 5, file_access_denied = 6, file_non_existent = 7,
                              duplicate_filename = 8, insufficient_space_in_filestore = 9;
}
}  // namespace error_code

struct service_error {
  service_error() noexcept = default;
  service_error(error_class c, std::int64_t value) noexcept : cls(c), code(value) {}

  error_class cls = error_class::others;
  std::int64_t code = 0;
  std::optional<std::int64_t> additional_code;
  std::optional<std::string_view> additional_description;
  // Contents octets of [3] serviceSpecificInfo, carried opaque; empty when absent.
  byte_view service_specific_info;
};

//   RejectPDU ::= SEQUENCE { originalInvokeID [0] IMPLICIT Unsigned32 OPTIONAL,
//     rejectReason CHOICE { confirmed-requestPDU [1] IMPLICIT INTEGER, ...,
//                           conclude-errorPDU [11] IMPLICIT INTEGER } }
enum class reject_type : std::uint8_t {
  confirmed_request = 1,
  confirmed_response = 2,
  confirmed_error = 3,
  unconfirmed = 4,
  pdu_error = 5,
  cancel_request = 6,
  cancel_response = 7,
  cancel_error = 8,
  conclude_request = 9,
  conclude_response = 10,
  conclude_error = 11,
};

namespace reject_code {
namespace confirmed_request {
inline constexpr std::int64_t other = 0, unrecognized_service = 1, unrecognized_modifier = 2,
                              invalid_invoke_id = 3, invalid_argument = 4, invalid_modifier = 5,
                              max_serv_outstanding_exceeded = 6, max_recursion_exceeded = 8,
                              value_out_of_range = 9;
}
namespace confirmed_response {
inline constexpr std::int64_t other = 0, unrecognized_service = 1, invalid_invoke_id = 2,
                              invalid_result = 3, max_recursion_exceeded = 5,
                              value_out_of_range = 6;
}
namespace confirmed_error {
inline constexpr std::int64_t other = 0, unrecognized_service = 1, invalid_invoke_id = 2,
                              invalid_service_error = 3, value_out_of_range = 4;
}
namespace unconfirmed {
inline constexpr std::int64_t other = 0, unrecognized_service = 1, invalid_argument = 2,
                              max_recursion_exceeded = 3, value_out_of_range = 4;
}
namespace pdu_error {
inline constexpr std::int64_t unknown_pdu_type = 0, invalid_pdu = 1, illegal_acse_mapping = 2;
}
}  // namespace reject_code

// ---------------------------------------------------------------------------------------------
// Confirmed services

// A service this codec does not implement; `encoding` is the complete service element.
struct other_service {
  std::uint32_t tag = 0;
  byte_view encoding;
};

struct identify_request {};

//   Identify-Response ::= SEQUENCE { vendorName [0] IMPLICIT MMSString,
//     modelName [1] IMPLICIT MMSString, revision [2] IMPLICIT MMSString,
//     listOfAbstractSyntaxes [3] IMPLICIT SEQUENCE OF OBJECT IDENTIFIER OPTIONAL }
struct identify_response {
  std::string_view vendor_name;
  std::string_view model_name;
  std::string_view revision;
  list_view<ber::oid> abstract_syntaxes;  // omitted when empty
};

// ObjectClass basicObjectClass values.
enum class object_class : std::uint8_t {
  named_variable = 0,
  scattered_access = 1,
  named_variable_list = 2,
  named_type = 3,
  semaphore = 4,
  event_condition = 5,
  event_action = 6,
  event_enrollment = 7,
  journal = 8,
  domain = 9,
  program_invocation = 10,
  operator_station = 11,
  data_exchange = 12,
  access_control_list = 13,
};

//   GetNameList-Request ::= SEQUENCE {
//     objectClass   [0] ObjectClass,  -- CHOICE { basicObjectClass [0] IMPLICIT INTEGER, ... }
//     objectScope   [1] CHOICE { vmdSpecific [0] IMPLICIT NULL,
//                                domainSpecific [1] IMPLICIT Identifier,
//                                aaSpecific [2] IMPLICIT NULL },
//     continueAfter [2] IMPLICIT Identifier OPTIONAL }
struct get_name_list_request {
  object_class cls = object_class::named_variable;
  object_scope scope = object_scope::vmd_specific;
  std::string_view domain_id;  // domain-specific scope
  std::optional<std::string_view> continue_after;
};

//   GetNameList-Response ::= SEQUENCE { listOfIdentifier [0] IMPLICIT SEQUENCE OF Identifier,
//     moreFollows [1] IMPLICIT BOOLEAN DEFAULT TRUE }
struct get_name_list_response {
  list_view<std::string_view> identifiers;
  bool more_follows = true;
};

//   Read-Request ::= SEQUENCE { specificationWithResult [0] IMPLICIT BOOLEAN DEFAULT FALSE,
//     variableAccessSpecification [1] VariableAccessSpecification }
struct read_request {
  bool specification_with_result = false;
  variable_access_specification spec;
};

//   Read-Response ::= SEQUENCE { variableAccessSpecification [0] VariableAccessSpecification
//     OPTIONAL, listOfAccessResult [1] IMPLICIT SEQUENCE OF AccessResult }
struct read_response {
  std::optional<variable_access_specification> spec;
  list_view<access_result> results;
};

//   Write-Request ::= SEQUENCE { variableAccessSpecification VariableAccessSpecification,
//     listOfData [0] IMPLICIT SEQUENCE OF Data }
struct write_request {
  variable_access_specification spec;
  list_view<data_ref> values;
};

//   Write-Response ::= SEQUENCE OF CHOICE { failure [0] IMPLICIT DataAccessError,
//     success [1] IMPLICIT NULL }
struct write_result {
  std::optional<data_access_error> failure;  // empty: success

  write_result() noexcept = default;
  write_result(data_access_error e) noexcept : failure(e) {}  // NOLINT(google-explicit-constructor)
  [[nodiscard]] bool success() const noexcept { return !failure.has_value(); }
};

struct write_response {
  list_view<write_result> results;
};

//   GetVariableAccessAttributes-Request ::= CHOICE { name [0] ObjectName, address [1] Address }
// (only `name` is supported).
struct get_variable_access_attributes_request {
  object_name name;
};

//   GetVariableAccessAttributes-Response ::= SEQUENCE { mmsDeletable [0] IMPLICIT BOOLEAN,
//     address [1] Address OPTIONAL, typeDescription [2] TypeDescription, ... }
// address and the later optional fields are skipped when decoding and never encoded.
struct get_variable_access_attributes_response {
  bool mms_deletable = false;
  type_description type;
};

// GetNamedVariableListAttributes-Request ::= ObjectName
struct get_named_variable_list_attributes_request {
  object_name name;
};

//   GetNamedVariableListAttributes-Response ::= SEQUENCE { mmsDeletable [0] IMPLICIT BOOLEAN,
//     listOfVariable [1] IMPLICIT SEQUENCE OF SEQUENCE { variableSpecification,
//       alternateAccess [5] IMPLICIT AlternateAccess OPTIONAL },
//     accessControlList [2] IMPLICIT Identifier OPTIONAL }
struct get_named_variable_list_attributes_response {
  bool mms_deletable = false;
  list_view<variable_spec> variables;
};

//   DefineNamedVariableList-Request ::= SEQUENCE { variableListName ObjectName,
//     listOfVariable [0] IMPLICIT SEQUENCE OF SEQUENCE { variableSpecification,
//       alternateAccess [5] IMPLICIT AlternateAccess OPTIONAL } }
struct define_named_variable_list_request {
  object_name name;
  list_view<variable_spec> variables;
};

struct define_named_variable_list_response {};  // NULL

enum class delete_scope : std::uint8_t { specific = 0, aa_specific = 1, domain = 2, vmd = 3 };

//   DeleteNamedVariableList-Request ::= SEQUENCE {
//     scopeOfDelete [0] IMPLICIT INTEGER { specific(0), aa-specific(1), domain(2), vmd(3) }
//                       DEFAULT specific,
//     listOfVariableListName [1] IMPLICIT SEQUENCE OF ObjectName OPTIONAL,
//     domainName [2] IMPLICIT Identifier OPTIONAL }
struct delete_named_variable_list_request {
  delete_scope scope = delete_scope::specific;
  list_view<object_name> names;  // omitted when empty
  std::optional<std::string_view> domain_name;
};

//   DeleteNamedVariableList-Response ::= SEQUENCE { numberMatched [0] IMPLICIT Unsigned32,
//     numberDeleted [1] IMPLICIT Unsigned32 }
struct delete_named_variable_list_response {
  std::uint32_t number_matched = 0;
  std::uint32_t number_deleted = 0;
};

// ---------------------------------------------------------------------------------------------
// Journal services (ISO 9506-2 §19 "Journal management"; IEC 61850-8-1 §17.3 maps the ACSI log
// onto them). TimeOfDay fields are the 4- or 6-octet form of mms::binary_time.

//   ReadJournal-Request ::= SEQUENCE {
//     journalName             [0] ObjectName,
//     rangeStartSpecification [1] CHOICE { startingTime [0] IMPLICIT TimeOfDay,
//                                          startingEntry [1] IMPLICIT OCTET STRING } OPTIONAL,
//     rangeStopSpecification  [2] CHOICE { endingTime [0] IMPLICIT TimeOfDay,
//                                          numberOfEntries [1] IMPLICIT Integer32 } OPTIONAL,
//     listOfVariables         [4] IMPLICIT SEQUENCE OF VisibleString OPTIONAL,
//     entryToStartAfter       [5] IMPLICIT SEQUENCE { timeSpecification [0] IMPLICIT TimeOfDay,
//                                                     entrySpecification [1] IMPLICIT OCTET STRING }
//                                 OPTIONAL }
// At most one of each starting_* / ending_* pair may be set (encoding fails with
// errc::invalid_state otherwise).
struct journal_start_after {
  binary_time time;
  byte_view entry;
};

struct read_journal_request {
  object_name journal_name;
  std::optional<binary_time> starting_time;
  std::optional<byte_view> starting_entry;
  std::optional<binary_time> ending_time;
  std::optional<std::int32_t> number_of_entries;
  std::optional<list_view<std::string_view>> variables;
  std::optional<journal_start_after> start_after;
};

//   Journal-Variable ::= SEQUENCE { variableTag [0] IMPLICIT MMS255String,
//                                   valueSpecification [1] Data }
struct journal_variable {
  std::string_view tag;
  data_ref value;
};

//   JournalEntry ::= SEQUENCE {
//     entryIdentifier        [0] IMPLICIT OCTET STRING,
//     originatingApplication [1] ApplicationReference,
//     entryContent           [2] IMPLICIT EntryContent }
//   EntryContent ::= SEQUENCE {
//     occurrenceTime   [0] IMPLICIT TimeOfDay,
//     additionalDetail [1] ... OPTIONAL,              -- skipped when decoding, never encoded
//     entryForm CHOICE {
//       data [2] IMPLICIT SEQUENCE {
//         event [0] IMPLICIT SEQUENCE { ... } OPTIONAL,  -- carried opaque
//         listOfVariables [1] IMPLICIT SEQUENCE OF Journal-Variable OPTIONAL },
//       annotation [3] MMSString } }
// `originating_application` holds the contents of [1] (an ApplicationReference SEQUENCE); when
// empty an empty SEQUENCE is encoded. An annotation entry has `annotation` set.
struct journal_entry {
  byte_view entry_id;
  byte_view originating_application;
  binary_time occurrence_time;
  byte_view event;  // contents of event [0]; empty when absent
  list_view<journal_variable> variables;
  std::optional<std::string_view> annotation;
};

//   ReadJournal-Response ::= SEQUENCE {
//     listOfJournalEntry [0] IMPLICIT SEQUENCE OF JournalEntry,
//     moreFollows        [1] IMPLICIT BOOLEAN DEFAULT FALSE }
struct read_journal_response {
  list_view<journal_entry> entries;
  bool more_follows = false;
};

//   InitializeJournal-Request ::= SEQUENCE {
//     journalName        [0] ObjectName,
//     limitSpecification [1] IMPLICIT SEQUENCE { limitingTime [0] IMPLICIT TimeOfDay,
//                                                limitingEntry [1] IMPLICIT OCTET STRING OPTIONAL }
//                            OPTIONAL }
//   InitializeJournal-Response ::= Unsigned32  -- entries deleted
struct initialize_journal_request {
  object_name journal_name;
  std::optional<binary_time> limiting_time;
  std::optional<byte_view> limiting_entry;  // requires limiting_time
};

struct initialize_journal_response {
  std::uint32_t deleted = 0;
};

//   ReportJournalStatus-Request ::= ObjectName
//   ReportJournalStatus-Response ::= SEQUENCE { currentEntries [0] IMPLICIT Unsigned32,
//     mmsDeletable [1] IMPLICIT BOOLEAN, accessControlList [2] IMPLICIT Identifier OPTIONAL }
struct report_journal_status_request {
  object_name journal_name;
};

struct report_journal_status_response {
  std::uint32_t current_entries = 0;
  bool mms_deletable = false;
};

// ---------------------------------------------------------------------------------------------
// File services (ISO 9506-2 Annex C "File access"; IEC 61850-8-1 §23 maps the ACSI file
// transfer onto them; SetFile is obtainFile, whose responder reads the file back from the requester
// with fileOpen, fileRead and fileClose while the request is outstanding).
//
//   FileName ::= SEQUENCE OF GraphicString   -- a VisibleString is accepted too
//   FileAttributes ::= SEQUENCE { sizeOfFile [0] IMPLICIT Unsigned32,
//                                 lastModified [1] IMPLICIT GeneralizedTime OPTIONAL }

struct file_attributes {
  std::uint32_t size = 0;
  std::optional<std::string_view> last_modified;  // GeneralizedTime text, e.g. "20240101120000Z"
};

//   FileOpen-Request ::= SEQUENCE { fileName [0] IMPLICIT FileName,
//                                   initialPosition [1] IMPLICIT Unsigned32 }
//   FileOpen-Response ::= SEQUENCE { frsmID [0] IMPLICIT Integer32,
//                                    fileAttributes [1] IMPLICIT FileAttributes }
struct file_open_request {
  list_view<std::string_view> file_name;
  std::uint32_t initial_position = 0;
};

struct file_open_response {
  std::int32_t frsm_id = 0;
  file_attributes attributes;
};

//   FileRead-Request ::= Integer32  -- FRSM ID
//   FileRead-Response ::= SEQUENCE { fileData [0] IMPLICIT OCTET STRING,
//                                    moreFollows [1] IMPLICIT BOOLEAN DEFAULT TRUE }
struct file_read_request {
  std::int32_t frsm_id = 0;
};

struct file_read_response {
  byte_view data;
  bool more_follows = true;
};

//   FileClose-Request ::= Integer32  -- FRSM ID;  FileClose-Response ::= NULL
struct file_close_request {
  std::int32_t frsm_id = 0;
};

struct file_close_response {};

//   FileRename-Request ::= SEQUENCE { currentFileName [0] IMPLICIT FileName,
//                                     newFileName [1] IMPLICIT FileName }
//   FileRename-Response ::= NULL
struct file_rename_request {
  list_view<std::string_view> current_name;
  list_view<std::string_view> new_name;
};

struct file_rename_response {};

//   FileDelete-Request ::= FileName;  FileDelete-Response ::= NULL
struct file_delete_request {
  list_view<std::string_view> file_name;
};

struct file_delete_response {};

//   FileDirectory-Request ::= SEQUENCE { fileSpecification [0] IMPLICIT FileName OPTIONAL,
//                                        continueAfter [1] IMPLICIT FileName OPTIONAL }
//   FileDirectory-Response ::= SEQUENCE {
//     listOfDirectoryEntry [0] SEQUENCE OF DirectoryEntry,   -- explicit tag
//     moreFollows          [1] IMPLICIT BOOLEAN DEFAULT FALSE }
//   DirectoryEntry ::= SEQUENCE { fileName [0] IMPLICIT FileName,
//                                 fileAttributes [1] IMPLICIT FileAttributes }
struct file_directory_request {
  std::optional<list_view<std::string_view>> file_specification;
  std::optional<list_view<std::string_view>> continue_after;
};

struct directory_entry {
  list_view<std::string_view> file_name;
  file_attributes attributes;
};

struct file_directory_response {
  list_view<directory_entry> entries;
  bool more_follows = false;
};

//   ObtainFile-Request ::= SEQUENCE { sourceFileServer [0] IMPLICIT ApplicationReference OPTIONAL,
//                                     sourceFile [1] IMPLICIT FileName,
//                                     destinationFile [2] IMPLICIT FileName }
//   ObtainFile-Response ::= NULL
// `source_file_server` holds the contents of [0], opaque (third party, parameter CBB tpy); when
// set and empty an empty SEQUENCE is encoded.
struct obtain_file_request {
  std::optional<byte_view> source_file_server;
  list_view<std::string_view> source_file;
  list_view<std::string_view> destination_file;
};

struct obtain_file_response {};

// ObtainFile-Error, carried in serviceSpecificInfo (service_error::service_specific_info holds
// obtainFile [0] IMPLICIT INTEGER): which of the two files the error is about.
namespace obtain_file_error {
inline constexpr std::array<std::uint8_t, 3> source_file{0x80, 0x01, 0x00};
inline constexpr std::array<std::uint8_t, 3> destination_file{0x80, 0x01, 0x01};
}  // namespace obtain_file_error

// The alternatives after other_service were added later; existing indices are unchanged.
using confirmed_service_request =
    std::variant<identify_request, get_name_list_request, read_request, write_request,
                 get_variable_access_attributes_request, get_named_variable_list_attributes_request,
                 define_named_variable_list_request, delete_named_variable_list_request,
                 other_service, read_journal_request, initialize_journal_request,
                 report_journal_status_request, file_open_request, file_read_request,
                 file_close_request, file_rename_request, file_delete_request,
                 file_directory_request, obtain_file_request>;

using confirmed_service_response =
    std::variant<identify_response, get_name_list_response, read_response, write_response,
                 get_variable_access_attributes_response,
                 get_named_variable_list_attributes_response, define_named_variable_list_response,
                 delete_named_variable_list_response, other_service, read_journal_response,
                 initialize_journal_response, report_journal_status_response, file_open_response,
                 file_read_response, file_close_response, file_rename_response,
                 file_delete_response, file_directory_response, obtain_file_response>;

// The CHOICE tag of a service (other_service: its tag).
[[nodiscard]] std::uint32_t service_tag(const confirmed_service_request& s) noexcept;
[[nodiscard]] std::uint32_t service_tag(const confirmed_service_response& s) noexcept;

// ---------------------------------------------------------------------------------------------
// Unconfirmed services

//   UnconfirmedService ::= CHOICE { informationReport [0] IMPLICIT InformationReport, ... }
//   InformationReport ::= SEQUENCE { variableAccessSpecification VariableAccessSpecification,
//     listOfAccessResult [0] IMPLICIT SEQUENCE OF AccessResult }
// IEC 61850-8-1 reports use variableListName = vmd-specific "RPT".
struct information_report {
  variable_access_specification spec;
  list_view<access_result> results;
};

using unconfirmed_service = std::variant<information_report, other_service>;

// ---------------------------------------------------------------------------------------------
// PDUs. The index of each alternative in mms_pdu equals its MMSpdu tag.

struct confirmed_request {
  std::uint32_t invoke_id = 0;
  byte_view modifiers;  // contents of listOfModifier, opaque; empty when absent
  confirmed_service_request service;
};

struct confirmed_response {
  std::uint32_t invoke_id = 0;
  confirmed_service_response service;
};

struct confirmed_error {
  std::uint32_t invoke_id = 0;
  std::optional<std::uint32_t> modifier_position;
  service_error error;
};

struct unconfirmed_pdu {
  unconfirmed_service service;
};

struct reject_pdu {
  std::optional<std::uint32_t> original_invoke_id;
  reject_type type = reject_type::pdu_error;
  std::int64_t reason = 0;
};

struct cancel_request {
  std::uint32_t invoke_id = 0;
};
struct cancel_response {
  std::uint32_t invoke_id = 0;
};
struct cancel_error {
  std::uint32_t invoke_id = 0;
  service_error error;
};

struct initiate_error {
  service_error error;
};
struct conclude_request {};
struct conclude_response {};
struct conclude_error {
  service_error error;
};

using mms_pdu =
    std::variant<confirmed_request, confirmed_response, confirmed_error, unconfirmed_pdu,
                 reject_pdu, cancel_request, cancel_response, cancel_error, initiate_request,
                 initiate_response, initiate_error, conclude_request, conclude_response,
                 conclude_error>;

[[nodiscard]] inline pdu_type type_of(const mms_pdu& pdu) noexcept {
  return static_cast<pdu_type>(pdu.index());
}

// The invokeID of confirmed request/response/error and the cancel PDUs; the originalInvokeID
// of a reject when present.
[[nodiscard]] std::optional<std::uint32_t> invoke_id(const mms_pdu& pdu) noexcept;

// Reads only the PDU tag and the invokeID of a confirmed request/response/error, even when the
// rest of the PDU is malformed, so that the receiver can reject it with originalInvokeID.
[[nodiscard]] result<std::uint32_t> peek_invoke_id(byte_view pdu) noexcept;

// Decodes exactly one MMSpdu (trailing bytes are malformed).
[[nodiscard]] result<mms_pdu> decode_pdu(byte_view pdu, const decode_options& opts = {});

// Appends the encoding of `pdu` to `out`. On failure (errc::invalid_state for an invalid owned
// Data value or an inconsistent TypeDescription), `out` is restored to its original size.
[[nodiscard]] result<void> encode_pdu(const mms_pdu& pdu, byte_buffer& out);

}  // namespace openiec61850::mms
