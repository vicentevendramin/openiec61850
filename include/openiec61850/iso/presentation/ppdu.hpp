#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <variant>
#include <vector>

#include "openiec61850/ber/oid.hpp"
#include "openiec61850/core/bytes.hpp"
#include "openiec61850/core/result.hpp"

// Connection-oriented presentation protocol (ISO/IEC 8823-1 = ITU-T X.226) PPDU codec: normal mode,
// kernel functional unit, fully-encoded user data. Every PPDU is BER-encoded (X.226 §8.1).
//
// Tags used here, from the ISO8823-PRESENTATION ASN.1 module (X.226 §8.2):
//
//   CP-type ::= SET {                                                          31
//     mode-selector                [0] IMPLICIT Mode-selector,                 A0 { 80 mode }
//     x410-mode-parameters         [1] IMPLICIT RTORQapdu OPTIONAL,            A1 (unsupported)
//     normal-mode-parameters       [2] IMPLICIT SEQUENCE {                     A2
//       protocol-version           [0] IMPLICIT BIT STRING {version-1(0)} DEFAULT {version-1}, 80
//       calling-presentation-selector [1] IMPLICIT OCTET STRING OPTIONAL,     81
//       called-presentation-selector  [2] IMPLICIT OCTET STRING OPTIONAL,     82
//       presentation-context-definition-list [4] IMPLICIT Context-list OPTIONAL, A4
//       default-context-name       [6] IMPLICIT SEQUENCE {                     A6
//                                     abstract-syntax-name [0] IMPLICIT OID,   80
//                                     transfer-syntax-name [1] IMPLICIT OID }  81
//       presentation-requirements  [8] IMPLICIT BIT STRING OPTIONAL,           88
//       user-session-requirements  [9] IMPLICIT BIT STRING OPTIONAL,           89
//       protocol-options [11], initiators-nominated-context [12], extensions [14]  (skipped)
//       user-data                  User-data OPTIONAL } OPTIONAL }             61 / 40
//   Mode-selector ::= SET { mode-value [0] IMPLICIT INTEGER {x410-1984-mode(0), normal-mode(1)} }
//   Context-list ::= SEQUENCE OF SEQUENCE {                                    30 { 30 ... }
//     presentation-context-identifier INTEGER,                                 02
//     abstract-syntax-name            OBJECT IDENTIFIER,                       06
//     transfer-syntax-name-list       SEQUENCE OF OBJECT IDENTIFIER }          30 { 06 ... }
//
//   CPA-PPDU ::= SET {                                                         31
//     mode-selector [0], x410-mode-parameters [1] (unsupported),
//     normal-mode-parameters [2] IMPLICIT SEQUENCE {                           A2
//       protocol-version [0], responding-presentation-selector [3] IMPLICIT OCTET STRING, 80 83
//       presentation-context-definition-result-list [5] IMPLICIT Result-list, A5
//       presentation-requirements [8], user-session-requirements [9],          88 89
//       protocol-options [11], responders-nominated-context [13] (skipped), user-data } }
//   Result-list ::= SEQUENCE OF SEQUENCE {
//     result               [0] IMPLICIT INTEGER {acceptance(0), user-rejection(1),
//                                                provider-rejection(2)},        80
//     transfer-syntax-name [1] IMPLICIT OBJECT IDENTIFIER OPTIONAL,            81
//     provider-reason      [2] IMPLICIT INTEGER OPTIONAL }                     82
//
//   CPR-PPDU ::= CHOICE { x400-mode-parameters RTORJapdu (SET, unsupported),
//     normal-mode-parameters SEQUENCE {                                        30
//       protocol-version [0], responding-presentation-selector [3],
//       presentation-context-definition-result-list [5],
//       default-context-result [7] IMPLICIT Result,                            87
//       provider-reason [10] IMPLICIT INTEGER,                                 8A
//       user-data } }
//
//   Abort-type ::= CHOICE { aru-ppdu ARU-PPDU, arp-ppdu ARP-PPDU }
//   ARU-PPDU ::= CHOICE { x400-mode-parameters RTABapdu (SET, unsupported),
//     normal-mode-parameters [0] IMPLICIT SEQUENCE {                           A0
//       presentation-context-identifier-list [0] IMPLICIT SEQUENCE OF SEQUENCE { A0
//         presentation-context-identifier INTEGER, transfer-syntax-name OID } OPTIONAL,
//       user-data User-data OPTIONAL } }
//   ARP-PPDU ::= SEQUENCE {                                                    30
//     provider-reason  [0] IMPLICIT Abort-reason OPTIONAL,                     80
//     event-identifier [1] IMPLICIT Event-identifier OPTIONAL }                81
//
//   User-data ::= CHOICE {
//     simply-encoded-data [APPLICATION 0] IMPLICIT OCTET STRING,               40 (unsupported)
//     fully-encoded-data  [APPLICATION 1] IMPLICIT SEQUENCE SIZE(1..MAX) OF PDV-list }  61
//   PDV-list ::= SEQUENCE {                                                    30
//     transfer-syntax-name            OBJECT IDENTIFIER OPTIONAL,              06
//     presentation-context-identifier INTEGER,                                 02
//     presentation-data-values CHOICE {
//       single-ASN1-type [0] ABSTRACT-SYNTAX.&Type,  (explicit: open type)     A0
//       octet-aligned    [1] IMPLICIT OCTET STRING,                            81
//       arbitrary        [2] IMPLICIT BIT STRING } }                           82
//
// TD-PPDU (P-DATA) and the user data of P-RELEASE are a bare User-data (X.226 §8.4, §8.2).
// Elements of a SET may come in any order; SEQUENCE elements must come in order. Context-specific
// elements of normal-mode-parameters from [11] on are skipped (options and extensions not supported
// here); any other unexpected element is malformed.
namespace openiec61850::iso::presentation {

// Object identifiers of the IEC 61850-8-1 profile.
inline constexpr ber::oid ber_transfer_syntax{2, 1, 1};            // basic-encoding (X.690)
inline constexpr ber::oid acse_abstract_syntax{2, 2, 1, 0, 1};     // acse-as-id (X.227)
inline constexpr ber::oid mms_abstract_syntax{1, 0, 9506, 2, 1};   // mms-abstract-syntax-version1

// Protocol-version, Presentation-requirements and User-session-requirements are named bit lists;
// they are held as masks where BIT STRING bit i is (1 << i). Bits beyond 31 are ignored.
inline constexpr std::uint32_t protocol_version_1 = 0x01;
namespace requirements {
inline constexpr std::uint32_t context_management = 0x01;
inline constexpr std::uint32_t restoration = 0x02;
}  // namespace requirements

// Mode-selector mode-value.
namespace mode {
inline constexpr std::int64_t x410_1984 = 0;
inline constexpr std::int64_t normal = 1;
}  // namespace mode

// Result of a presentation context definition (and default-context-result).
enum class context_result_code : std::uint8_t {
  acceptance = 0,
  user_rejection = 1,
  provider_rejection = 2,
};

// Result-list provider-reason.
namespace context_reason {
inline constexpr std::uint8_t not_specified = 0;
inline constexpr std::uint8_t abstract_syntax_not_supported = 1;
inline constexpr std::uint8_t proposed_transfer_syntaxes_not_supported = 2;
inline constexpr std::uint8_t local_limit_on_dcs_exceeded = 3;
}  // namespace context_reason

// CPR-PPDU Provider-reason.
namespace provider_reason {
inline constexpr std::uint8_t not_specified = 0;
inline constexpr std::uint8_t temporary_congestion = 1;
inline constexpr std::uint8_t local_limit_exceeded = 2;
inline constexpr std::uint8_t called_presentation_address_unknown = 3;
inline constexpr std::uint8_t protocol_version_not_supported = 4;
inline constexpr std::uint8_t default_context_not_supported = 5;
inline constexpr std::uint8_t user_data_not_readable = 6;
inline constexpr std::uint8_t no_psap_available = 7;
}  // namespace provider_reason

// ARP-PPDU Abort-reason.
namespace abort_reason {
inline constexpr std::uint8_t not_specified = 0;
inline constexpr std::uint8_t unrecognized_ppdu = 1;
inline constexpr std::uint8_t unexpected_ppdu = 2;
inline constexpr std::uint8_t unexpected_session_service_primitive = 3;
inline constexpr std::uint8_t unrecognized_ppdu_parameter = 4;
inline constexpr std::uint8_t unexpected_ppdu_parameter = 5;
inline constexpr std::uint8_t invalid_ppdu_parameter_value = 6;
}  // namespace abort_reason

// ARP-PPDU Event-identifier (the subset relevant to the kernel).
namespace event_id {
inline constexpr std::uint8_t cp_ppdu = 0;
inline constexpr std::uint8_t cpa_ppdu = 1;
inline constexpr std::uint8_t cpr_ppdu = 2;
inline constexpr std::uint8_t aru_ppdu = 3;
inline constexpr std::uint8_t arp_ppdu = 4;
inline constexpr std::uint8_t td_ppdu = 7;
inline constexpr std::uint8_t s_release_indication = 14;
inline constexpr std::uint8_t s_release_confirm = 15;
}  // namespace event_id

// All byte_view members of decoded PPDUs point into the decoded buffer. An empty selector view
// means the parameter is absent; encoders omit empty selectors and empty lists.

enum class pdv_encoding : std::uint8_t { single_asn1_type, octet_aligned, arbitrary };

// One PDV-list: a presentation data value of one presentation context.
struct pdv {
  std::optional<ber::oid> transfer_syntax;
  std::uint32_t context_id = 0;
  pdv_encoding encoding = pdv_encoding::single_asn1_type;
  // single_asn1_type: the complete encoding (one TLV) of the embedded value, e.g. an ACSE APDU or
  // an MMS PDU. octet_aligned: the OCTET STRING contents. arbitrary: the BIT STRING data octets.
  byte_view data;
  std::uint8_t unused_bits = 0;  // arbitrary only
};

struct context_definition {
  std::uint32_t id = 0;
  ber::oid abstract_syntax;
  std::vector<ber::oid> transfer_syntaxes;
};

struct context_result {
  context_result_code result = context_result_code::acceptance;
  std::optional<ber::oid> transfer_syntax;
  std::optional<std::uint8_t> provider_reason;  // context_reason
};

struct default_context_name {
  ber::oid abstract_syntax;
  ber::oid transfer_syntax;
};

struct context_identifier {
  std::uint32_t id = 0;
  ber::oid transfer_syntax;
};

struct connect_ppdu {  // CP-type (CP-PPDU), normal mode
  std::optional<std::uint32_t> protocol_version;  // absent = {version-1}
  byte_view calling_selector;
  byte_view called_selector;
  std::vector<context_definition> contexts;
  std::optional<default_context_name> default_context;
  std::optional<std::uint32_t> presentation_requirements;
  std::optional<std::uint32_t> user_session_requirements;
  std::vector<pdv> user_data;
};

struct accept_ppdu {  // CPA-PPDU, normal mode
  std::optional<std::uint32_t> protocol_version;
  byte_view responding_selector;
  std::vector<context_result> results;
  std::optional<std::uint32_t> presentation_requirements;
  std::optional<std::uint32_t> user_session_requirements;
  std::vector<pdv> user_data;
};

struct refuse_ppdu {  // CPR-PPDU, normal mode
  std::optional<std::uint32_t> protocol_version;
  byte_view responding_selector;
  std::vector<context_result> results;
  std::optional<context_result_code> default_context_result;
  std::optional<std::uint8_t> provider_reason;  // provider_reason; absent = user rejection
  std::vector<pdv> user_data;
};

struct user_abort_ppdu {  // ARU-PPDU, normal mode
  std::vector<context_identifier> context_ids;
  std::vector<pdv> user_data;
};

struct provider_abort_ppdu {  // ARP-PPDU
  std::optional<std::uint8_t> reason;  // abort_reason
  std::optional<std::uint8_t> event;   // event_id
};

using abort_ppdu = std::variant<user_abort_ppdu, provider_abort_ppdu>;

// Decoders take the complete user data of the carrying session primitive; trailing octets are
// rejected. x410-mode PPDUs and simply-encoded-data fail with errc::unsupported.
[[nodiscard]] result<connect_ppdu> decode_connect(byte_view data);   // S-CONNECT request
[[nodiscard]] result<accept_ppdu> decode_accept(byte_view data);     // S-CONNECT response +
[[nodiscard]] result<refuse_ppdu> decode_refuse(byte_view data);     // S-CONNECT response -
[[nodiscard]] result<abort_ppdu> decode_abort(byte_view data);       // S-U-ABORT
// User-data (TD-PPDU, S-RELEASE). The PDVs are appended to `out`, which is cleared first.
[[nodiscard]] result<void> decode_user_data(byte_view data, std::vector<pdv>& out);

// Each encoder appends one PPDU to `out`; on error `out` is left unchanged. Empty user data is
// omitted, except by encode_user_data, which requires at least one PDV.
[[nodiscard]] result<void> encode(const connect_ppdu& p, byte_buffer& out);
[[nodiscard]] result<void> encode(const accept_ppdu& p, byte_buffer& out);
[[nodiscard]] result<void> encode(const refuse_ppdu& p, byte_buffer& out);
[[nodiscard]] result<void> encode(const user_abort_ppdu& p, byte_buffer& out);
[[nodiscard]] result<void> encode(const provider_abort_ppdu& p, byte_buffer& out);
[[nodiscard]] result<void> encode_user_data(std::span<const pdv> pdvs, byte_buffer& out);

}  // namespace openiec61850::iso::presentation
