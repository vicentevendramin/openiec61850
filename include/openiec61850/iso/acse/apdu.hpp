#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <variant>
#include <vector>

#include "openiec61850/ber/decode.hpp"
#include "openiec61850/ber/oid.hpp"
#include "openiec61850/core/bytes.hpp"
#include "openiec61850/core/result.hpp"

// ACSE APDU codec (ISO/IEC 8650-1 = ITU-T X.227, module ACSE-1, explicit tagging environment).
// APDUs are encoded as standalone BER values; they travel as single-ASN1-type PDVs of the ACSE
// presentation context (abstract syntax {2 2 1 0 1}).
//
// Tags used (X.227 §9 / annex A; "E" = explicit tag around the type, "I" = implicit):
//
//   AARQ [APPLICATION 0]                    AARE [APPLICATION 1]
//     [0]  I protocol-version BIT STRING      [0]  I protocol-version BIT STRING
//     [1]  E application-context-name OID     [1]  E application-context-name OID
//     [2]  E called-AP-title                  [2]  E result INTEGER
//     [3]  E called-AE-qualifier              [3]  E result-source-diagnostic CHOICE
//     [4]  E called-AP-invocation-id INTEGER        { acse-service-user [1] E INTEGER,
//     [5]  E called-AE-invocation-id INTEGER          acse-service-provider [2] E INTEGER }
//     [6]  E calling-AP-title                 [4]  E responding-AP-title
//     [7]  E calling-AE-qualifier             [5]  E responding-AE-qualifier
//     [8]  E calling-AP-invocation-id         [6]  E responding-AP-invocation-id
//     [9]  E calling-AE-invocation-id         [7]  E responding-AE-invocation-id
//     [10] I sender-acse-requirements         [8]  I responder-acse-requirements
//     [11] I mechanism-name OID               [9]  I mechanism-name OID
//     [12] E calling-authentication-value     [10] E responding-authentication-value
//     [13] I application-context-name-list    [11] I application-context-name-list
//     [29] I implementation-information       [29] I implementation-information
//     [30] I user-information                 [30] I user-information
//
//   RLRQ [APPLICATION 2] { [0] I reason INTEGER, [30] I user-information }
//   RLRE [APPLICATION 3] { [0] I reason INTEGER, [30] I user-information }
//   ABRT [APPLICATION 4] { [0] I abort-source INTEGER, [1] I abort-diagnostic ENUMERATED,
//                          [30] I user-information }
//
//   AP-title     ::= CHOICE { form1 Name, form2 OBJECT IDENTIFIER, ..., form3 PrintableString }
//   AE-qualifier ::= CHOICE { form1 RelativeDistinguishedName, form2 INTEGER, ..., form3 ... }
//   Authentication-value ::= CHOICE { charstring [0] I GraphicString, bitstring [1] I BIT STRING,
//                                     external [2] I EXTERNAL, other [3] I SEQUENCE {
//                                     other-mechanism-name OID, other-mechanism-value ANY } }
//   Association-information ::= SEQUENCE SIZE (1..MAX) OF EXTERNAL
//   EXTERNAL (X.690 §8.18) ::= [UNIVERSAL 8] I SEQUENCE { direct-reference OID OPTIONAL,
//       indirect-reference INTEGER OPTIONAL, data-value-descriptor ObjectDescriptor OPTIONAL,
//       encoding CHOICE { single-ASN1-type [0] E ANY, octet-aligned [1] I OCTET STRING,
//                         arbitrary [2] I BIT STRING } }
//
// Decoding is lenient where X.227 is extensible: unknown elements inside an APDU (later-edition
// fields such as the ASO-related ones) are skipped, and AP-title/AE-qualifier forms other than
// form 2 are kept as raw encodings. Known fields must appear in ascending tag order, at most once.
// The A-DT, ACRQ and ACRP APDUs ([APPLICATION 5..7]) are rejected with errc::unsupported.
//
// All views in decoded APDUs point into the decoded buffer. Encoders read the views of the
// structures they are given; they produce minimal definite-length encodings and leave `out`
// unchanged on error (errc::invalid_state for an invalid OID or a malformed raw field).
namespace openiec61850::iso::acse {

namespace oids {
inline constexpr ber::oid acse_abstract_syntax{2, 2, 1, 0, 1};       // X.227 annex A
inline constexpr ber::oid ber_transfer_syntax{2, 1, 1};              // X.690 basic encoding
inline constexpr ber::oid mms_abstract_syntax{1, 0, 9506, 2, 1};     // ISO 9506-2 mms-abstract-syntax-version1
inline constexpr ber::oid mms_application_context{1, 0, 9506, 2, 3}; // IEC 61850-8-1 / ISO 9506-2
inline constexpr ber::oid password_mechanism{2, 2, 3, 1};            // X.227 annex B
}  // namespace oids

// Named bits of BIT STRINGs, as masks: bit n of the BIT STRING is (1u << n).
namespace protocol_version {
inline constexpr std::uint32_t version1 = 1U << 0;
}
namespace acse_requirements {
inline constexpr std::uint32_t authentication = 1U << 0;
inline constexpr std::uint32_t application_context_negotiation = 1U << 1;
inline constexpr std::uint32_t higher_level_association = 1U << 2;
inline constexpr std::uint32_t nested_association = 1U << 3;
}  // namespace acse_requirements

namespace associate_result {
inline constexpr std::int64_t accepted = 0;
inline constexpr std::int64_t rejected_permanent = 1;
inline constexpr std::int64_t rejected_transient = 2;
}  // namespace associate_result

// Reasons of Associate-source-diagnostic.
namespace service_user_diagnostic {
inline constexpr std::int64_t null = 0;
inline constexpr std::int64_t no_reason_given = 1;
inline constexpr std::int64_t application_context_name_not_supported = 2;
inline constexpr std::int64_t calling_ap_title_not_recognized = 3;
inline constexpr std::int64_t calling_ap_invocation_id_not_recognized = 4;
inline constexpr std::int64_t calling_ae_qualifier_not_recognized = 5;
inline constexpr std::int64_t calling_ae_invocation_id_not_recognized = 6;
inline constexpr std::int64_t called_ap_title_not_recognized = 7;
inline constexpr std::int64_t called_ap_invocation_id_not_recognized = 8;
inline constexpr std::int64_t called_ae_qualifier_not_recognized = 9;
inline constexpr std::int64_t called_ae_invocation_id_not_recognized = 10;
inline constexpr std::int64_t authentication_mechanism_name_not_recognized = 11;
inline constexpr std::int64_t authentication_mechanism_name_required = 12;
inline constexpr std::int64_t authentication_failure = 13;
inline constexpr std::int64_t authentication_required = 14;
}  // namespace service_user_diagnostic
namespace service_provider_diagnostic {
inline constexpr std::int64_t null = 0;
inline constexpr std::int64_t no_reason_given = 1;
inline constexpr std::int64_t no_common_acse_version = 2;
}  // namespace service_provider_diagnostic

namespace release_request_reason {
inline constexpr std::int64_t normal = 0;
inline constexpr std::int64_t urgent = 1;
inline constexpr std::int64_t user_defined = 30;
}  // namespace release_request_reason
namespace release_response_reason {
inline constexpr std::int64_t normal = 0;
inline constexpr std::int64_t not_finished = 1;
inline constexpr std::int64_t user_defined = 30;
}  // namespace release_response_reason

namespace abort_source {
inline constexpr std::int64_t service_user = 0;
inline constexpr std::int64_t service_provider = 1;
}  // namespace abort_source
namespace abort_diagnostic {
inline constexpr std::int64_t no_reason_given = 1;
inline constexpr std::int64_t protocol_error = 2;
inline constexpr std::int64_t authentication_mechanism_name_not_recognized = 3;
inline constexpr std::int64_t authentication_mechanism_name_required = 4;
inline constexpr std::int64_t authentication_failure = 5;
inline constexpr std::int64_t authentication_required = 6;
}  // namespace abort_diagnostic

// A CHOICE alternative kept undecoded: the complete TLV of the alternative.
struct raw_form {
  byte_view encoding;
};

// Form 2 is decoded; forms 1 and 3 (and future ones) are kept raw.
using ap_title = std::variant<ber::oid, raw_form>;
using ae_qualifier = std::variant<std::int64_t, raw_form>;

enum class external_encoding : std::uint8_t { single_asn1_type, octet_aligned, arbitrary };

// EXTERNAL, X.690 §8.18. `data` is the complete TLV of the value for single-ASN1-type, the
// contents of the OCTET STRING for octet-aligned, and the data octets of the BIT STRING for
// arbitrary (with `bit_count` bits).
struct external {
  std::optional<ber::oid> direct_reference;        // transfer syntax name
  std::optional<std::int64_t> indirect_reference;  // presentation context identifier
  std::optional<std::string_view> data_value_descriptor;
  external_encoding encoding = external_encoding::single_asn1_type;
  byte_view data;
  std::size_t bit_count = 0;
};

// Association-information. Empty means absent (the type has SIZE (1..MAX)).
using user_information = std::vector<external>;

struct auth_charstring {
  std::string_view value;  // GraphicString, e.g. the password of the {2 2 3 1} mechanism
};
struct auth_bitstring {
  byte_view bytes;
  std::size_t bit_count = 0;
};
struct auth_external {
  external value;
};
struct auth_other {
  ber::oid mechanism;
  byte_view value;  // complete TLV of other-mechanism-value
};
using authentication_value = std::variant<auth_charstring, auth_bitstring, auth_external, auth_other>;

// BIT STRING fields are masks of named bits (see above). Bits beyond 31 are ignored on decoding.
struct aarq_apdu {
  std::optional<std::uint32_t> protocol_version;  // absent = DEFAULT {version1}
  ber::oid application_context_name;
  std::optional<ap_title> called_ap_title;
  std::optional<ae_qualifier> called_ae_qualifier;
  std::optional<std::int64_t> called_ap_invocation_id;
  std::optional<std::int64_t> called_ae_invocation_id;
  std::optional<ap_title> calling_ap_title;
  std::optional<ae_qualifier> calling_ae_qualifier;
  std::optional<std::int64_t> calling_ap_invocation_id;
  std::optional<std::int64_t> calling_ae_invocation_id;
  std::optional<std::uint32_t> acse_requirements;
  std::optional<ber::oid> mechanism_name;
  std::optional<authentication_value> authentication;
  byte_view application_context_name_list;  // contents (SEQUENCE OF OID) kept raw; empty = absent
  std::optional<std::string_view> implementation_information;
  acse::user_information user_information;
};

enum class diagnostic_source : std::uint8_t { service_user = 1, service_provider = 2 };

struct associate_source_diagnostic {
  diagnostic_source source = diagnostic_source::service_user;
  std::int64_t reason = service_user_diagnostic::null;
};

struct aare_apdu {
  std::optional<std::uint32_t> protocol_version;
  ber::oid application_context_name;
  std::int64_t result = associate_result::accepted;
  associate_source_diagnostic result_source_diagnostic;
  std::optional<ap_title> responding_ap_title;
  std::optional<ae_qualifier> responding_ae_qualifier;
  std::optional<std::int64_t> responding_ap_invocation_id;
  std::optional<std::int64_t> responding_ae_invocation_id;
  std::optional<std::uint32_t> acse_requirements;
  std::optional<ber::oid> mechanism_name;
  std::optional<authentication_value> authentication;
  byte_view application_context_name_list;
  std::optional<std::string_view> implementation_information;
  acse::user_information user_information;
};

struct rlrq_apdu {
  std::optional<std::int64_t> reason;
  acse::user_information user_information;
};

struct rlre_apdu {
  std::optional<std::int64_t> reason;
  acse::user_information user_information;
};

struct abrt_apdu {
  std::int64_t source = abort_source::service_user;
  std::optional<std::int64_t> diagnostic;
  acse::user_information user_information;
};

using apdu = std::variant<aarq_apdu, aare_apdu, rlrq_apdu, rlre_apdu, abrt_apdu>;

// Decodes exactly one APDU; trailing data is errc::malformed_encoding.
[[nodiscard]] result<apdu> decode(byte_view data, const ber::decode_options& opts = {});

// Each encoder appends one complete APDU to `out`.
[[nodiscard]] result<void> encode(const aarq_apdu& a, byte_buffer& out);
[[nodiscard]] result<void> encode(const aare_apdu& a, byte_buffer& out);
[[nodiscard]] result<void> encode(const rlrq_apdu& a, byte_buffer& out);
[[nodiscard]] result<void> encode(const rlre_apdu& a, byte_buffer& out);
[[nodiscard]] result<void> encode(const abrt_apdu& a, byte_buffer& out);
[[nodiscard]] result<void> encode(const apdu& a, byte_buffer& out);

// The first EXTERNAL of `info` whose indirect-reference is `context_id`, or nullptr.
[[nodiscard]] const external* find_by_context(std::span<const external> info,
                                              std::int64_t context_id) noexcept;

// An EXTERNAL carrying `value` (one complete BER TLV) as single-ASN1-type in presentation
// context `context_id`, without direct-reference (the transfer syntax is the context's one).
[[nodiscard]] external single_asn1_external(std::int64_t context_id, byte_view value);

// IEC 61850-8-1 style association (MMS application context, ISO 9506-2 / IEC 61850-8-1 §10).
// The returned APDU points into `p`'s views (password, initiate PDU, raw titles).
struct mms_aarq_params {
  std::optional<ap_title> called_ap_title;
  std::optional<ae_qualifier> called_ae_qualifier;
  std::optional<ap_title> calling_ap_title;
  std::optional<ae_qualifier> calling_ae_qualifier;
  // When set: acse-requirements {authentication}, mechanism {2 2 3 1} and a charstring value.
  std::optional<std::string_view> password;
  std::int64_t mms_context_id = 3;  // presentation context identifier of mms-abstract-syntax
  byte_view initiate_request;       // encoded MMS Initiate-RequestPDU
};
[[nodiscard]] aarq_apdu make_mms_aarq(const mms_aarq_params& p);

// AARE accepting an MMS association (result-source-diagnostic acse-service-user null).
[[nodiscard]] aare_apdu make_mms_aare(std::int64_t mms_context_id, byte_view initiate_response);

}  // namespace openiec61850::iso::acse
