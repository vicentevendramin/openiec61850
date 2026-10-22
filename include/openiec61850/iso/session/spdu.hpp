#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <variant>

#include "openiec61850/core/bytes.hpp"
#include "openiec61850/core/result.hpp"

// ISO session protocol (ISO/IEC 8327-1 = ITU-T X.225) SPDU codec: the kernel and duplex functional
// units, versions 1 and 2, basic concatenation only. The codec works on complete TSDUs.
namespace openiec61850::iso::session {

// SPDU identifiers, X.225 §8.3 (table 9). GT and DT share the code 1 and are told apart by their
// position in the TSDU: GT is category 0 (first SPDU), DT is category 2 (always concatenated after a
// category 0 SPDU). All other SPDUs below are category 1 and are mapped one-to-one onto a TSDU.
namespace si {
inline constexpr std::uint8_t give_tokens = 1;     // GT, category 0
inline constexpr std::uint8_t please_tokens = 2;   // PT, category 0
inline constexpr std::uint8_t data_transfer = 1;   // DT, category 2
inline constexpr std::uint8_t not_finished = 8;    // NF
inline constexpr std::uint8_t finish = 9;          // FN
inline constexpr std::uint8_t disconnect = 10;     // DN
inline constexpr std::uint8_t refuse = 12;         // RF
inline constexpr std::uint8_t connect = 13;        // CN
inline constexpr std::uint8_t accept = 14;         // AC
inline constexpr std::uint8_t abort = 25;          // AB
inline constexpr std::uint8_t abort_accept = 26;   // AA
}  // namespace si

// Parameter (PI) and parameter group (PGI) codes, X.225 §8.3.
namespace pi {
inline constexpr std::uint8_t connection_identifier = 1;   // PGI
inline constexpr std::uint8_t connect_accept_item = 5;     // PGI
inline constexpr std::uint8_t called_ss_user_reference = 9;
inline constexpr std::uint8_t calling_ss_user_reference = 10;
inline constexpr std::uint8_t common_reference = 11;
inline constexpr std::uint8_t additional_reference = 12;
inline constexpr std::uint8_t token_item = 16;
inline constexpr std::uint8_t transport_disconnect = 17;
inline constexpr std::uint8_t protocol_options = 19;
inline constexpr std::uint8_t session_user_requirements = 20;
inline constexpr std::uint8_t tsdu_maximum_size = 21;
inline constexpr std::uint8_t version_number = 22;
inline constexpr std::uint8_t initial_serial_number = 23;
inline constexpr std::uint8_t enclosure_item = 25;
inline constexpr std::uint8_t token_setting_item = 26;
inline constexpr std::uint8_t reflect_parameter_values = 49;
inline constexpr std::uint8_t reason_code = 50;
inline constexpr std::uint8_t calling_session_selector = 51;
inline constexpr std::uint8_t called_session_selector = 52;  // "responding" in AC
inline constexpr std::uint8_t responding_session_selector = 52;
inline constexpr std::uint8_t data_overflow = 60;
inline constexpr std::uint8_t user_data = 193;              // PGI
inline constexpr std::uint8_t extended_user_data = 194;     // PGI
}  // namespace pi

// Version Number PV bits, X.225 §8.3.1 (CN).
inline constexpr std::uint8_t version_1 = 0x01;
inline constexpr std::uint8_t version_2 = 0x02;

// Session User Requirements PV bits (functional units), X.225 §8.3.1 (CN). The kernel is implicit.
namespace fu {
inline constexpr std::uint16_t half_duplex = 0x0001;
inline constexpr std::uint16_t duplex = 0x0002;
inline constexpr std::uint16_t expedited_data = 0x0004;
inline constexpr std::uint16_t minor_synchronize = 0x0008;
inline constexpr std::uint16_t major_synchronize = 0x0010;
inline constexpr std::uint16_t resynchronize = 0x0020;
inline constexpr std::uint16_t activity_management = 0x0040;
inline constexpr std::uint16_t negotiated_release = 0x0080;
inline constexpr std::uint16_t capability_data = 0x0100;
inline constexpr std::uint16_t exceptions = 0x0200;
inline constexpr std::uint16_t typed_data = 0x0400;
inline constexpr std::uint16_t symmetric_synchronize = 0x0800;
inline constexpr std::uint16_t data_separation = 0x1000;
// Value assumed when the parameter is absent from CN/AC.
inline constexpr std::uint16_t default_requirements =
    half_duplex | minor_synchronize | activity_management | capability_data | exceptions;
}  // namespace fu

// Transport Disconnect PV bits, X.225 §8.3.5-§8.3.6 (RF, FN) and §8.3.9 (AB).
namespace transport_disconnect {
inline constexpr std::uint8_t released = 0x01;  // 0 = the transport connection is kept
inline constexpr std::uint8_t user_abort = 0x02;
inline constexpr std::uint8_t protocol_error = 0x04;
inline constexpr std::uint8_t no_reason = 0x08;
inline constexpr std::uint8_t implementation_restriction = 0x10;
}  // namespace transport_disconnect

// Enclosure Item PV bits (version 2). Segmenting is not supported: only "complete" is accepted.
namespace enclosure {
inline constexpr std::uint8_t beginning = 0x01;
inline constexpr std::uint8_t end = 0x02;
inline constexpr std::uint8_t complete = beginning | end;
}  // namespace enclosure

// Reason Code PV values of RF, X.225 §8.3.5.
namespace refuse_reason {
inline constexpr std::uint8_t not_specified = 0;
inline constexpr std::uint8_t temporary_congestion = 1;
inline constexpr std::uint8_t rejected_by_user = 2;  // followed by SS-user data
inline constexpr std::uint8_t selector_unknown = 128 + 1;
inline constexpr std::uint8_t user_not_attached = 128 + 2;
inline constexpr std::uint8_t spm_congestion = 128 + 3;
inline constexpr std::uint8_t version_not_supported = 128 + 4;
inline constexpr std::uint8_t spm_not_specified = 128 + 5;
inline constexpr std::uint8_t implementation_restriction = 128 + 6;
}  // namespace refuse_reason

// User data limits, X.225 §8.3.1: CN User Data (PGI 193) up to 512 octets; Extended User Data
// (PGI 194, version 2 only) up to 10240 octets. Larger CN user data needs CDO/OA (not supported).
inline constexpr std::size_t max_connect_user_data = 512;
inline constexpr std::size_t max_connect_extended_user_data = 10240;
// Largest value an LI field can carry (§8.2.5).
inline constexpr std::size_t max_li = 65535;

// All byte_view members of decoded SPDUs point into the decoded TSDU. An empty view means the
// parameter is absent (or present with zero length); encoders omit empty views.

// Connection Identifier PGI. In CN the SS-user reference is the calling one (PI 10); in AC/RF it is
// the called one (PI 9).
struct connection_identifier {
  byte_view ss_user_reference;     // ≤ 64 octets
  byte_view common_reference;      // ≤ 64 octets
  byte_view additional_reference;  // ≤ 4 octets
};

// TSDU Maximum Size PV: two 16-bit sizes; 0 means "no limit" in that direction.
struct tsdu_maximum_size {
  std::uint16_t initiator_to_responder = 0;
  std::uint16_t responder_to_initiator = 0;
};

struct connect_spdu {  // CN, X.225 §8.3.1
  std::optional<connection_identifier> connection_id;
  // Connect/Accept Item PGI. When the whole PGI is absent the decoder reports version 1.
  std::uint8_t protocol_options = 0;
  std::optional<tsdu_maximum_size> tsdu_max_size;
  std::uint8_t version_number = version_2;
  byte_view initial_serial_number;
  std::optional<std::uint8_t> token_setting;
  std::uint16_t session_requirements = fu::duplex;
  byte_view calling_selector;  // ≤ 16 octets
  byte_view called_selector;   // ≤ 16 octets
  std::optional<std::uint8_t> data_overflow;
  byte_view user_data;  // PGI 193, or PGI 194 when > 512 octets (version 2)
};

struct accept_spdu {  // AC, X.225 §8.3.4
  std::optional<connection_identifier> connection_id;
  std::uint8_t protocol_options = 0;
  std::optional<tsdu_maximum_size> tsdu_max_size;
  std::uint8_t version_number = version_2;  // exactly one bit: the selected version
  byte_view initial_serial_number;
  std::optional<std::uint8_t> token_setting;
  std::optional<std::uint8_t> token_item;
  std::uint16_t session_requirements = fu::duplex;
  std::optional<std::uint8_t> enclosure;
  byte_view calling_selector;
  byte_view responding_selector;
  byte_view user_data;
};

struct refuse_spdu {  // RF, X.225 §8.3.5
  std::optional<connection_identifier> connection_id;
  std::optional<std::uint8_t> transport_disconnect;
  std::optional<std::uint16_t> session_requirements;
  std::optional<std::uint8_t> version_number;
  std::optional<std::uint8_t> enclosure;
  std::uint8_t reason = refuse_reason::not_specified;
  byte_view user_data;  // carried inside the Reason Code PV after the reason octet
};

struct finish_spdu {  // FN, X.225 §8.3.6
  std::optional<std::uint8_t> transport_disconnect;
  std::optional<std::uint8_t> enclosure;
  byte_view user_data;
};

struct disconnect_spdu {  // DN, X.225 §8.3.7
  std::optional<std::uint8_t> enclosure;
  byte_view user_data;
};

struct not_finished_spdu {  // NF, X.225 §8.3.8
  std::optional<std::uint8_t> enclosure;
  byte_view user_data;
};

struct abort_spdu {  // AB, X.225 §8.3.9
  std::optional<std::uint8_t> transport_disconnect;
  std::optional<std::uint8_t> enclosure;
  byte_view reflect_parameter;  // ≤ 9 octets
  byte_view user_data;
};

struct abort_accept_spdu {};  // AA, X.225 §8.3.10: no parameters

struct give_tokens_spdu {  // GT sent alone (category 0 mapped one-to-one), X.225 §8.3.16
  std::optional<std::uint8_t> token_item;
};

// A data TSDU: an empty GT (category 0) concatenated with DT (category 2) and its user
// information field (basic concatenation), X.225 §8.3.11.
struct data_transfer_spdu {
  std::optional<std::uint8_t> enclosure;
  byte_view user_information;
};

using spdu = std::variant<connect_spdu, accept_spdu, refuse_spdu, finish_spdu, disconnect_spdu,
                          not_finished_spdu, abort_spdu, abort_accept_spdu, give_tokens_spdu,
                          data_transfer_spdu>;

// Decodes one complete TSDU. Unknown parameters are skipped; duplicate or ill-sized known parameters,
// unknown SPDU identifiers, trailing octets and unsupported concatenations are rejected.
[[nodiscard]] result<spdu> decode_tsdu(byte_view tsdu);

// Each encoder appends one complete TSDU to `out`. On error `out` is left unchanged.
[[nodiscard]] result<void> encode(const connect_spdu& s, byte_buffer& out);
[[nodiscard]] result<void> encode(const accept_spdu& s, byte_buffer& out);
[[nodiscard]] result<void> encode(const refuse_spdu& s, byte_buffer& out);
[[nodiscard]] result<void> encode(const finish_spdu& s, byte_buffer& out);
[[nodiscard]] result<void> encode(const disconnect_spdu& s, byte_buffer& out);
[[nodiscard]] result<void> encode(const not_finished_spdu& s, byte_buffer& out);
[[nodiscard]] result<void> encode(const abort_spdu& s, byte_buffer& out);
[[nodiscard]] result<void> encode(const abort_accept_spdu& s, byte_buffer& out);
[[nodiscard]] result<void> encode(const give_tokens_spdu& s, byte_buffer& out);
[[nodiscard]] result<void> encode(const data_transfer_spdu& s, byte_buffer& out);
[[nodiscard]] result<void> encode(const spdu& s, byte_buffer& out);

// Fast path for the data phase: appends GT(empty) + DT(empty) + user information (4 + n octets).
void encode_data_tsdu(byte_view user_information, byte_buffer& out);

}  // namespace openiec61850::iso::session
