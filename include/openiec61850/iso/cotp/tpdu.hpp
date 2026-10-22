#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <variant>
#include <vector>

#include "openiec61850/core/bytes.hpp"
#include "openiec61850/core/result.hpp"

namespace openiec61850::iso::cotp {

// TPDU codes, X.224 §13.1 table 8 (high nibble; CR/CC carry CDT in the low nibble).
enum class tpdu_kind : std::uint8_t {
  cr = 0xE0,  // connection request
  cc = 0xD0,  // connection confirm
  dr = 0x80,  // disconnect request
  dc = 0xC0,  // disconnect confirm (not used in class 0)
  dt = 0xF0,  // data
  ed = 0x10,  // expedited data (not used in class 0)
  ak = 0x60,  // data acknowledgement (not used in class 0)
  ea = 0x20,  // expedited data acknowledgement (not used in class 0)
  rj = 0x50,  // reject (not used in class 0)
  er = 0x70,  // TPDU error
};

// Returns the kind for a TPDU code octet, or std::nullopt for an unassigned code.
[[nodiscard]] std::optional<tpdu_kind> tpdu_kind_of(std::uint8_t code) noexcept;

// Parameter codes of the variable part, X.224 §13.3.4 and §13.12.4.
namespace parameter_code {
inline constexpr std::uint8_t tpdu_size = 0xC0;
inline constexpr std::uint8_t calling_tsap = 0xC1;
inline constexpr std::uint8_t called_tsap = 0xC2;
inline constexpr std::uint8_t invalid_tpdu = 0xC1;  // ER only
inline constexpr std::uint8_t additional_information = 0xE0;  // DR only
}  // namespace parameter_code

// TPDU size, X.224 §13.3.4 b): code 7..13 means 2^code octets (128..8192).
// Class 0 only allows up to 2048 octets; 128 applies when the parameter is absent.
inline constexpr std::size_t default_tpdu_size = 128;
inline constexpr std::size_t class0_max_tpdu_size = 2048;
[[nodiscard]] std::optional<std::size_t> tpdu_size_from_code(std::uint8_t code) noexcept;
[[nodiscard]] std::optional<std::uint8_t> tpdu_size_code(std::size_t size) noexcept;

// DR reason, X.224 §13.5.3 d).
namespace disconnect_reason {
inline constexpr std::uint8_t not_specified = 0;
inline constexpr std::uint8_t congestion_at_tsap = 1;
inline constexpr std::uint8_t session_entity_not_attached = 2;
inline constexpr std::uint8_t address_unknown = 3;
inline constexpr std::uint8_t normal = 128;
inline constexpr std::uint8_t remote_congestion = 129;
inline constexpr std::uint8_t negotiation_failed = 130;
inline constexpr std::uint8_t duplicate_reference = 131;
inline constexpr std::uint8_t mismatched_references = 132;
inline constexpr std::uint8_t protocol_error = 133;
inline constexpr std::uint8_t reference_overflow = 135;
inline constexpr std::uint8_t refused = 136;
inline constexpr std::uint8_t invalid_length = 138;
}  // namespace disconnect_reason

// ER reject cause, X.224 §13.12.3 c).
namespace reject_cause {
inline constexpr std::uint8_t not_specified = 0;
inline constexpr std::uint8_t invalid_parameter_code = 1;
inline constexpr std::uint8_t invalid_tpdu_type = 2;
inline constexpr std::uint8_t invalid_parameter_value = 3;
}  // namespace reject_cause

// A variable-part parameter the codec does not interpret; kept so it survives a round trip.
struct tpdu_parameter {
  std::uint8_t code = 0;
  byte_buffer value;

  friend bool operator==(const tpdu_parameter&, const tpdu_parameter&) = default;
};

// CR and CC share their layout, X.224 §13.3 and §13.4.
struct connect_tpdu {
  std::uint8_t credit = 0;  // CDT, always 0 in class 0
  std::uint16_t dst_ref = 0;
  std::uint16_t src_ref = 0;
  std::uint8_t class_options = 0;  // class in the high nibble, options in the low nibble
  std::optional<std::uint8_t> tpdu_size;  // size code (see tpdu_size_from_code)
  std::optional<byte_buffer> calling_tsap;
  std::optional<byte_buffer> called_tsap;
  std::vector<tpdu_parameter> other_parameters;
  byte_buffer user_data;  // not permitted in class 0

  [[nodiscard]] std::uint8_t protocol_class() const noexcept {
    return static_cast<std::uint8_t>(class_options >> 4);
  }

  friend bool operator==(const connect_tpdu&, const connect_tpdu&) = default;
};

struct connection_request : connect_tpdu {
  friend bool operator==(const connection_request&, const connection_request&) = default;
};
struct connection_confirm : connect_tpdu {
  friend bool operator==(const connection_confirm&, const connection_confirm&) = default;
};

// X.224 §13.5.
struct disconnect_request {
  std::uint16_t dst_ref = 0;
  std::uint16_t src_ref = 0;
  std::uint8_t reason = disconnect_reason::not_specified;
  std::vector<tpdu_parameter> parameters;
  byte_buffer user_data;

  friend bool operator==(const disconnect_request&, const disconnect_request&) = default;
};

// Normal-format DT for classes 0 and 1, X.224 §13.7. user_data views the decoded input.
struct data_tpdu {
  bool eot = true;
  std::uint8_t nr = 0;  // TPDU-NR, not significant in class 0
  byte_view user_data;
};

// X.224 §13.12.
struct error_tpdu {
  std::uint16_t dst_ref = 0;
  std::uint8_t cause = reject_cause::not_specified;
  std::optional<byte_buffer> invalid_tpdu;
  std::vector<tpdu_parameter> other_parameters;

  friend bool operator==(const error_tpdu&, const error_tpdu&) = default;
};

using tpdu = std::variant<connection_request, connection_confirm, disconnect_request, data_tpdu,
                          error_tpdu>;

// Size of a class 0 DT header (LI, code, EOT/TPDU-NR).
inline constexpr std::size_t dt_header_size = 3;

// Decodes one TPDU occupying the whole input (a TPKT payload).
// errc::malformed_encoding: unassigned code or invalid field; errc::unsupported: a TPDU
// type that class 0 does not use; errc::length_overflow: LI or a parameter runs past
// the input; errc::truncated_input: input shorter than a header.
[[nodiscard]] result<tpdu> decode_tpdu(byte_view in);

// Append the encoding of a TPDU to out. On error, out is left unchanged.
[[nodiscard]] result<void> encode(const connection_request& t, byte_buffer& out);
[[nodiscard]] result<void> encode(const connection_confirm& t, byte_buffer& out);
[[nodiscard]] result<void> encode(const disconnect_request& t, byte_buffer& out);
[[nodiscard]] result<void> encode(const data_tpdu& t, byte_buffer& out);
[[nodiscard]] result<void> encode(const error_tpdu& t, byte_buffer& out);
[[nodiscard]] result<void> encode(const tpdu& t, byte_buffer& out);

// Appends a TPKT carrying the encoded TPDU.
[[nodiscard]] result<void> encode_tpkt(const tpdu& t, byte_buffer& out);

}  // namespace openiec61850::iso::cotp
