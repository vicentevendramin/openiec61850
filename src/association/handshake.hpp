#pragma once

// Sans-I/O pieces of association establishment shared by both roles (and the fuzzer).

#include <cstdint>
#include <optional>
#include <system_error>

#include "openiec61850/association/client_association.hpp"
#include "openiec61850/association/server_association.hpp"
#include "openiec61850/association/types.hpp"
#include "openiec61850/core/bytes.hpp"
#include "openiec61850/core/result.hpp"
#include "openiec61850/iso/acse/apdu.hpp"
#include "openiec61850/iso/presentation/connection.hpp"
#include "openiec61850/mms/pdu.hpp"

namespace openiec61850::association::detail {

namespace ps = iso::presentation;
namespace acse = iso::acse;

[[nodiscard]] result<byte_buffer> encode_mms(const mms::mms_pdu& pdu);
[[nodiscard]] result<byte_buffer> encode_acse(const acse::apdu& apdu);

// The negotiated parameters as seen by both sides (values above the proposal are clamped).
[[nodiscard]] negotiated_parameters to_negotiated(const mms::initiate_request& proposed,
                                                  const mms::initiate_response& response) noexcept;

// --- Initiator

[[nodiscard]] ps::connection_options initiator_options(const association_params& p);
// The AARQ APDU carrying the Initiate-RequestPDU (IEC 61850-8-1 §10 / ISO 9506-2 annex).
[[nodiscard]] result<byte_buffer> encode_aarq(const association_params& p);
// Appends the CP TSDU (S-CONNECT carrying CP(AARQ)) to `out`.
[[nodiscard]] result<void> connect_request(ps::connection& pc, const association_params& p,
                                           byte_buffer& out);

struct associate_response {
  std::error_code error;  // empty: accepted
  negotiated_parameters negotiated;
  std::optional<ber::oid> responding_ap_title;
  std::optional<std::int64_t> responding_ae_qualifier;
  std::optional<service_error_info> initiate_error;
};

// Interprets the presentation event that answers the CP.
[[nodiscard]] associate_response parse_associate_response(const ps::event& ev,
                                                          const mms::initiate_request& proposed,
                                                          const mms::decode_options& opts);

// --- Responder

[[nodiscard]] ps::connection_options responder_options(const server_options& o);

struct associate_indication {
  std::optional<std::uint32_t> acse_context;  // accepted ACSE context, if any
  std::optional<std::uint32_t> mms_context;   // accepted MMS context, if any
  std::optional<association_request> request;
  // Why the AARQ cannot be accepted when !request (acse service-user diagnostic).
  std::int64_t diagnostic = acse::service_user_diagnostic::no_reason_given;
  bool initiate_failed = false;  // AARQ fine, Initiate-RequestPDU missing or undecodable
};

[[nodiscard]] associate_indication parse_associate_request(const ps::connect_indication& ind,
                                                           const mms::decode_options& opts);

// CPA(AARE accepted(Initiate-ResponsePDU)).
[[nodiscard]] result<void> accept_association(ps::connection& pc, const associate_indication& ind,
                                              const server_options& o,
                                              const mms::initiate_response& negotiated,
                                              byte_buffer& out);
// CPR(AARE rejected-permanent[, Initiate-ErrorPDU]); a bare CPR without an ACSE context.
[[nodiscard]] result<void> refuse_association(ps::connection& pc, const associate_indication& ind,
                                              const server_options& o, std::int64_t diagnostic,
                                              byte_buffer& out);

}  // namespace openiec61850::association::detail
