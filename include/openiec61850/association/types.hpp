#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <system_error>
#include <utility>
#include <variant>

#include <asio/awaitable.hpp>
#include <asio/ip/tcp.hpp>

#include "openiec61850/association/error.hpp"
#include "openiec61850/ber/oid.hpp"
#include "openiec61850/transport/tls.hpp"
#include "openiec61850/core/bytes.hpp"
#include "openiec61850/core/result.hpp"
#include "openiec61850/mms/pdu.hpp"

namespace openiec61850::association {

// Presentation context identifiers proposed by the initiator (IEC 61850-8-1 profile).
inline constexpr std::uint32_t acse_context_id = 1;
inline constexpr std::uint32_t mms_context_id = 3;

// AP-title and AE-qualifier commonly configured for IEC 61850 clients and servers when none is
// given; they only identify the application entity (X.227 §7.1.1, form 2).
inline constexpr ber::oid default_ap_title{1, 1, 999, 1};
inline constexpr std::int64_t default_ae_qualifier = 12;

enum class association_state : std::uint8_t {
  established,  // requests may be issued
  releasing,    // release() in progress (client) or Conclude accepted (server)
  closed,       // released, aborted or lost; see wait_closed()
};

// A decoded MMS PDU that owns the bytes it views. Decoded PDUs are zero-copy views into the
// received TSDU (mms/pdu.hpp); this keeps that buffer alive, so copies and moves are safe and the
// views stay valid for as long as any copy exists.
class received_pdu {
 public:
  received_pdu() = default;

  // Decodes `encoding`, which must lie inside *buffer.
  [[nodiscard]] static result<received_pdu> decode(std::shared_ptr<const byte_buffer> buffer,
                                                   byte_view encoding,
                                                   const mms::decode_options& opts = {});

  [[nodiscard]] const mms::mms_pdu& pdu() const noexcept { return pdu_; }
  // The MMS PDU encoding (a view into buffer()).
  [[nodiscard]] byte_view encoding() const noexcept { return encoding_; }
  [[nodiscard]] const std::shared_ptr<const byte_buffer>& buffer() const noexcept { return buffer_; }

 private:
  std::shared_ptr<const byte_buffer> buffer_;
  byte_view encoding_;
  mms::mms_pdu pdu_;
};

// Confirmed-ResponsePDU of a successful request.
class service_response {
 public:
  explicit service_response(received_pdu message) noexcept : message_(std::move(message)) {}

  [[nodiscard]] std::uint32_t invoke_id() const noexcept { return response().invoke_id; }
  [[nodiscard]] const mms::confirmed_service_response& service() const noexcept {
    return response().service;
  }
  [[nodiscard]] const mms::confirmed_response& response() const noexcept {
    return std::get<mms::confirmed_response>(message_.pdu());
  }
  [[nodiscard]] const received_pdu& message() const noexcept { return message_; }

 private:
  received_pdu message_;
};

// Owning copy of an mms::service_error.
struct service_error_info {
  mms::error_class cls = mms::error_class::others;
  std::int64_t code = 0;
  std::optional<std::int64_t> additional_code;
  std::optional<std::string> additional_description;
  byte_buffer service_specific_info;  // contents of serviceSpecificInfo, opaque

  [[nodiscard]] static service_error_info from(const mms::service_error& e);
  // A view for encoding; valid while this object is.
  [[nodiscard]] mms::service_error view() const noexcept;
};

struct reject_info {
  std::optional<std::uint32_t> original_invoke_id;
  mms::reject_type type = mms::reject_type::pdu_error;
  std::int64_t reason = 0;
};

// Why a request failed. `code` is always set:
//  - errc::service_error: Confirmed-ErrorPDU, `service_error` (and `modifier_position`) set;
//  - errc::request_rejected: RejectPDU naming the request, `reject` set;
//  - errc::request_timed_out, asio::error::operation_aborted (cancelled), openiec61850::errc
//    (encoding failure, length_overflow above the peer's max PDU size, invalid_state), or the
//    error that ended the association (errc::released, errc::peer_aborted, socket errors...).
struct request_error {
  std::error_code code;
  std::optional<service_error_info> service_error;
  std::optional<std::uint32_t> modifier_position;
  std::optional<reject_info> reject;
};

// Outcome of a confirmed request: a service_response or a request_error. Mirrors result<T>.
class [[nodiscard]] request_result {
 public:
  request_result(service_response r) : storage_(std::in_place_index<0>, std::move(r)) {}  // NOLINT
  request_result(request_error e) : storage_(std::in_place_index<1>, std::move(e)) {}     // NOLINT
  request_result(std::error_code ec) : request_result(request_error{ec, {}, {}, {}}) {}   // NOLINT
  request_result(errc e) : request_result(make_error_code(e)) {}                          // NOLINT
  request_result(openiec61850::errc e) : request_result(openiec61850::make_error_code(e)) {}  // NOLINT

  [[nodiscard]] bool has_value() const noexcept { return storage_.index() == 0; }
  explicit operator bool() const noexcept { return has_value(); }

  [[nodiscard]] service_response& value() & { return std::get<0>(storage_); }
  [[nodiscard]] const service_response& value() const& { return std::get<0>(storage_); }
  [[nodiscard]] service_response&& value() && { return std::get<0>(std::move(storage_)); }
  service_response& operator*() & { return value(); }
  const service_response& operator*() const& { return value(); }
  service_response* operator->() { return &value(); }
  const service_response* operator->() const { return &value(); }

  [[nodiscard]] std::error_code error() const noexcept {
    return has_value() ? std::error_code{} : std::get<1>(storage_).code;
  }
  // Details of the failure; only valid when !has_value().
  [[nodiscard]] const request_error& failure() const { return std::get<1>(storage_); }

 private:
  std::variant<service_response, request_error> storage_;
};

// An unconfirmed PDU (e.g. an InformationReport carrying an IEC 61850 report).
class unconfirmed_message {
 public:
  unconfirmed_message(received_pdu message, std::size_t lost_before) noexcept
      : message_(std::move(message)), lost_before_(lost_before) {}

  [[nodiscard]] const mms::unconfirmed_service& service() const noexcept {
    return std::get<mms::unconfirmed_pdu>(message_.pdu()).service;
  }
  // The InformationReport, or nullptr for another unconfirmed service.
  [[nodiscard]] const mms::information_report* information_report() const noexcept {
    return std::get_if<mms::information_report>(&service());
  }
  [[nodiscard]] const received_pdu& message() const noexcept { return message_; }
  // Messages dropped by the queue overflow policy immediately before this one.
  [[nodiscard]] std::size_t lost_before() const noexcept { return lost_before_; }

 private:
  received_pdu message_;
  std::size_t lost_before_ = 0;
};

namespace detail {
class core;
}

// An encoded MMS PDU on its way to the peer, for server_association::send_batch().
struct outbound_pdu {
  std::optional<std::uint32_t> answers;  // the invokeID of the request it answers, if any
  byte_buffer pdu;
};

// A confirmed request received from the peer. It owns the received bytes. Answer it exactly once,
// in any order relative to the other requests; until then it counts against the peer's negotiated
// max serv outstanding (further requests beyond it are rejected with
// max-serv-outstanding-exceeded). Destroying it unanswered sends a Confirmed-ErrorPDU
// (service/other). The answer methods may be awaited from any executor.
class incoming_request {
 public:
  incoming_request(incoming_request&&) noexcept = default;
  incoming_request& operator=(incoming_request&& other) noexcept;
  incoming_request(const incoming_request&) = delete;
  incoming_request& operator=(const incoming_request&) = delete;
  ~incoming_request();

  [[nodiscard]] std::uint32_t invoke_id() const noexcept { return request().invoke_id; }
  [[nodiscard]] const mms::confirmed_service_request& service() const noexcept {
    return request().service;
  }
  [[nodiscard]] const mms::confirmed_request& request() const noexcept {
    return std::get<mms::confirmed_request>(message_.pdu());
  }
  [[nodiscard]] const received_pdu& message() const noexcept { return message_; }
  [[nodiscard]] bool answered() const noexcept { return answered_; }

  // Each completes once the answer has been written; a second answer fails with
  // errc::invalid_state. The response is encoded before the call returns its awaitable.
  [[nodiscard]] asio::awaitable<result<void>> respond(const mms::confirmed_service_response& response);
  [[nodiscard]] asio::awaitable<result<void>> respond_error(
      const mms::service_error& error, std::optional<std::uint32_t> modifier_position = std::nullopt);
  // RejectPDU (confirmed-requestPDU) with the given reason (mms::reject_code::confirmed_request).
  [[nodiscard]] asio::awaitable<result<void>> reject(
      std::int64_t reason = mms::reject_code::confirmed_request::other);
  // Marks the request answered by an already encoded MMS PDU (Confirmed-Response, Confirmed-Error
  // or Reject), to be sent with server_association::send_batch(). errc::invalid_state on a second
  // answer.
  [[nodiscard]] result<outbound_pdu> encoded_answer(byte_buffer pdu);

 private:
  friend class detail::core;
  incoming_request(std::shared_ptr<detail::core> state, received_pdu message) noexcept;
  asio::awaitable<result<void>> answer(result<byte_buffer> pdu);
  asio::awaitable<result<void>> answer(byte_buffer pdu);

  std::shared_ptr<detail::core> state_;
  received_pdu message_;
  bool answered_ = false;
};

// The Initiate parameters in force (ISO 9506-1 §8.2). Max serv outstanding calling bounds the
// confirmed requests the client may have outstanding; called, those of the server. Each side's
// local detail is the largest MMS PDU it accepts (absent: no stated limit).
struct negotiated_parameters {
  std::optional<std::int32_t> local_detail_calling;
  std::optional<std::int32_t> local_detail_called;
  std::int16_t max_serv_outstanding_calling = 1;
  std::int16_t max_serv_outstanding_called = 1;
  std::optional<std::int8_t> data_structure_nesting_level;
  std::int16_t version_number = 1;
  mms::support_options parameter_cbb;
  mms::support_options services_supported_calling;
  mms::support_options services_supported_called;
};

// Immutable description of an established association.
struct association_info {
  negotiated_parameters negotiated;
  // The peer's AP-title/AE-qualifier (responding on the client, calling on the server), when sent
  // in form 2.
  std::optional<ber::oid> peer_ap_title;
  std::optional<std::int64_t> peer_ae_qualifier;
  asio::ip::tcp::endpoint local_endpoint;
  asio::ip::tcp::endpoint remote_endpoint;
  std::optional<transport::tls_session_info> tls;  // unset on a plain connection
};

}  // namespace openiec61850::association
