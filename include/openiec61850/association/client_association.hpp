#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <system_error>

#include <asio/any_io_executor.hpp>
#include <asio/awaitable.hpp>

#include "openiec61850/association/types.hpp"
#include "openiec61850/ber/oid.hpp"
#include "openiec61850/core/bytes.hpp"
#include "openiec61850/iso/session/spdu.hpp"
#include "openiec61850/core/result.hpp"
#include "openiec61850/mms/pdu.hpp"
#include "openiec61850/transport/cotp_channel.hpp"

namespace openiec61850::association {

// COTP options with the TSAP selectors of the IEC 61850-8-1 profile (0x0001 both ways).
[[nodiscard]] transport::channel_options default_channel_options();

struct association_params {
  std::string host = "127.0.0.1";
  std::uint16_t port = transport::default_port;
  // TCP/COTP: TSAP selectors (cotp.calling_tsap / cotp.called_tsap), TPDU size, connect and CR/CC
  // timeouts.
  transport::channel_options transport = default_channel_options();
  byte_buffer calling_session_selector{0x00, 0x01};
  byte_buffer called_session_selector{0x00, 0x01};
  // Session versions proposed in CN. Version 2 only by default: some IEC 61850 servers drop the
  // connection when a CN proposes versions 1 and 2 together.
  std::uint8_t session_versions = iso::session::version_2;
  byte_buffer calling_presentation_selector{0x00, 0x00, 0x00, 0x01};
  byte_buffer called_presentation_selector{0x00, 0x00, 0x00, 0x01};
  // ACSE application entity titles (form 2); unset omits the field from the AARQ.
  std::optional<ber::oid> called_ap_title = default_ap_title;
  std::optional<std::int64_t> called_ae_qualifier = default_ae_qualifier;
  std::optional<ber::oid> calling_ap_title = default_ap_title;
  std::optional<std::int64_t> calling_ae_qualifier = default_ae_qualifier;
  // Password authentication (X.227 annex B mechanism {2 2 3 1}, sent as a GraphicString).
  std::optional<std::string> password;
  // The Initiate-RequestPDU proposal.
  mms::initiate_request initiate;
  // CP sent to CPA/CPR received. Zero disables the timeout.
  std::chrono::milliseconds association_timeout{10000};
  // Default per-request timeout, including the time spent waiting for a free request slot.
  // Zero disables it.
  std::chrono::milliseconds request_timeout{10000};
  // Whole release() exchange (waiting for outstanding requests, Conclude, RLRQ/RLRE).
  std::chrono::milliseconds release_timeout{5000};
  // Unconfirmed PDUs kept for next_unconfirmed(); at least 1. On overflow the oldest queued
  // message is dropped and counted in the next one's lost_before(), so the reader coroutine never
  // blocks (that would stall every response) and the consumer sees the newest data.
  std::size_t unconfirmed_queue_capacity = 1024;
  mms::decode_options decode;
};

namespace detail {
struct client_state;
}

// The initiator (Client) side of an MMS association over the ISO stack of IEC 61850-8-1:
// TCP/RFC 1006 + COTP class 0 + session kernel + presentation kernel + ACSE + MMS.
//
// Confirmed requests may be issued concurrently from any number of coroutines (ADR 0004). Each
// one gets the next free invokeID; at most negotiated max_serv_outstanding_calling are sent at a
// time and the others wait, in order, for a free slot. Responses are correlated by invokeID and
// may arrive in any order. Confirmed requests of the server (the reverse services of obtainFile)
// go to set_request_handler().
//
// Threading: as transport::cotp_channel. All state lives on the channel's strand; one reader
// coroutine there dispatches every incoming PDU. Coroutine methods may be awaited from any
// executor (they hop onto the strand and resume the caller on its own executor); abort(),
// set_unconfirmed_handler(), state() and the immutable accessors are safe from any thread.
// The handle is a move-only owner; destroying it aborts the association if still open.
class client_association {
 public:
  using executor_type = transport::cotp_channel::executor_type;

  // TCP + COTP, then CP(AARQ(Initiate-Request)) and CPA(AARE(Initiate-Response)). Errors:
  // transport errors; errc::connection_refused (session RF / presentation CPR without AARE);
  // errc::association_rejected / authentication_failed (AARE rejected); errc::initiate_error;
  // errc::peer_aborted; asio::error::timed_out (association_timeout).
  [[nodiscard]] static asio::awaitable<result<client_association>> connect(
      asio::any_io_executor ex, association_params params);

  client_association(client_association&&) noexcept = default;
  client_association& operator=(client_association&& other) noexcept;
  client_association(const client_association&) = delete;
  client_association& operator=(const client_association&) = delete;
  ~client_association();

  // Sends a Confirmed-RequestPDU and waits for its response; see request_error for the
  // failures. Views inside `service` must stay valid until the request completes (it is encoded
  // once a request slot is free). Cancelling the awaiting coroutine abandons the request: its
  // slot is freed at once and a late response is discarded.
  [[nodiscard]] asio::awaitable<request_result> request(mms::confirmed_service_request service);
  [[nodiscard]] asio::awaitable<request_result> request(mms::confirmed_service_request service,
                                                        std::chrono::milliseconds timeout);

  // Next unconfirmed PDU. One consumer at a time (errc::invalid_state otherwise). Messages queued
  // before the association closed are still delivered, then the closing error is reported.
  [[nodiscard]] asio::awaitable<result<unconfirmed_message>> next_unconfirmed();
  // Alternative to next_unconfirmed(): every unconfirmed PDU (including those already queued) is
  // handed to `handler` on the strand; it must not throw nor block. An empty function restores
  // the queue. Any thread.
  void set_unconfirmed_handler(std::function<void(unconfirmed_message)> handler);

  // Serves the confirmed requests of the server. Each one is handed to `handler` on the strand
  // (it must not throw nor block) and bounded by the negotiated max_serv_outstanding_called, also
  // while a request of this side is outstanding. An empty function, the default, rejects them with
  // unrecognized-service. Any thread.
  void set_request_handler(std::function<void(incoming_request)> handler);

  // Orderly release: waits for the outstanding requests, MMS Conclude-Request/-Response, then
  // A-RELEASE (RLRQ/RLRE on P-RELEASE) and the transport is closed. New requests fail with
  // errc::invalid_state meanwhile. errc::conclude_refused leaves the association established.
  // On timeout the association is aborted and asio::error::timed_out is returned.
  [[nodiscard]] asio::awaitable<result<void>> release();

  // A-ABORT (ABRT on P-U-ABORT), then the transport is closed. Pending requests fail with
  // errc::aborted. Idempotent, any thread.
  void abort() noexcept;

  // Completes once the association is closed, with the reason: errc::released, errc::aborted,
  // errc::peer_aborted, openiec61850::errc::protocol_violation, or a transport error.
  [[nodiscard]] asio::awaitable<std::error_code> wait_closed();

  // Any thread.
  [[nodiscard]] association_state state() const noexcept;
  // Unconfirmed messages dropped so far by the overflow policy. Any thread.
  [[nodiscard]] std::uint64_t unconfirmed_dropped() const noexcept;

  // Immutable.
  [[nodiscard]] const association_info& info() const noexcept;
  [[nodiscard]] executor_type get_executor() const noexcept;

 private:
  explicit client_association(std::shared_ptr<detail::client_state> state) noexcept;

  std::shared_ptr<detail::client_state> state_;
};

}  // namespace openiec61850::association
