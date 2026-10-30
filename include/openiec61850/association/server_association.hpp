#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <system_error>

#include <asio/any_io_executor.hpp>
#include <asio/awaitable.hpp>
#include <asio/ip/tcp.hpp>

#include "openiec61850/association/types.hpp"
#include "openiec61850/ber/oid.hpp"
#include "openiec61850/core/bytes.hpp"
#include "openiec61850/core/result.hpp"
#include "openiec61850/iso/acse/apdu.hpp"
#include "openiec61850/mms/pdu.hpp"
#include "openiec61850/transport/cotp_channel.hpp"

namespace openiec61850::association {

// What the client asked for in CP(AARQ(Initiate-Request)), as owning copies.
struct association_request {
  std::optional<ber::oid> calling_ap_title;  // form 2 only
  std::optional<std::int64_t> calling_ae_qualifier;
  std::optional<ber::oid> called_ap_title;
  std::optional<std::int64_t> called_ae_qualifier;
  std::optional<ber::oid> mechanism_name;
  // The charstring authentication value (the password of mechanism {2 2 3 1}).
  std::optional<std::string> password;
  mms::initiate_request initiate;
  // Presentation selectors of the CP (the layers below accept any selector; refuse here if needed).
  byte_buffer calling_presentation_selector;
  byte_buffer called_presentation_selector;
  asio::ip::tcp::endpoint remote_endpoint;
  // The TLS session of the connection, with the client certificate; unset on a plain connection.
  std::optional<transport::tls_session_info> tls;
};

// The application's answer to an association_request.
struct association_decision {
  bool accept = true;
  // AARE result-source-diagnostic (acse-service-user) when refusing, e.g.
  // service_user_diagnostic::authentication_failure.
  std::int64_t diagnostic = iso::acse::service_user_diagnostic::no_reason_given;

  [[nodiscard]] static association_decision accepted() noexcept { return {}; }
  [[nodiscard]] static association_decision rejected(
      std::int64_t diagnostic = iso::acse::service_user_diagnostic::no_reason_given) noexcept {
    return {false, diagnostic};
  }
};

// Responder negotiation (ISO 9506-1 §8.2.1): each negotiated value is the smaller of the proposal
// and the local limit, the parameter CBB is the intersection and servicesSupportedCalled are the
// local services. The nesting level is omitted when the proposal omitted it.
[[nodiscard]] mms::initiate_response negotiate(const mms::initiate_request& proposed,
                                               const mms::initiate_response& local) noexcept;

struct server_options {
  // COTP: options.cotp.accept_connection may refuse on the TSAP selectors.
  transport::channel_options transport;
  byte_buffer session_selector{0x00, 0x01};
  byte_buffer presentation_selector{0x00, 0x00, 0x00, 0x01};
  // Sent in the AARE as responding AP-title / AE-qualifier; unset omits them.
  std::optional<ber::oid> ap_title = default_ap_title;
  std::optional<std::int64_t> ae_qualifier = default_ae_qualifier;
  // Local limits and capabilities: local_detail_called, the max serv outstanding values, nesting
  // level, version, parameter CBB and servicesSupportedCalled.
  mms::initiate_response limits;
  // Called with the request and the negotiated response (which it may lower further). Unset
  // accepts every association. Runs on the association's strand; must not block nor throw.
  std::function<association_decision(const association_request&, mms::initiate_response&)> authorize;
  // CR/CC done to CP received. Zero disables the timeout.
  std::chrono::milliseconds association_timeout{10000};
  // Default timeout of request(), as association_params::request_timeout.
  std::chrono::milliseconds request_timeout{10000};
  mms::decode_options decode;
};

namespace detail {
struct server_state;
}

// The responder (Servidor) side of an MMS association. Threading as client_association.
class server_association {
 public:
  using executor_type = transport::cotp_channel::executor_type;

  // COTP CR/CC on an accepted socket, then waits for CP(AARQ(Initiate-Request)), asks
  // options.authorize and answers with CPA(AARE(Initiate-Response)) or refuses with
  // CPR(AARE rejected[, Initiate-ErrorPDU]). A refused association is reported as
  // errc::association_rejected (errc::authentication_failed for an authentication diagnostic).
  [[nodiscard]] static asio::awaitable<result<server_association>> accept(
      asio::ip::tcp::socket socket, server_options options);

  server_association(server_association&&) noexcept = default;
  server_association& operator=(server_association&& other) noexcept;
  server_association(const server_association&) = delete;
  server_association& operator=(const server_association&) = delete;
  ~server_association();

  // Next confirmed request. One consumer at a time (errc::invalid_state otherwise). After the
  // association closes the queued requests are still delivered (answering them fails), then the
  // closing error (errc::released after an orderly release) is reported.
  [[nodiscard]] asio::awaitable<result<incoming_request>> next_request();

  // Sends a Confirmed-RequestPDU to the client and waits for its response, on the terms of
  // client_association::request(); at most the negotiated max_serv_outstanding_called are sent at
  // a time. The client's requests are still delivered meanwhile: obtainFile stays outstanding
  // while the server reads the file with fileOpen, fileRead and fileClose (ISO 9506-2 Annex C).
  [[nodiscard]] asio::awaitable<request_result> request(mms::confirmed_service_request service);
  [[nodiscard]] asio::awaitable<request_result> request(mms::confirmed_service_request service,
                                                        std::chrono::milliseconds timeout);

  // Sends an Unconfirmed-PDU (e.g. an IEC 61850 report); completes once written.
  [[nodiscard]] asio::awaitable<result<void>> send_unconfirmed(const mms::information_report& report);
  [[nodiscard]] asio::awaitable<result<void>> send_unconfirmed(const mms::unconfirmed_service& service);

  // A-ABORT, then the transport is closed. Idempotent, any thread.
  void abort() noexcept;
  // Closes the transport at once, without an ABRT (as if the server disappeared). Any thread.
  void close() noexcept;

  [[nodiscard]] asio::awaitable<std::error_code> wait_closed();
  [[nodiscard]] association_state state() const noexcept;

  // Immutable.
  [[nodiscard]] const association_info& info() const noexcept;
  [[nodiscard]] const association_request& peer_request() const noexcept;
  [[nodiscard]] executor_type get_executor() const noexcept;

 private:
  explicit server_association(std::shared_ptr<detail::server_state> state) noexcept;

  std::shared_ptr<detail::server_state> state_;
};

// Accepts associations on a TCP endpoint. A server that must not let a slow peer delay the
// others spawns server_association::accept() for each socket from accept_socket().
class association_listener {
 public:
  [[nodiscard]] static result<association_listener> listen(asio::any_io_executor ex,
                                                           const asio::ip::tcp::endpoint& endpoint,
                                                           server_options options = {});

  // accept_socket() followed by server_association::accept(): one handshake at a time. A failed
  // handshake is reported as an error; the listener stays usable.
  [[nodiscard]] asio::awaitable<result<server_association>> accept();
  [[nodiscard]] asio::awaitable<result<asio::ip::tcp::socket>> accept_socket();

  // Any thread.
  void close() noexcept;
  [[nodiscard]] const asio::ip::tcp::endpoint& local_endpoint() const noexcept;
  [[nodiscard]] const server_options& options() const noexcept { return options_; }

 private:
  association_listener(transport::cotp_listener listener, server_options options) noexcept;

  transport::cotp_listener listener_;
  server_options options_;
};

}  // namespace openiec61850::association
