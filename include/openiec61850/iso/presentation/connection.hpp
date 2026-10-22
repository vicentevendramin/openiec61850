#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <system_error>
#include <variant>
#include <vector>

#include "openiec61850/ber/oid.hpp"
#include "openiec61850/core/bytes.hpp"
#include "openiec61850/core/result.hpp"
#include "openiec61850/iso/presentation/ppdu.hpp"
#include "openiec61850/iso/session/connection.hpp"

namespace openiec61850::iso::presentation {

// Sans-I/O presentation protocol machine (X.226), normal mode, kernel functional unit, BER as the
// only transfer syntax. It owns the session protocol machine below it and is driven exactly like it:
// every TSDU received from the transport goes to on_tsdu(), and every outgoing TSDU is appended to
// the caller's `out` buffer (one TSDU per call), ready for the transport.
//
// Service mapping (X.226 §6, §8.4): P-CONNECT = CP/CPA/CPR on S-CONNECT; P-DATA = TD (bare
// User-data) on S-DATA; P-RELEASE = User-data on S-RELEASE (no PPDU); P-U-ABORT = ARU and
// P-P-ABORT = ARP on S-U-ABORT.
//
// The upper layer (ACSE, MMS) exchanges lists of PDVs: each one a presentation context identifier
// and the complete encoding of one APDU of that context's abstract syntax (single-ASN1-type).

using session::role;
using session::state;  // the presentation connection is always in the state of its session

struct context_proposal {
  std::uint32_t id;  // odd and unique (X.226 §6.2.2)
  ber::oid abstract_syntax;
};

struct connection_options {
  session::connection_options session;
  byte_buffer local_selector;   // calling (initiator) or responding (responder) P-selector
  byte_buffer remote_selector;  // called P-selector (initiator only)
  // Initiator: the presentation contexts proposed, each with BER as the only transfer syntax.
  std::vector<context_proposal> contexts;
  // Responder: abstract syntaxes accepted; empty accepts any. A context is accepted only when BER is
  // among its proposed transfer syntaxes.
  std::vector<ber::oid> supported_abstract_syntaxes;
};

// The defined context set as negotiated so far.
struct negotiated_context {
  std::uint32_t id;
  ber::oid abstract_syntax;
  bool accepted;
  std::uint8_t reason;  // context_reason, when not accepted
};

// Byte views point into the TSDU passed to on_tsdu. Spans of PDVs point into the connection and are
// valid until the next call to on_tsdu.

// Responder: answer with accept() or refuse(). The contexts are already decided (accepted when the
// abstract syntax is supported and BER was proposed).
struct connect_indication {
  byte_view calling_selector;
  byte_view called_selector;
  std::span<const negotiated_context> contexts;
  std::span<const pdv> user_data;
};

// Initiator: CPA received, the connection is in data transfer.
struct connect_confirm {
  byte_view responding_selector;
  std::span<const negotiated_context> contexts;
  std::span<const pdv> user_data;
};

// Initiator: the connection was refused, by the peer's presentation user (no provider_reason) or by
// its presentation provider; or by the session provider (session_reason not rejected_by_user).
struct connect_refused {
  std::uint8_t session_reason;
  std::optional<std::uint8_t> provider_reason;
  std::span<const pdv> user_data;
};

struct data_indication {
  std::span<const pdv> user_data;
};

// Answer with release_response(). `collision` is set when our own release is outstanding.
struct release_indication {
  bool collision;
  std::span<const pdv> user_data;
};

struct release_confirm {
  std::span<const pdv> user_data;
};

// P-U-ABORT indication: ARU received (or a session user abort without user data).
struct user_abort_indication {
  std::span<const pdv> user_data;
};

// P-P-ABORT indication: ARP received, or the session was aborted by its provider.
struct provider_abort_indication {
  std::optional<std::uint8_t> reason;  // abort_reason, from the ARP
};

// The local protocol machine terminated the connection (malformed PPDU or SPDU, protocol violation,
// unsupported proposal). `out` holds the TSDU to send, if any (AB with an ARP, or RF with a CPR);
// then close the transport.
struct provider_abort {
  std::error_code error;
};

struct no_event {};

using event = std::variant<no_event, connect_indication, connect_confirm, connect_refused,
                           data_indication, release_indication, release_confirm,
                           user_abort_indication, provider_abort_indication, provider_abort>;

class connection {
 public:
  connection(role r, connection_options options);

  [[nodiscard]] role connection_role() const noexcept { return session_.connection_role(); }
  [[nodiscard]] state current_state() const noexcept { return session_.current_state(); }
  [[nodiscard]] const session::connection& session() const noexcept { return session_; }
  [[nodiscard]] std::span<const negotiated_context> contexts() const noexcept { return contexts_; }
  [[nodiscard]] bool is_accepted(std::uint32_t context_id) const noexcept;

  // Local service requests. Each appends one TSDU to `out`, or fails without appending anything:
  // errc::invalid_state when not allowed in the current state or when a PDV names a context that is
  // not usable (not proposed in connect, not accepted afterwards); errors from the session encoders
  // (e.g. user data too long for S-CONNECT) are passed through.
  [[nodiscard]] result<void> connect(std::span<const pdv> user_data, byte_buffer& out);  // P-CONNECT req
  [[nodiscard]] result<void> accept(std::span<const pdv> user_data, byte_buffer& out);   // P-CONNECT rsp+
  [[nodiscard]] result<void> refuse(std::span<const pdv> user_data, byte_buffer& out);   // P-CONNECT rsp-
  [[nodiscard]] result<void> send_data(std::span<const pdv> user_data, byte_buffer& out);  // P-DATA
  // P-DATA with one single-ASN1-type PDV.
  [[nodiscard]] result<void> send_data(std::uint32_t context_id, byte_view apdu, byte_buffer& out);
  [[nodiscard]] result<void> release(std::span<const pdv> user_data, byte_buffer& out);  // P-RELEASE req
  [[nodiscard]] result<void> release_response(std::span<const pdv> user_data,           // P-RELEASE rsp
                                              byte_buffer& out);
  [[nodiscard]] result<void> abort(std::span<const pdv> user_data, byte_buffer& out);    // P-U-ABORT

  // Processes one TSDU received from the transport. Automatic answers are appended to `out`. Fails
  // with errc::invalid_state only when the connection is already closed.
  [[nodiscard]] result<event> on_tsdu(byte_view tsdu, byte_buffer& out);

  // See session::connection::on_transport_disconnect.
  bool on_transport_disconnect() noexcept { return session_.on_transport_disconnect(); }

 private:
  event on_connect(const session::connect_indication& ind, byte_buffer& out);
  event on_accept(const session::connect_confirm& conf, byte_buffer& out);
  event on_refuse(const session::connect_refused& ref);
  event on_abort(const session::abort_indication& ab);
  event on_user_data(byte_view data, std::uint8_t ppdu, byte_buffer& out);
  event fail(std::error_code error, std::uint8_t ppdu, byte_buffer& out);
  event refuse_locally(std::error_code error, std::uint8_t reason, byte_buffer& out);
  [[nodiscard]] bool usable(std::span<const pdv> pdvs, bool proposed) const noexcept;
  [[nodiscard]] std::vector<context_result> results() const;
  [[nodiscard]] result<void> encode_data(std::span<const pdv> user_data);

  session::connection session_;
  connection_options options_;
  std::vector<negotiated_context> contexts_;
  std::vector<pdv> received_;  // PDVs of the last event
  byte_buffer scratch_;        // presentation encoding handed to the session layer
};

}  // namespace openiec61850::iso::presentation
