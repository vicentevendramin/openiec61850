#pragma once

#include <cstdint>
#include <system_error>
#include <variant>

#include "openiec61850/core/bytes.hpp"
#include "openiec61850/core/result.hpp"
#include "openiec61850/iso/session/spdu.hpp"

namespace openiec61850::iso::session {

// Sans-I/O session protocol machine (X.225 §7, annex A) for the kernel + duplex profile. It consumes
// complete TSDUs and produces events; every outgoing TSDU is appended to the caller's `out` buffer,
// which the caller hands to the transport (COTP) as one TSDU per call.
//
// Release: without the negotiated release functional unit there is no release token, so either side
// may send FN and S-RELEASE cannot be refused (NF is a protocol error). If both FNs cross, each side
// answers the peer's FN with DN and the release completes when both DNs have been received.
// The transport connection is never reused: after a release or an abort, close it.

enum class role : std::uint8_t { initiator, responder };

enum class state : std::uint8_t {
  idle,                       // STA01: no session connection
  awaiting_accept,            // initiator: CN sent, awaiting AC/RF (STA02A)
  awaiting_connect_response,  // responder: CN received, the user must accept or refuse (STA08)
  data_transfer,              // STA713
  awaiting_disconnect,        // FN sent, awaiting DN (STA03); peer data may still arrive
  awaiting_release_response,  // FN received, the user must answer with release_response (STA09)
  closed,                     // released, refused or aborted
};

struct connection_options {
  byte_buffer local_selector;   // calling selector (initiator) or responding selector (responder)
  byte_buffer remote_selector;  // called selector (initiator only)
  // Versions proposed (initiator) or supported (responder); the highest common one is selected.
  std::uint8_t versions = version_1 | version_2;
};

// All byte_view members point into the TSDU passed to on_tsdu and are valid only as long as it is.

// Responder: answer with accept() or refuse().
struct connect_indication {
  byte_view calling_selector;
  byte_view called_selector;
  std::uint8_t version;  // the version that accept() will select
  byte_view user_data;
};

// Initiator: AC received, the session is in data transfer.
struct connect_confirm {
  byte_view responding_selector;
  std::uint8_t version;
  byte_view user_data;
};

// Initiator: RF received.
struct connect_refused {
  std::uint8_t reason;
  byte_view user_data;
};

struct data_indication {
  byte_view user_data;
};

// FN received: answer with release_response(). `collision` is set when our own FN is outstanding.
struct release_indication {
  bool collision;
  byte_view user_data;
};

// DN received in answer to our FN.
struct release_confirm {
  byte_view user_data;
};

// AB received from the peer (S-U-ABORT, or S-P-ABORT when the user abort bit is clear).
struct abort_indication {
  std::uint8_t transport_disconnect;
  byte_view user_data;
};

// The local protocol machine terminated the session (malformed SPDU, protocol violation, or an
// unsupported proposal). `out` holds the AB or RF to send, if any; then close the transport.
struct provider_abort {
  std::error_code error;
};

struct no_event {};

using event = std::variant<no_event, connect_indication, connect_confirm, connect_refused,
                           data_indication, release_indication, release_confirm, abort_indication,
                           provider_abort>;

class connection {
 public:
  connection(role r, connection_options options);

  [[nodiscard]] role connection_role() const noexcept { return role_; }
  [[nodiscard]] state current_state() const noexcept { return state_; }
  // The selected version once known (connect_indication / connect_confirm), else 0.
  [[nodiscard]] std::uint8_t version() const noexcept { return version_; }

  // Local service requests. Each appends one TSDU to `out`, or fails with errc::invalid_state
  // when not allowed in the current state (nothing is appended and the state is unchanged).
  [[nodiscard]] result<void> connect(byte_view user_data, byte_buffer& out);   // S-CONNECT req
  [[nodiscard]] result<void> accept(byte_view user_data, byte_buffer& out);    // S-CONNECT rsp+
  [[nodiscard]] result<void> refuse(std::uint8_t reason, byte_view user_data,  // S-CONNECT rsp-
                                    byte_buffer& out);
  [[nodiscard]] result<void> send_data(byte_view user_data, byte_buffer& out);         // S-DATA
  [[nodiscard]] result<void> release(byte_view user_data, byte_buffer& out);           // S-RELEASE req
  [[nodiscard]] result<void> release_response(byte_view user_data, byte_buffer& out);  // S-RELEASE rsp
  [[nodiscard]] result<void> abort(byte_view user_data, byte_buffer& out);             // S-U-ABORT

  // Processes one TSDU received from the transport. Automatic answers (AB on a protocol error, AA,
  // RF on an unsupported proposal) are appended to `out`. Fails with errc::invalid_state only
  // when the session is already closed.
  [[nodiscard]] result<event> on_tsdu(byte_view tsdu, byte_buffer& out);

  // The transport connection was lost or closed. Returns true if that was expected (the session had
  // already ended); the session is closed in either case.
  bool on_transport_disconnect() noexcept;

 private:
  event fail(std::error_code error, byte_buffer& out);
  event refuse_locally(std::error_code error, std::uint8_t reason, byte_buffer& out);
  event on_connect(const connect_spdu& cn, byte_buffer& out);
  event on_accept(const accept_spdu& ac, byte_buffer& out);

  role role_;
  state state_ = state::idle;
  connection_options options_;
  std::uint8_t version_ = 0;
  bool collision_ = false;          // FNs crossed
  bool peer_disconnected_ = false;  // DN received during a collision, before our own DN
};

}  // namespace openiec61850::iso::session
