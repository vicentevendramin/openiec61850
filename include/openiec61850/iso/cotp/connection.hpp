#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <system_error>
#include <variant>
#include <vector>

#include "openiec61850/core/bytes.hpp"
#include "openiec61850/core/result.hpp"
#include "openiec61850/iso/cotp/tpdu.hpp"
#include "openiec61850/iso/cotp/tpkt.hpp"

namespace openiec61850::iso::cotp {

enum class role : std::uint8_t { initiator, responder };

enum class connection_state : std::uint8_t {
  idle,         // initiator before connect()
  awaiting_cr,  // responder waiting for the peer's CR
  awaiting_cc,  // initiator after sending CR
  open,
  closed,       // the transport must close the network connection after flushing output
};

struct connection_config {
  std::uint16_t local_reference = 1;  // SRC-REF sent in CR/CC
  // Initiator: sent in CR when set. Responder: unused (the CR's selectors are echoed).
  std::optional<byte_buffer> calling_tsap;
  std::optional<byte_buffer> called_tsap;
  // Initiator: proposed in CR. Responder: upper bound for the negotiated size.
  // Must be a power of two in [128, 2048] (X.224 §13.3.4 b), class 0).
  std::size_t max_tpdu_size = class0_max_tpdu_size;
  // Upper bound for a reassembled incoming TSDU.
  std::size_t max_tsdu_size = 1u << 20;
  // Upper bound for the TPKT length field; bounds the receive buffer. DT TPDUs larger
  // than the negotiated TPDU size are additionally rejected with an ER.
  std::size_t max_tpkt_size = tpkt_max_length;
  // Responder: inspects the CR (e.g. its TSAP selectors). Return std::nullopt to accept
  // or a disconnect_reason to refuse with a DR. Unset accepts every CR.
  std::function<std::optional<std::uint8_t>(const connection_request&)> accept_connection;
};

struct connected_indication {
  std::size_t tpdu_size = default_tpdu_size;
  std::uint16_t remote_reference = 0;
  std::optional<byte_buffer> calling_tsap;
  std::optional<byte_buffer> called_tsap;
};

struct data_indication {
  byte_buffer tsdu;
};

enum class disconnect_origin : std::uint8_t {
  refused,          // initiator: the peer answered the CR with a DR (reason holds its reason)
  local_refusal,    // responder: accept_connection refused the CR, a DR was queued
  remote_disconnect,  // a DR after establishment (not valid in class 0, tolerated)
  remote_error,     // the peer sent an ER (reason holds its reject cause)
  protocol_error,   // a local check failed (error says why); an ER may have been queued
  network_closed,   // network_closed() was called
};

struct disconnect_indication {
  disconnect_origin origin = disconnect_origin::protocol_error;
  std::uint8_t reason = 0;
  std::error_code error;
};

using event = std::variant<connected_indication, data_indication, disconnect_indication>;

// Sans-I/O ISO transport class 0 connection over RFC 1006 (X.224 §6, §13).
// The transport feeds received bytes to feed(), writes whatever take_output()
// returns, and closes the network connection once state() is closed and the output
// has been flushed. Class 0 has no DR after establishment and no expedited data:
// disconnection is done by closing the network connection (X.224 §6.7.1.4).
class connection {
 public:
  // Fails with errc::unsupported if the config is invalid for class 0.
  [[nodiscard]] static result<connection> create(role r, connection_config config);

  // Initiator only: queues the CR.
  [[nodiscard]] result<void> connect();

  // Queues a TSDU as DT TPDUs sized to the negotiated TPDU size, EOT on the last one.
  // Fails with errc::invalid_state if the connection is not open.
  [[nodiscard]] result<void> send(byte_view tsdu);

  // Consumes received bytes (any chunking) and appends the resulting events.
  // Input after the connection is closed is ignored.
  void feed(byte_view data, std::vector<event>& events);

  // The network connection was closed by the peer or lost.
  void network_closed(std::vector<event>& events);

  // Local disconnect: in class 0 this only means closing the network connection.
  void close() noexcept;

  // Bytes to write to the network connection, in order.
  [[nodiscard]] byte_buffer take_output() noexcept;
  [[nodiscard]] bool has_output() const noexcept { return !output_.empty(); }

  [[nodiscard]] role connection_role() const noexcept { return role_; }
  [[nodiscard]] connection_state state() const noexcept { return state_; }
  [[nodiscard]] std::size_t tpdu_size() const noexcept { return tpdu_size_; }
  [[nodiscard]] std::uint16_t remote_reference() const noexcept { return remote_ref_; }

 private:
  connection(role r, connection_config config);

  void handle_tpdu(byte_view raw, std::vector<event>& events);
  void handle_cr(const connection_request& cr, std::vector<event>& events);
  void handle_cc(const connection_confirm& cc, byte_view raw, std::vector<event>& events);
  void handle_dt(const data_tpdu& dt, byte_view raw, std::vector<event>& events);
  void enter_open(std::size_t tpdu_size, std::uint16_t remote_ref,
                  std::optional<byte_buffer> calling, std::optional<byte_buffer> called,
                  std::vector<event>& events);
  // Closes after a local protocol check failed; queues an ER when cause is set.
  void fail(std::error_code ec, std::optional<std::uint8_t> cause, byte_view raw,
            std::vector<event>& events);
  void disconnect(disconnect_origin origin, std::uint8_t reason, std::vector<event>& events);

  role role_;
  connection_config config_;
  connection_state state_;
  tpkt_framer framer_;
  byte_buffer output_;
  byte_buffer reassembly_;
  std::size_t tpdu_size_ = default_tpdu_size;
  std::uint16_t remote_ref_ = 0;
};

}  // namespace openiec61850::iso::cotp
