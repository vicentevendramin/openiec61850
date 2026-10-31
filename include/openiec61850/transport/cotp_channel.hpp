#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>

#include <asio/any_io_executor.hpp>
#include <asio/awaitable.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/strand.hpp>

#include "openiec61850/core/bytes.hpp"
#include "openiec61850/core/result.hpp"
#include "openiec61850/iso/cotp/connection.hpp"
#include "openiec61850/transport/tls.hpp"

namespace openiec61850::transport {

// RFC 1006 §3: ISO transport services on top of TCP listen on port 102.
inline constexpr std::uint16_t default_port = 102;

struct channel_options {
  iso::cotp::connection_config cotp;
  // Name resolution plus TCP connect (initiator only). Zero disables the timeout.
  std::chrono::milliseconds connect_timeout{10000};
  // CR/CC exchange, both roles. Zero disables the timeout.
  std::chrono::milliseconds handshake_timeout{10000};
  bool no_delay = true;
  bool keep_alive = false;
  // Size of the socket read buffer.
  std::size_t read_buffer_size = 16384;
  // Output queued for the peer and not yet taken by the socket, plain or TLS, charged as the bytes
  // plus about 2 KiB per pending send (what a send holds besides its bytes). Beyond it the channel
  // fails with errc::output_limit_exceeded rather than growing: a peer that stops reading cannot
  // take more memory than this, whatever it provokes. A send into an empty queue always fits. Zero
  // disables the limit.
  std::size_t max_output_bytes = 16 * 1024 * 1024;
  // Queued output the socket takes none of for this long means a peer that stopped reading: the
  // channel fails with asio::error::timed_out, within up to twice this time. Any progress restarts
  // it, so a slow peer is fine. Zero disables it, and then a close that waits for the queued output
  // (shutdown(), an orderly release) can wait for ever.
  std::chrono::milliseconds write_stall_timeout{30000};
  // Runs COTP inside TLS (IEC 62351-3): the TLS handshake comes first, right after TCP, and
  // counts against handshake_timeout. Unset is plain RFC 1006.
  std::shared_ptr<tls_context> tls;
};

namespace detail {
struct channel_state;
struct listener_state;
}  // namespace detail

struct channel_factory;

// An established ISO transport connection (class 0 over RFC 1006 on TCP) that moves
// TSDUs. It knows nothing about the layers above.
//
// Threading: all state lives on the channel's strand (get_executor()). The coroutine
// methods may be awaited from a coroutine on any executor; when it is not the strand they
// hop onto it and resume the caller on its own executor. The callback methods and close()
// are safe to call from any thread; their handlers run on the strand (the I/O thread of
// an io_runtime) and must not throw. Accessors marked immutable are fixed before the
// channel is handed out and may be read from any thread. The handle itself is a
// move-only owner: moving or destroying the same handle concurrently is not allowed.
//
// Errors: socket errors are passed through (asio::error::eof when the peer closed,
// connection_reset, timed_out for the configured timeouts, operation_aborted after a local
// close or a cancelled operation, errc::output_limit_exceeded past max_output_bytes). COTP events map to: refused CR (DR answer, or local
// accept_connection refusal) -> std::errc::connection_refused; ER from the peer ->
// errc::protocol_violation; a local protocol check -> the cotp error (protocol_violation,
// malformed_encoding, length_overflow...). Once an error is reported every later send or
// receive reports it too, after the TSDUs already received have been delivered. A failed TLS
// handshake, including a rejected peer certificate, reports the OpenSSL error
// (asio::error::get_ssl_category()).
//
// Bridging to non-coroutine code: use the callback methods, or co_spawn any coroutine
// method onto get_executor() with a completion handler.
class cotp_channel {
 public:
  using executor_type = asio::strand<asio::any_io_executor>;

  // Resolves host, connects over TCP and performs the CR/CC exchange as initiator.
  [[nodiscard]] static asio::awaitable<result<cotp_channel>> connect(
      asio::any_io_executor ex, std::string host, std::uint16_t port = default_port,
      channel_options options = {});
  [[nodiscard]] static asio::awaitable<result<cotp_channel>> connect(
      asio::any_io_executor ex, asio::ip::tcp::endpoint endpoint, channel_options options = {});

  // Performs the CR/CC exchange as responder on an accepted TCP socket. options.cotp's
  // accept_connection hook can refuse the CR (e.g. on its TSAP selectors). If the socket's
  // executor is not a strand, the socket is moved onto a new strand on that executor.
  [[nodiscard]] static asio::awaitable<result<cotp_channel>> accept(asio::ip::tcp::socket socket,
                                                                    channel_options options = {});

  // Callback form of connect(); the handler runs on the new channel's strand.
  static void async_connect(asio::any_io_executor ex, std::string host, std::uint16_t port,
                            channel_options options,
                            std::function<void(result<cotp_channel>)> handler);

  cotp_channel(cotp_channel&&) noexcept = default;
  cotp_channel& operator=(cotp_channel&& other) noexcept;
  cotp_channel(const cotp_channel&) = delete;
  cotp_channel& operator=(const cotp_channel&) = delete;
  // Closes the connection.
  ~cotp_channel();

  // Queues the TSDU (segmented into DT TPDUs) and completes once it has been written to
  // the socket. Concurrent sends are queued in call order and written back to back, so
  // any number of them may be outstanding within max_output_bytes. tsdu must stay valid until
  // completion.
  // Cancelling a send does not withdraw a TSDU that was already queued.
  [[nodiscard]] asio::awaitable<result<void>> send(byte_view tsdu);

  // Next complete TSDU. Only one receive may be outstanding (errc::invalid_state
  // otherwise). Cancelling a receive leaves the channel usable.
  [[nodiscard]] asio::awaitable<result<byte_buffer>> receive();

  // Waits until every queued TSDU has been written, then closes the connection
  // (class 0 disconnects by closing the network connection, X.224 §6.7.1.4). With a non-zero
  // `limit` it closes after that time at the latest (asio::error::timed_out), whatever is left.
  [[nodiscard]] asio::awaitable<result<void>> shutdown(
      std::chrono::milliseconds limit = std::chrono::milliseconds::zero());

  // Callback forms; handlers run on the strand.
  void async_send(byte_buffer tsdu, std::function<void(result<void>)> handler);
  void async_receive(std::function<void(result<byte_buffer>)> handler);

  // Closes the connection at once, aborting pending operations. Idempotent, any thread.
  void close() noexcept;

  [[nodiscard]] executor_type get_executor() const noexcept;
  // False once the channel has been closed or has failed. Any thread.
  [[nodiscard]] bool is_open() const noexcept;

  // Immutable: the outcome of the CR/CC exchange (negotiated TPDU size, TSAP selectors).
  [[nodiscard]] const iso::cotp::connected_indication& connection_info() const noexcept;
  [[nodiscard]] iso::cotp::role connection_role() const noexcept;
  // Key updates this side started (tls_config::key_update_*). Read it on the strand.
  [[nodiscard]] std::uint64_t tls_key_updates() const noexcept;
  // Immutable: the TLS session, unset on a plain connection.
  [[nodiscard]] const std::optional<tls_session_info>& tls_session() const noexcept;
  [[nodiscard]] const asio::ip::tcp::endpoint& local_endpoint() const noexcept;
  [[nodiscard]] const asio::ip::tcp::endpoint& remote_endpoint() const noexcept;

 private:
  friend struct channel_factory;
  explicit cotp_channel(std::shared_ptr<detail::channel_state> state) noexcept;

  std::shared_ptr<detail::channel_state> state_;
};

// Accepts TCP connections for COTP responders. Thread safety as for cotp_channel: the
// acceptor lives on its own strand, coroutine methods hop onto it, close() is any-thread.
class cotp_listener {
 public:
  // Opens, binds (SO_REUSEADDR) and listens. Use port 0 for an ephemeral port.
  [[nodiscard]] static result<cotp_listener> listen(asio::any_io_executor ex,
                                                    const asio::ip::tcp::endpoint& endpoint,
                                                    int backlog = asio::socket_base::max_listen_connections);

  cotp_listener(cotp_listener&&) noexcept = default;
  cotp_listener& operator=(cotp_listener&& other) noexcept;
  cotp_listener(const cotp_listener&) = delete;
  cotp_listener& operator=(const cotp_listener&) = delete;
  ~cotp_listener();

  // Next TCP connection, on a new strand. A server that must not let a slow peer delay
  // the others spawns cotp_channel::accept() for each socket.
  [[nodiscard]] asio::awaitable<result<asio::ip::tcp::socket>> accept_socket();

  // accept_socket() followed by cotp_channel::accept(): one handshake at a time. Reports
  // a failed handshake (refused CR, timeout...) as an error; the listener stays usable.
  [[nodiscard]] asio::awaitable<result<cotp_channel>> accept(channel_options options = {});

  // Stops listening; a pending accept completes with operation_aborted. Any thread.
  void close() noexcept;

  // Immutable after listen().
  [[nodiscard]] const asio::ip::tcp::endpoint& local_endpoint() const noexcept;

 private:
  explicit cotp_listener(std::shared_ptr<detail::listener_state> state) noexcept;

  std::shared_ptr<detail::listener_state> state_;
};

}  // namespace openiec61850::transport
