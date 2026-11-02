#include "openiec61850/transport/cotp_channel.hpp"
#include "openiec61850/transport/spawn.hpp"

#include <algorithm>
#include <atomic>
#include <deque>
#include <exception>
#include <optional>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>

#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/connect.hpp>
#include <asio/detached.hpp>
#include <asio/dispatch.hpp>
#include <asio/steady_timer.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/write.hpp>

#ifdef OPENIEC61850_WITH_TLS
#include <asio/ssl/error.hpp>

#include "tls_impl.hpp"
#endif

namespace openiec61850::transport {

namespace cotp = iso::cotp;
using asio::awaitable;
using asio::ip::tcp;
using strand_type = cotp_channel::executor_type;

namespace {

constexpr auto use_tuple = asio::as_tuple(asio::use_awaitable);
constexpr std::size_t min_read_buffer_size = 512;
// What a queued send holds besides its bytes (coroutine frames, timers, handlers), as charged to
// channel_options::max_output_bytes. Measured: about 2 KiB per send, so that a flood of tiny PDUs
// costs what the limit says.
constexpr std::size_t send_overhead = 2048;
constexpr std::size_t max_transfer_size = 65536;  // of one write to the socket
#ifdef OPENIEC61850_WITH_TLS
// How long a release waits for the peer's close_notify.
constexpr std::chrono::seconds tls_close_timeout{1};
#endif

// Runs op on strand, resuming the caller on its own executor afterwards.
template <typename T>
awaitable<T> on_strand(strand_type strand, awaitable<T> op) {
  const auto current = co_await asio::this_coro::executor;
  if (current == asio::any_io_executor(strand)) co_return co_await std::move(op);
  co_return co_await run_on(strand, std::move(op));
}

template <typename T>
awaitable<T> ready(T value) {
  co_return value;
}

std::error_code map_disconnect(const cotp::disconnect_indication& d) {
  switch (d.origin) {
    case cotp::disconnect_origin::refused:
    case cotp::disconnect_origin::local_refusal:
      return std::make_error_code(std::errc::connection_refused);
    case cotp::disconnect_origin::remote_disconnect:
      return asio::error::connection_reset;
    case cotp::disconnect_origin::remote_error:
      return errc::protocol_violation;
    case cotp::disconnect_origin::network_closed:
      return asio::error::eof;
    case cotp::disconnect_origin::protocol_error:
      break;
  }
  return d.error ? d.error : make_error_code(errc::protocol_violation);
}

}  // namespace

namespace detail {

struct send_waiter {
  std::uint64_t target;
  asio::steady_timer timer;
};

struct channel_state : std::enable_shared_from_this<channel_state> {
  channel_state(strand_type s, tcp::socket sock, cotp::connection c, const channel_options& o)
      : strand(std::move(s)),
        socket(std::move(sock)),
        deadline(strand),
        stall_timer(strand),
        conn(std::move(c)),
        read_buffer(std::max(o.read_buffer_size, min_read_buffer_size)),
        max_output(o.max_output_bytes),
        stall_timeout(o.write_stall_timeout) {}

  strand_type strand;
  tcp::socket socket;
#ifdef OPENIEC61850_WITH_TLS
  std::shared_ptr<tls_context> tls_ctx;  // outlives tls
  std::optional<tls_stream> tls;
  std::chrono::steady_clock::time_point keys_since = std::chrono::steady_clock::now();
  std::uint64_t bytes_since_update = 0;
  std::uint64_t tls_key_updates = 0;
#endif
  std::optional<tls_session_info> tls_info;
  std::optional<tcp::resolver> resolver;
  asio::steady_timer deadline;
  std::uint64_t deadline_phase = 0;
  asio::steady_timer stall_timer;
  bool stall_watch = false;
  std::uint64_t write_progress = 0;  // bumped each time the socket takes more bytes
  cotp::connection conn;
  std::vector<cotp::event> events;
  byte_buffer read_buffer;
  std::deque<byte_buffer> inbox;
  bool receiving = false;

  byte_buffer out;      // queued, not yet handed to the socket
  byte_buffer writing;  // being written
  std::uint64_t enqueued = 0;
  std::uint64_t written = 0;
  bool writer_active = false;
  bool close_after_flush = false;
  std::vector<send_waiter*> waiters;
  std::size_t max_output;
  std::chrono::milliseconds stall_timeout;

  std::error_code error;  // terminal
  std::atomic<bool> open{false};
  cotp::connected_indication info;
  tcp::endpoint local;
  tcp::endpoint remote;

  void arm_deadline(std::chrono::milliseconds d) {
    if (d <= std::chrono::milliseconds::zero()) return;
    const auto phase = ++deadline_phase;
    deadline.expires_after(d);
    deadline.async_wait([self = shared_from_this(), phase](std::error_code ec) {
      if (!ec && self->deadline_phase == phase) self->fail(asio::error::timed_out);
    });
  }

  void disarm_deadline() {
    ++deadline_phase;
    deadline.cancel();
  }

  void wake_all() {
    for (auto* w : waiters) w->timer.cancel();
  }

  // Checked once per period rather than re-armed on every write, which would cost a timer
  // operation per PDU: a stall is noticed between one and two periods after the last progress, and
  // an idle channel has no timer pending.
  void watch_writes() {
    if (stall_watch || stall_timeout <= std::chrono::milliseconds::zero()) return;
    stall_watch = true;
    stall_timer.expires_after(stall_timeout);
    stall_timer.async_wait([self = shared_from_this(), seen = write_progress](std::error_code ec) {
      self->stall_watch = false;
      if (ec || !self->writer_active || !self->socket.is_open()) return;
      if (self->write_progress == seen) {
        self->network_error(asio::error::timed_out);
      } else {
        self->watch_writes();
      }
    });
  }

#ifdef OPENIEC61850_WITH_TLS
  void renew_tls_keys(std::size_t about_to_write) {
    const auto& c = tls_ctx->config();
    const auto now = std::chrono::steady_clock::now();
    const bool by_time =
        c.key_update_interval.count() > 0 && now - keys_since >= c.key_update_interval;
    const bool by_bytes = c.key_update_bytes > 0 && bytes_since_update >= c.key_update_bytes;
    if (by_time || by_bytes) {
      if (request_key_update(*tls)) ++tls_key_updates;
      keys_since = now;
      bytes_since_update = 0;
    }
    bytes_since_update += about_to_write;
  }
#endif

  awaitable<std::tuple<std::error_code, std::size_t>> read_some() {
#ifdef OPENIEC61850_WITH_TLS
    if (tls) {
      auto [ec, n] = co_await tls->async_read_some(asio::buffer(read_buffer), use_tuple);
      // The association layers have their own orderly release, so a TCP close without
      // close_notify cannot truncate anything unnoticed: it is a plain end of stream here.
      if (ec == asio::ssl::error::stream_truncated) ec = asio::error::eof;
      co_return std::tuple{ec, n};
    }
#endif
    co_return co_await socket.async_read_some(asio::buffer(read_buffer), use_tuple);
  }

  awaitable<std::tuple<std::error_code, std::size_t>> write_all(asio::const_buffer data) {
    // Called before each partial write: asio::transfer_all() that counts the progress.
    auto progress = [this](const std::error_code& ec, std::size_t) -> std::size_t {
      ++write_progress;
      return ec ? 0 : max_transfer_size;
    };
#ifdef OPENIEC61850_WITH_TLS
    if (tls) {
      renew_tls_keys(data.size());
      co_return co_await asio::async_write(*tls, data, progress, use_tuple);
    }
#endif
    co_return co_await asio::async_write(socket, data, progress, use_tuple);
  }

  void close_socket() {
    std::error_code ignored;
    if (resolver) resolver->cancel();
    socket.close(ignored);
    stall_timer.cancel();
    disarm_deadline();
    wake_all();
  }

  // Ends the channel at once.
  void fail(std::error_code ec) {
    if (!error) error = ec;
    open = false;
    conn.close();
    out.clear();
    close_socket();
  }

  // Ends the channel once the queued output (e.g. an ER or DR) has been written.
  void finish(std::error_code ec) {
    if (!error) error = ec;
    open = false;
    if (!writer_active && out.empty()) {
      close_socket();
    } else {
      close_after_flush = true;
      wake_all();
    }
  }

  void network_error(std::error_code ec) {
    if (error) return;
    events.clear();
    conn.network_closed(events);
    fail(ec);
  }

  // A TSDU fits an empty queue whatever its size: the limit is on what piles up.
  [[nodiscard]] bool over_limit(std::size_t more) const noexcept {
    if (max_output == 0 || (out.empty() && !writer_active)) return false;
    const auto queued = out.size() + writing.size() + waiters.size() * send_overhead;
    return queued + more > max_output;
  }

  void enqueue(byte_buffer bytes) {
    if (bytes.empty() || !socket.is_open()) return;
    if (over_limit(bytes.size())) {
      fail(errc::output_limit_exceeded);
      return;
    }
    enqueued += bytes.size();
    if (out.empty()) {
      out = std::move(bytes);
    } else {
      // resize + copy instead of insert: GCC 13 emits a false -Wstringop-overflow for insert at -O2.
      const auto offset = out.size();
      out.resize(offset + bytes.size());
      std::copy(bytes.begin(), bytes.end(), out.begin() + static_cast<std::ptrdiff_t>(offset));
    }
    if (!writer_active) {
      writer_active = true;
      watch_writes();
      asio::co_spawn(strand, write_loop(shared_from_this()), asio::detached);
    }
  }

  static awaitable<void> write_loop(std::shared_ptr<channel_state> self) {
    while (!self->out.empty() && self->socket.is_open()) {
      std::swap(self->out, self->writing);
      const std::uint64_t end = self->enqueued;
      auto [ec, n] = co_await self->write_all(asio::buffer(self->writing));
      self->writing.clear();
      if (ec) {
        self->network_error(ec);
        break;
      }
      self->written = end;
      ++self->write_progress;
      for (auto* w : self->waiters) {
        if (w->target <= end) w->timer.cancel();
      }
    }
    self->out.clear();
    self->writer_active = false;
    if (self->close_after_flush) self->close_socket();
  }

  awaitable<result<void>> wait_written(std::uint64_t target) {
    if (written >= target) co_return result<void>{};
    if (error) co_return error;
    send_waiter w{target, asio::steady_timer(strand, asio::steady_timer::time_point::max())};
    waiters.push_back(&w);
    struct unregister {
      channel_state* s;
      send_waiter* w;
      ~unregister() { std::erase(s->waiters, w); }
    } guard{this, &w};
    (void)co_await w.timer.async_wait(use_tuple);
    if (written >= target) co_return result<void>{};
    if (error) co_return error;
    co_return asio::error::operation_aborted;  // the caller cancelled the wait
  }

  void process_input(byte_view data) {
    events.clear();
    conn.feed(data, events);
    std::error_code disconnect;
    for (auto& e : events) {
      if (auto* c = std::get_if<cotp::connected_indication>(&e)) {
        info = std::move(*c);
      } else if (auto* d = std::get_if<cotp::data_indication>(&e)) {
        inbox.push_back(std::move(d->tsdu));
      } else if (auto* x = std::get_if<cotp::disconnect_indication>(&e)) {
        disconnect = map_disconnect(*x);
      }
    }
    enqueue(conn.take_output());
    if (conn.state() == cotp::connection_state::closed) {
      finish(disconnect ? disconnect : make_error_code(errc::protocol_violation));
    }
  }

  void apply_socket_options(const channel_options& o) {
    std::error_code ignored;
    socket.set_option(tcp::no_delay(o.no_delay), ignored);
    if (o.keep_alive) socket.set_option(asio::socket_base::keep_alive(true), ignored);
  }

  awaitable<result<void>> tls_handshake() {
#ifdef OPENIEC61850_WITH_TLS
    if (tls) {
      const auto side = conn.connection_role() == cotp::role::initiator
                            ? asio::ssl::stream_base::client
                            : asio::ssl::stream_base::server;
      auto [ec] = co_await tls->async_handshake(side, use_tuple);
      if (error) co_return error;
      if (ec) {
        fail(ec);
        co_return ec;
      }
      tls_info = describe_session(*tls);
    }
#endif
    co_return result<void>{};
  }

  // Names the certificate of the peer must carry, for the host being connected to.
  result<void> prepare_tls(const std::string& host) {
#ifdef OPENIEC61850_WITH_TLS
    if (tls) {
      const auto& c = tls_ctx->config();
      const auto& name = c.peer_name.empty() ? host : c.peer_name;
      if (conn.connection_role() == cotp::role::initiator) set_server_name_indication(*tls, name);
      if (c.verify_peer && c.verify_peer_name && !name.empty()) {
        if (auto ec = set_expected_peer_name(*tls, name)) {
          fail(ec);
          return ec;
        }
      }
    }
#else
    (void)host;
#endif
    return {};
  }

  awaitable<result<void>> handshake(std::chrono::milliseconds timeout) {
    arm_deadline(timeout);
    if (auto r = co_await tls_handshake(); !r) co_return r;
    if (conn.connection_role() == cotp::role::initiator) {
      if (auto r = conn.connect(); !r) {
        fail(r.error());
        co_return r;
      }
      enqueue(conn.take_output());
    }
    while (conn.state() != cotp::connection_state::open) {
      if (error) co_return error;
      auto [ec, n] = co_await read_some();
      if (ec) {
        network_error(ec);
        continue;
      }
      process_input(byte_view(read_buffer).first(n));
    }
    disarm_deadline();
    if (error) co_return error;
    std::error_code ignored;
    local = socket.local_endpoint(ignored);
    remote = socket.remote_endpoint(ignored);
    open = true;
    co_return result<void>{};
  }

  static awaitable<result<void>> connect_op(std::shared_ptr<channel_state> self, std::string host,
                                            std::uint16_t port, channel_options o) {
    self->arm_deadline(o.connect_timeout);
    self->resolver.emplace(self->strand);
    auto [rec, endpoints] =
        co_await self->resolver->async_resolve(host, std::to_string(port), use_tuple);
    if (self->error) co_return self->error;
    if (rec) {
      self->fail(rec);
      co_return rec;
    }
    auto [cec, endpoint] = co_await asio::async_connect(self->socket, endpoints, use_tuple);
    (void)endpoint;
    if (auto r = self->prepare_tls(host); !r) co_return r;
    co_return co_await self->after_connect(cec, o);
  }

  static awaitable<result<void>> connect_endpoint_op(std::shared_ptr<channel_state> self,
                                                     tcp::endpoint endpoint, channel_options o) {
    self->arm_deadline(o.connect_timeout);
    auto [ec] = co_await self->socket.async_connect(endpoint, use_tuple);
    if (auto r = self->prepare_tls(endpoint.address().to_string()); !r) co_return r;
    co_return co_await self->after_connect(ec, o);
  }

  awaitable<result<void>> after_connect(std::error_code ec, const channel_options& o) {
    if (error) co_return error;
    if (ec) {
      fail(ec);
      co_return ec;
    }
    disarm_deadline();
    apply_socket_options(o);
    co_return co_await handshake(o.handshake_timeout);
  }

  static awaitable<result<void>> accept_op(std::shared_ptr<channel_state> self,
                                           channel_options o) {
    self->apply_socket_options(o);
    if (auto r = self->prepare_tls({}); !r) co_return r;
    co_return co_await self->handshake(o.handshake_timeout);
  }

  static awaitable<result<void>> send_op(std::shared_ptr<channel_state> self, byte_view tsdu) {
    if (self->error) co_return self->error;
    if (auto r = self->conn.send(tsdu); !r) co_return r;
    self->enqueue(self->conn.take_output());
    co_return co_await self->wait_written(self->enqueued);
  }

  static awaitable<result<void>> send_owned_op(std::shared_ptr<channel_state> self,
                                               byte_buffer tsdu) {
    co_return co_await send_op(std::move(self), tsdu);
  }

  static awaitable<result<byte_buffer>> receive_op(std::shared_ptr<channel_state> self) {
    if (self->receiving) co_return errc::invalid_state;
    self->receiving = true;
    struct reset {
      bool& flag;
      ~reset() { flag = false; }
    } guard{self->receiving};
    for (;;) {
      if (!self->inbox.empty()) {
        byte_buffer tsdu = std::move(self->inbox.front());
        self->inbox.pop_front();
        co_return tsdu;
      }
      if (self->error) co_return self->error;
      auto [ec, n] = co_await self->read_some();
      if (ec) {
        if (self->error) continue;
        // Only a cancellation by the caller gets here: the channel stays usable.
        if (ec == asio::error::operation_aborted) co_return ec;
        self->network_error(ec);
        continue;
      }
      self->process_input(byte_view(self->read_buffer).first(n));
    }
  }

  static awaitable<result<void>> shutdown_op(std::shared_ptr<channel_state> self,
                                             std::chrono::milliseconds limit) {
    if (!self->error) self->arm_deadline(limit);
    auto r = co_await self->wait_written(self->enqueued);
#ifdef OPENIEC61850_WITH_TLS
    if (self->tls && !self->error) {
      self->error = asio::error::operation_aborted;  // the channel is over for its other users
      self->open = false;
      self->arm_deadline(tls_close_timeout);
      // A read still pending competes with the shutdown for the stream's input and, with data in
      // flight, leaves it waiting out the whole deadline with the socket open.
      std::error_code ignored;
      self->socket.cancel(ignored);
      (void)co_await self->tls->async_shutdown(use_tuple);
    }
#endif
    self->inbox.clear();
    self->fail(asio::error::operation_aborted);
    co_return r;
  }

  void local_close() {
    inbox.clear();
    fail(asio::error::operation_aborted);
  }
};

struct listener_state {
  listener_state(asio::any_io_executor e, strand_type s) : ex(std::move(e)), acceptor(s), strand(std::move(s)) {}

  asio::any_io_executor ex;
  tcp::acceptor acceptor;
  strand_type strand;
  tcp::endpoint local;

  static awaitable<result<tcp::socket>> accept_op(std::shared_ptr<listener_state> self) {
    auto [ec, socket] = co_await self->acceptor.async_accept(
        asio::any_io_executor(asio::make_strand(self->ex)), use_tuple);
    if (ec) co_return ec;
    co_return std::move(socket);
  }
};

}  // namespace detail

namespace {

using detail::channel_state;

result<std::shared_ptr<channel_state>> make_state(strand_type strand, tcp::socket socket,
                                                  cotp::role role, const channel_options& o) {
  auto conn = cotp::connection::create(role, o.cotp);
  if (!conn) return conn.error();
  auto state =
      std::make_shared<channel_state>(std::move(strand), std::move(socket), std::move(*conn), o);
#ifdef OPENIEC61850_WITH_TLS
  if (o.tls) {
    state->tls_ctx = o.tls;
    state->tls.emplace(state->socket, o.tls->native().ssl);
  }
#endif
  return state;
}

}  // namespace

// Grants the helpers below access to the private constructor.
struct channel_factory {
  static awaitable<result<cotp_channel>> open(std::shared_ptr<channel_state> state,
                                              awaitable<result<void>> op) {
    auto r = co_await on_strand(state->strand, std::move(op));
    if (!r) co_return r.error();
    co_return cotp_channel(std::move(state));
  }
};


cotp_channel::cotp_channel(std::shared_ptr<detail::channel_state> state) noexcept
    : state_(std::move(state)) {}

cotp_channel& cotp_channel::operator=(cotp_channel&& other) noexcept {
  if (this != &other) {
    close();
    state_ = std::move(other.state_);
  }
  return *this;
}

cotp_channel::~cotp_channel() { close(); }

awaitable<result<cotp_channel>> cotp_channel::connect(asio::any_io_executor ex, std::string host,
                                                      std::uint16_t port, channel_options options) {
  auto strand = asio::make_strand(ex);
  auto state = make_state(strand, tcp::socket(strand), cotp::role::initiator, options);
  if (!state) return ready<result<cotp_channel>>(state.error());
  auto op = channel_state::connect_op(*state, std::move(host), port, std::move(options));
  return channel_factory::open(std::move(*state), std::move(op));
}

awaitable<result<cotp_channel>> cotp_channel::connect(asio::any_io_executor ex,
                                                      tcp::endpoint endpoint,
                                                      channel_options options) {
  auto strand = asio::make_strand(ex);
  auto state = make_state(strand, tcp::socket(strand), cotp::role::initiator, options);
  if (!state) return ready<result<cotp_channel>>(state.error());
  auto op = channel_state::connect_endpoint_op(*state, endpoint, std::move(options));
  return channel_factory::open(std::move(*state), std::move(op));
}

awaitable<result<cotp_channel>> cotp_channel::accept(tcp::socket socket, channel_options options) {
  std::optional<strand_type> strand;
  if (const auto* s = socket.get_executor().target<strand_type>()) {
    strand = *s;
  } else {
    // Move the descriptor onto a strand so that all state is serialised.
    strand = asio::make_strand(socket.get_executor());
    std::error_code ec;
    const auto protocol = socket.local_endpoint(ec).protocol();
    if (ec) return ready<result<cotp_channel>>(ec);
    const auto handle = socket.release(ec);
    if (ec) return ready<result<cotp_channel>>(ec);
    tcp::socket rehomed(*strand);
    rehomed.assign(protocol, handle, ec);
    if (ec) return ready<result<cotp_channel>>(ec);
    socket = std::move(rehomed);
  }
  auto state = make_state(*strand, std::move(socket), cotp::role::responder, options);
  if (!state) return ready<result<cotp_channel>>(state.error());
  auto op = channel_state::accept_op(*state, std::move(options));
  return channel_factory::open(std::move(*state), std::move(op));
}

void cotp_channel::async_connect(asio::any_io_executor ex, std::string host, std::uint16_t port,
                                 channel_options options,
                                 std::function<void(result<cotp_channel>)> handler) {
  auto strand = asio::make_strand(ex);
  auto state = make_state(strand, tcp::socket(strand), cotp::role::initiator, options);
  if (!state) {
    asio::dispatch(strand, [h = std::move(handler), ec = state.error()] { h(ec); });
    return;
  }
  auto op = channel_state::connect_op(*state, std::move(host), port, std::move(options));
  transport::spawn(strand, channel_factory::open(std::move(*state), std::move(op)),
                      std::move(handler));
}

awaitable<result<void>> cotp_channel::send(byte_view tsdu) {
  if (!state_) return ready<result<void>>(errc::invalid_state);
  return on_strand(state_->strand, channel_state::send_op(state_, tsdu));
}

awaitable<result<byte_buffer>> cotp_channel::receive() {
  if (!state_) return ready<result<byte_buffer>>(errc::invalid_state);
  return on_strand(state_->strand, channel_state::receive_op(state_));
}

awaitable<result<void>> cotp_channel::shutdown(std::chrono::milliseconds limit) {
  if (!state_) return ready<result<void>>(errc::invalid_state);
  return on_strand(state_->strand, channel_state::shutdown_op(state_, limit));
}

void cotp_channel::async_send(byte_buffer tsdu, std::function<void(result<void>)> handler) {
  if (!state_) {
    handler(errc::invalid_state);
    return;
  }
  transport::spawn(state_->strand, channel_state::send_owned_op(state_, std::move(tsdu)),
                      std::move(handler));
}

void cotp_channel::async_receive(std::function<void(result<byte_buffer>)> handler) {
  if (!state_) {
    handler(errc::invalid_state);
    return;
  }
  transport::spawn(state_->strand, channel_state::receive_op(state_), std::move(handler));
}

void cotp_channel::close() noexcept {
  if (!state_) return;
  asio::dispatch(state_->strand, [s = state_] { s->local_close(); });
}

cotp_channel::executor_type cotp_channel::get_executor() const noexcept { return state_->strand; }

bool cotp_channel::is_open() const noexcept { return state_ && state_->open.load(); }

const cotp::connected_indication& cotp_channel::connection_info() const noexcept {
  return state_->info;
}

cotp::role cotp_channel::connection_role() const noexcept { return state_->conn.connection_role(); }

const std::optional<tls_session_info>& cotp_channel::tls_session() const noexcept {
  return state_->tls_info;
}

std::uint64_t cotp_channel::tls_key_updates() const noexcept {
#ifdef OPENIEC61850_WITH_TLS
  return state_->tls_key_updates;
#else
  return 0;
#endif
}

const tcp::endpoint& cotp_channel::local_endpoint() const noexcept { return state_->local; }

const tcp::endpoint& cotp_channel::remote_endpoint() const noexcept { return state_->remote; }

// --- cotp_listener ---

cotp_listener::cotp_listener(std::shared_ptr<detail::listener_state> state) noexcept
    : state_(std::move(state)) {}

cotp_listener& cotp_listener::operator=(cotp_listener&& other) noexcept {
  if (this != &other) {
    close();
    state_ = std::move(other.state_);
  }
  return *this;
}

cotp_listener::~cotp_listener() { close(); }

result<cotp_listener> cotp_listener::listen(asio::any_io_executor ex, const tcp::endpoint& endpoint,
                                            int backlog) {
  auto strand = asio::make_strand(ex);
  auto state = std::make_shared<detail::listener_state>(ex, strand);
  auto& a = state->acceptor;
  std::error_code ec;
  if (a.open(endpoint.protocol(), ec); ec) return ec;
#if !defined(_WIN32)
  // On Windows this option would instead let a second listener take over a port in use.
  if (a.set_option(tcp::acceptor::reuse_address(true), ec); ec) return ec;
#endif
  if (a.bind(endpoint, ec); ec) return ec;
  if (a.listen(backlog, ec); ec) return ec;
  state->local = a.local_endpoint(ec);
  if (ec) return ec;
  return cotp_listener(std::move(state));
}

awaitable<result<tcp::socket>> cotp_listener::accept_socket() {
  if (!state_) return ready<result<tcp::socket>>(errc::invalid_state);
  return on_strand(state_->strand, detail::listener_state::accept_op(state_));
}

awaitable<result<cotp_channel>> cotp_listener::accept(channel_options options) {
  auto socket = co_await accept_socket();
  if (!socket) co_return socket.error();
  co_return co_await cotp_channel::accept(std::move(*socket), std::move(options));
}

void cotp_listener::close() noexcept {
  if (!state_) return;
  asio::dispatch(state_->strand, [s = state_] {
    std::error_code ignored;
    s->acceptor.close(ignored);
  });
}

const tcp::endpoint& cotp_listener::local_endpoint() const noexcept { return state_->local; }

}  // namespace openiec61850::transport
