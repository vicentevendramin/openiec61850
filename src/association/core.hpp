#pragma once

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <memory>
#include <optional>
#include <system_error>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <asio/awaitable.hpp>
#include <asio/steady_timer.hpp>
#include <asio/this_coro.hpp>

#include "openiec61850/association/types.hpp"
#include "openiec61850/core/bytes.hpp"
#include "openiec61850/core/result.hpp"
#include "openiec61850/iso/presentation/connection.hpp"
#include "openiec61850/mms/pdu.hpp"
#include "openiec61850/transport/cotp_channel.hpp"
#include "openiec61850/transport/spawn.hpp"

namespace openiec61850::association::detail {

namespace ps = iso::presentation;
using strand_type = transport::cotp_channel::executor_type;
using clock = std::chrono::steady_clock;

// Runs op on strand, resuming the caller on its own executor afterwards.
template <typename T>
asio::awaitable<T> on_strand(strand_type strand, asio::awaitable<T> op) {
  const auto current = co_await asio::this_coro::executor;
  if (current == asio::any_io_executor(strand)) co_return co_await std::move(op);
  co_return co_await transport::run_on(strand, std::move(op));
}

template <typename T>
asio::awaitable<T> ready(T value) {
  co_return value;
}

// Zero means no deadline.
[[nodiscard]] clock::time_point deadline_after(std::chrono::milliseconds timeout) noexcept;

// One coroutine waiting on the strand for a condition. notify() may come before the wait.
struct waiter {
  explicit waiter(const strand_type& s) : timer(s, clock::time_point::max()) {}
  void notify() noexcept {
    notified = true;
    timer.cancel();
  }

  asio::steady_timer timer;
  bool notified = false;
};

enum class wait_status : std::uint8_t { notified, timed_out, cancelled };

// Waits for notify(), the deadline or the cancellation of the awaiting coroutine (in that order of
// precedence when they coincide, except that a cancellation always wins).
[[nodiscard]] asio::awaitable<wait_status> wait(waiter& w, clock::time_point deadline);

class waiter_list {
 public:
  void add(waiter* w) { items_.push_back(w); }
  void remove(waiter* w) noexcept { std::erase(items_, w); }
  [[nodiscard]] bool empty() const noexcept { return items_.empty(); }
  void notify_all() noexcept {
    for (auto* w : items_) w->notify();
  }
  // Notifies and unregisters the oldest waiter.
  bool notify_one() noexcept {
    if (items_.empty()) return false;
    auto* w = items_.front();
    items_.erase(items_.begin());
    w->notify();
    return true;
  }

 private:
  std::vector<waiter*> items_;
};

// Unregisters a waiter when the waiting coroutine leaves (or its frame is destroyed).
struct registration {
  registration(waiter_list& l, waiter& w) : list(l), item(&w) { list.add(item); }
  ~registration() { list.remove(item); }
  registration(const registration&) = delete;
  registration& operator=(const registration&) = delete;

  waiter_list& list;
  waiter* item;
};

struct send_completion {
  explicit send_completion(const strand_type& s) : done(s) {}
  waiter done;
  std::optional<result<void>> outcome;
};

struct pending_request {
  explicit pending_request(const strand_type& s) : done(s) {}
  waiter done;
  std::optional<request_result> outcome;
};

// The strand-confined state common to both roles: the channel, the presentation (and session)
// protocol machine, the reader coroutine, the termination logic, and the confirmed services in
// both directions (each direction has its own invokeIDs).
class core : public std::enable_shared_from_this<core> {
 public:
  core(transport::cotp_channel ch, ps::role role, const ps::connection_options& options,
       const mms::decode_options& decode);
  virtual ~core() = default;
  core(const core&) = delete;
  core& operator=(const core&) = delete;

  [[nodiscard]] association_state current_state() const noexcept { return state_.load(); }
  [[nodiscard]] bool closed() const noexcept { return current_state() == association_state::closed; }
  void set_state(association_state s) noexcept { state_.store(s); }

  // Hands TSDUs to the transport in call order.
  std::shared_ptr<send_completion> send_tsdu(byte_buffer tsdu);
  void flush(byte_buffer& out);
  // P-DATA of one MMS PDU on the MMS context.
  [[nodiscard]] result<std::shared_ptr<send_completion>> send_mms_bytes(byte_view pdu);
  [[nodiscard]] result<std::shared_ptr<send_completion>> send_mms(const mms::mms_pdu& pdu);
  [[nodiscard]] static asio::awaitable<result<void>> wait_sent(std::shared_ptr<send_completion> c);
  void reject(std::optional<std::uint32_t> invoke_id, mms::reject_type type, std::int64_t reason);

  // Closes the association with `reason`: everyone waiting is woken up, then the transport is
  // closed (after the queued output when graceful). Idempotent.
  void terminate(std::error_code reason, bool graceful);
  // ABRT (P-U-ABORT) if the presentation connection can carry it, then terminate.
  void abort_with(std::error_code reason);

  // Receives one TSDU with a deadline (establishment only, before the reader runs).
  [[nodiscard]] asio::awaitable<result<byte_buffer>> receive_before(std::chrono::milliseconds timeout);
  void start_reader();

  [[nodiscard]] static asio::awaitable<std::error_code> wait_closed_op(std::shared_ptr<core> self);

  // Confirmed requests issued by this side.
  [[nodiscard]] static asio::awaitable<request_result> request_op(std::shared_ptr<core> self,
                                                                  mms::confirmed_service_request service,
                                                                  std::chrono::milliseconds timeout);
  // Confirmed-Response, Confirmed-Error or Reject, matched to the request it answers.
  void on_answer(received_pdu m);
  [[nodiscard]] bool requests_idle() const noexcept {
    return outstanding == 0 && slot_waiters.empty();
  }

  // Confirmed requests received. admit() counts one, or rejects it (`open`: the state allows it).
  [[nodiscard]] bool admit(std::uint32_t id, bool open);
  [[nodiscard]] static incoming_request make_incoming(std::shared_ptr<core> self, received_pdu m);
  [[nodiscard]] static asio::awaitable<result<void>> answer_op(std::shared_ptr<core> self,
                                                               std::uint32_t id, byte_buffer pdu);
  // Writes an already encoded PDU that answers nothing.
  [[nodiscard]] static asio::awaitable<result<void>> send_op(std::shared_ptr<core> self,
                                                             byte_buffer pdu);

  strand_type strand;
  transport::cotp_channel channel;
  ps::connection pres;
  mms::decode_options decode;
  std::uint32_t acse_context = acse_context_id;
  std::uint32_t mms_context = mms_context_id;
  std::error_code error;  // why the association closed
  waiter_list closed_waiters;
  association_info info;

  // Issued: the negotiated limit and the peer's largest PDU; requests holding a slot (sent or about
  // to be), and those waiting for one, in order.
  std::size_t limit = 1;
  std::optional<std::size_t> peer_max_pdu;
  std::size_t outstanding = 0;
  waiter_list slot_waiters;
  // Received, not answered yet.
  std::size_t incoming_limit = 1;
  std::unordered_set<std::uint32_t> incoming;

 protected:
  virtual void on_mms(received_pdu pdu) = 0;
  // FN received; answered with RLRE by default.
  virtual void on_release_indication(bool collision);
  virtual void on_release_confirm();
  virtual void on_terminated() = 0;
  // The last issued request has finished.
  virtual void on_requests_idle() {}

 private:
  std::uint32_t allocate_invoke_id();
  void abandon(std::uint32_t id);
  void release_slot();
  bool complete(std::uint32_t id, request_result outcome);
  void unmatched(std::uint32_t id, mms::reject_type type, std::int64_t reason);

  static asio::awaitable<void> reader(std::shared_ptr<core> self);
  void handle_tsdu(byte_buffer tsdu);
  void on_bad_mms(byte_view encoding, std::error_code ec);

  std::unordered_map<std::uint32_t, pending_request*> pending_;
  std::unordered_set<std::uint32_t> abandoned_;
  std::deque<std::uint32_t> abandoned_order_;
  std::uint32_t next_invoke_id_ = 0;
  std::atomic<association_state> state_{association_state::established};
};

}  // namespace openiec61850::association::detail
