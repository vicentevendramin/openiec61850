#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <system_error>
#include <vector>

#include <asio/awaitable.hpp>

#include "openiec61850/core/result.hpp"
#include "openiec61850/goose/frame.hpp"
#include "openiec61850/goose/pdu.hpp"
#include "openiec61850/mms/data.hpp"
#include "openiec61850/model/timestamp.hpp"

// GOOSE Assinante (IEC 61850-7-2 §18.2.3, IEC 61850-8-1 §18.1.2.5).
//
// A subscription selects the messages of one GoCB by APPID, destination address and gocbRef
// (each optional), checks them against the expected datSet / goID / confRev / number of entries,
// follows stNum / sqNum and supervises timeAllowedtoLive: when no message arrives within the TAL
// of the last one, a timeout event is raised and the values must be considered invalid
// (7-2 §18.2.3.6) until the next message.
//
// Subscriptions are created on a receiver (receiver.hpp) that reads the link.

namespace openiec61850::goose {

// How a message relates to the previous one of the same subscription.
enum class sequence_status : std::uint8_t {
  first,           // first message, or first after a timeout
  new_state,       // stNum advanced by 1
  retransmission,  // same stNum, sqNum advanced by 1
  sq_gap,          // same stNum, sqNum advanced by more than 1 (messages lost)
  st_gap,          // stNum advanced by more than 1 (state changes lost)
  duplicate,       // same stNum and sqNum
  out_of_order,    // older stNum, or same stNum and older sqNum
};

[[nodiscard]] const char* to_string(sequence_status s) noexcept;

struct sequence_check {
  sequence_status status = sequence_status::first;
  // Messages (sq_gap) or state changes (st_gap) known to be missing.
  std::uint32_t lost = 0;
};

// stNum / sqNum / TAL supervision of one GoCB, without I/O (8-1 §18.1.2.5). Counters compare
// with serial-number arithmetic (RFC 1982), so the wrap 2^32-1 -> 1 is in order; sqNum 0 after a
// state change is expected.
class sequence_tracker {
 public:
  using clock = std::chrono::steady_clock;

  // Records a message received at `now` and arms the TAL deadline (now + TAL + margin).
  // Duplicates refresh the deadline without changing the counters; out-of-order messages change
  // nothing. A message with stNum 1 and sqNum 0 after a higher stNum is taken as a publisher
  // restart and reported as `first`.
  sequence_check on_message(std::uint32_t st_num, std::uint32_t sq_num, std::uint32_t tal_ms,
                            clock::time_point now) noexcept;

  // True once `now` is past the deadline of the last message.
  [[nodiscard]] bool expired(clock::time_point now) const noexcept;
  [[nodiscard]] std::optional<clock::time_point> deadline() const noexcept { return deadline_; }
  // Forgets the previous message (after a timeout): the next one is `first`.
  void reset() noexcept;

  [[nodiscard]] bool has_state() const noexcept { return has_state_; }
  [[nodiscard]] std::uint32_t st_num() const noexcept { return st_num_; }
  [[nodiscard]] std::uint32_t sq_num() const noexcept { return sq_num_; }

  // Added to every TAL (jitter allowance).
  std::chrono::milliseconds margin{0};

 private:
  bool has_state_ = false;
  std::uint32_t st_num_ = 0;
  std::uint32_t sq_num_ = 0;
  std::optional<clock::time_point> deadline_;
};

struct subscriber_config {
  // Filters (unset / empty = any).
  std::optional<std::uint16_t> app_id;
  std::optional<mac_address> destination;
  std::string gocb_ref;

  // Expectations: a matching message that disagrees raises a mismatch event instead of a
  // message event.
  std::optional<std::string> dat_set;
  std::optional<std::string> go_id;
  std::optional<std::uint32_t> conf_rev;
  std::optional<std::uint32_t> num_entries;

  // Ed.2: simulated messages (PDU simulation field or Reserved1 S bit) are ignored unless the
  // subscriber is in simulation mode (LPHD.Sim, 7-4).
  bool accept_simulation = false;
  // Extra time over the TAL before a timeout is raised.
  std::chrono::milliseconds tal_margin{0};
  // Events buffered for next_event(); the oldest is dropped on overflow.
  std::size_t queue_capacity = 256;
};

// A decoded GOOSE message, owning its data.
struct message {
  mac_address destination{};
  mac_address source{};
  std::optional<vlan_tag> vlan;
  std::uint16_t app_id = 0;
  std::uint16_t reserved1 = 0;
  std::uint16_t reserved2 = 0;

  std::string gocb_ref;
  std::uint32_t time_allowed_to_live = 0;
  std::string dat_set;
  std::optional<std::string> go_id;
  model::timestamp t;
  std::uint32_t st_num = 0;
  std::uint32_t sq_num = 0;
  bool simulation = false;
  std::uint32_t conf_rev = 0;
  bool nds_com = false;
  std::uint32_t num_dat_set_entries = 0;
  std::vector<mms::data> values;

  sequence_check sequence;
  std::chrono::steady_clock::time_point received{};
};

// Deep copy of a decoded message (sequence and received are left default).
[[nodiscard]] result<message> to_message(const message_view& v);

enum class event_kind : std::uint8_t {
  message,   // a valid message
  timeout,   // TAL expired: `msg` is the last message received (without values)
  mismatch,  // a message of the GoCB that disagrees with the configuration (see `reason`)
};

enum class mismatch_reason : std::uint8_t {
  none,
  dat_set,
  go_id,
  conf_rev,
  num_entries,  // numDatSetEntries, or the number of values, differs
  nds_com,      // needs commissioning
};

struct event {
  event_kind kind = event_kind::message;
  mismatch_reason reason = mismatch_reason::none;
  message msg;
  // Events dropped by the queue overflow immediately before this one.
  std::uint64_t dropped_before = 0;
};

struct subscriber_stats {
  std::uint64_t messages = 0;  // messages that matched the filters
  std::uint64_t timeouts = 0;
  std::uint64_t mismatches = 0;
  std::uint64_t lost = 0;  // sum of sequence_check::lost
  std::uint64_t duplicates = 0;
  std::uint64_t out_of_order = 0;
  std::uint64_t simulated_ignored = 0;
  std::uint64_t dropped = 0;  // queue overflow
};

// One subscription. Threading: methods are safe from any thread; the state lives on the strand
// of the receiver. Events are consumed with next_event() (async iterator style) or a handler.
class subscriber {
 public:
  ~subscriber();
  subscriber(const subscriber&) = delete;
  subscriber& operator=(const subscriber&) = delete;

  // The next event. Fails with errc::invalid_state once closed and drained (or when a handler
  // is set). The awaiting coroutine resumes on its own executor.
  [[nodiscard]] asio::awaitable<result<event>> next_event();
  // Alternative to next_event(): every event (including those queued) goes to `handler` on the
  // receiver's strand; it must not block nor throw. An empty function restores the queue.
  void set_handler(std::function<void(const event&)> handler);
  // Ends the subscription (pending next_event() fails with errc::invalid_state).
  void close();

  [[nodiscard]] const subscriber_config& config() const noexcept;
  [[nodiscard]] subscriber_stats stats() const;

  struct impl;
  explicit subscriber(std::shared_ptr<impl> p) noexcept;
  [[nodiscard]] const std::shared_ptr<impl>& get_impl() const noexcept { return impl_; }

 private:
  std::shared_ptr<impl> impl_;
};

}  // namespace openiec61850::goose
