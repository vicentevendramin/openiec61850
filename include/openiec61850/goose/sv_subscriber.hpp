#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>

#include <asio/awaitable.hpp>

#include "openiec61850/core/bytes.hpp"
#include "openiec61850/core/result.hpp"
#include "openiec61850/goose/sv.hpp"

// Sampled Values Assinante (IEC 61850-9-2). A subscription selects the ASDUs of one MSVCB by
// APPID, destination address and svID, checks confRev and follows smpCnt continuity: smpCnt must
// grow by one per ASDU and wrap to 0 at smp_cnt_wrap (when 0, a drop to 0 from any value is taken
// as the wrap).
//
// Subscriptions are created on a receiver (receiver.hpp).

namespace openiec61850::sv {

enum class continuity : std::uint8_t {
  first,         // first ASDU of the subscription
  in_sequence,   // smpCnt = previous + 1 (with wrap)
  gap,           // samples missing (see `lost`)
  duplicate,     // same smpCnt again
  out_of_order,  // older smpCnt, or a jump beyond half the counter range
};

[[nodiscard]] const char* to_string(continuity c) noexcept;

// smpCnt continuity, without I/O. `wrap` 0 means the counter range is unknown.
class smp_cnt_tracker {
 public:
  explicit smp_cnt_tracker(std::uint32_t wrap = 0) noexcept : wrap_(wrap) {}

  struct check {
    continuity status = continuity::first;
    std::uint32_t lost = 0;
  };
  check on_sample(std::uint16_t smp_cnt) noexcept;
  void reset() noexcept { has_ = false; }

 private:
  std::uint32_t wrap_;
  bool has_ = false;
  std::uint16_t last_ = 0;
};

struct subscriber_config {
  std::optional<std::uint16_t> app_id;
  std::optional<mac_address> destination;
  std::string sv_id;  // empty = any
  std::optional<std::uint32_t> conf_rev;
  std::uint32_t smp_cnt_wrap = 0;
  bool accept_simulation = false;  // Reserved1 S bit
  std::size_t queue_capacity = 4096;
};

// One ASDU, owning its data.
struct sample_event {
  mac_address source{};
  std::uint16_t app_id = 0;
  bool simulation = false;

  std::string sv_id;
  std::optional<std::string> dat_set;
  std::uint16_t smp_cnt = 0;
  std::uint32_t conf_rev = 0;
  std::optional<mms::utc_time> refr_tm;
  std::uint8_t smp_synch = 0;
  std::optional<std::uint16_t> smp_rate;
  std::optional<std::uint16_t> smp_mod;
  byte_buffer seq_data;

  continuity status = continuity::first;
  std::uint32_t lost = 0;
  bool conf_rev_mismatch = false;
  std::uint64_t dropped_before = 0;  // queue overflow
  std::chrono::steady_clock::time_point received{};
};

struct subscriber_stats {
  std::uint64_t samples = 0;
  std::uint64_t lost = 0;
  std::uint64_t duplicates = 0;
  std::uint64_t out_of_order = 0;
  std::uint64_t conf_rev_mismatches = 0;
  std::uint64_t simulated_ignored = 0;
  std::uint64_t dropped = 0;
};

class subscriber {
 public:
  ~subscriber();
  subscriber(const subscriber&) = delete;
  subscriber& operator=(const subscriber&) = delete;

  // Same rules as goose::subscriber::next_event().
  [[nodiscard]] asio::awaitable<result<sample_event>> next_sample();
  // Low-latency alternative: called on the receiver's strand for every ASDU with a view into the
  // receive buffer (valid only during the call), without allocating. Must not block nor throw.
  // An empty function restores the queue.
  void set_handler(
      std::function<void(const frame_view&, const asdu_view&, const smp_cnt_tracker::check&)>
          handler);
  void close();

  [[nodiscard]] const subscriber_config& config() const noexcept;
  [[nodiscard]] subscriber_stats stats() const;

  struct impl;
  explicit subscriber(std::shared_ptr<impl> p) noexcept;
  [[nodiscard]] const std::shared_ptr<impl>& get_impl() const noexcept { return impl_; }

 private:
  std::shared_ptr<impl> impl_;
};

}  // namespace openiec61850::sv
