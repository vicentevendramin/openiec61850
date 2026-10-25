#pragma once

#include <atomic>
#include <functional>
#include <mutex>
#include <optional>

#include <asio/steady_timer.hpp>

#include "detail.hpp"
#include "openiec61850/goose/subscriber.hpp"
#include "openiec61850/goose/sv_subscriber.hpp"

namespace openiec61850::goose {

struct subscriber::impl : std::enable_shared_from_this<subscriber::impl> {
  impl(const detail::strand_type& s, subscriber_config c)
      : cfg(std::move(c)), strand(s), queue(s, cfg.queue_capacity), timer(s) {
    tracker.margin = cfg.tal_margin;
  }

  subscriber_config cfg;
  detail::strand_type strand;
  detail::event_queue<event> queue;
  asio::steady_timer timer;
  sequence_tracker tracker;
  std::optional<message> last;  // header of the last message, without values
  std::atomic<bool> closed{false};

  mutable std::mutex stats_mutex;
  subscriber_stats st;

  // The rest runs on the strand.
  [[nodiscard]] bool matches(const frame_view& f, std::string_view gocb_ref) const noexcept;
  void on_message(const message_view& m, detail::clock::time_point now);
  void close_on_strand();

 private:
  void push(event e);
  void arm_timer();
};

}  // namespace openiec61850::goose

namespace openiec61850::sv {

struct subscriber::impl : std::enable_shared_from_this<subscriber::impl> {
  using view_handler =
      std::function<void(const frame_view&, const asdu_view&, const smp_cnt_tracker::check&)>;

  impl(const goose::detail::strand_type& s, subscriber_config c)
      : cfg(std::move(c)), strand(s), queue(s, cfg.queue_capacity), tracker(cfg.smp_cnt_wrap) {}

  subscriber_config cfg;
  goose::detail::strand_type strand;
  goose::detail::event_queue<sample_event> queue;
  smp_cnt_tracker tracker;
  view_handler handler;
  std::atomic<bool> closed{false};

  mutable std::mutex stats_mutex;
  subscriber_stats st;

  [[nodiscard]] bool matches(const frame_view& f) const noexcept;
  // Every ASDU of the frame with this svID.
  void on_message(const message_view& m, goose::detail::clock::time_point now);
  void close_on_strand();
};

}  // namespace openiec61850::sv
