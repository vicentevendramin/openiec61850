#include "openiec61850/goose/sv_subscriber.hpp"

#include <asio/post.hpp>

#include "subscription_impl.hpp"

namespace openiec61850::sv {

const char* to_string(continuity c) noexcept {
  switch (c) {
    case continuity::first: return "first";
    case continuity::in_sequence: return "in_sequence";
    case continuity::gap: return "gap";
    case continuity::duplicate: return "duplicate";
    case continuity::out_of_order: return "out_of_order";
  }
  return "?";
}

smp_cnt_tracker::check smp_cnt_tracker::on_sample(std::uint16_t smp_cnt) noexcept {
  check c;
  if (!has_) {
    has_ = true;
    last_ = smp_cnt;
    return c;
  }
  const std::uint32_t range = wrap_ == 0 || wrap_ > 0x10000U ? 0x10000U : wrap_;
  if (smp_cnt == last_) {
    c.status = continuity::duplicate;
    return c;
  }
  std::uint32_t ahead = 0;
  if (smp_cnt >= range) {
    // Outside the configured range: restart the tracking.
    c.status = continuity::out_of_order;
    last_ = smp_cnt;
    return c;
  }
  if (wrap_ == 0 && smp_cnt == 0) {
    ahead = 1;  // unknown range: a drop to 0 is the wrap
  } else {
    ahead = (smp_cnt + range - last_) % range;
  }
  if (ahead == 1) {
    c.status = continuity::in_sequence;
  } else if (ahead < range / 2) {
    c.status = continuity::gap;
    c.lost = ahead - 1;
  } else {
    c.status = continuity::out_of_order;
    return c;
  }
  last_ = smp_cnt;
  return c;
}

bool subscriber::impl::matches(const frame_view& f) const noexcept {
  if (closed) return false;
  if (cfg.app_id && *cfg.app_id != f.app_id) return false;
  return !cfg.destination || *cfg.destination == f.destination;
}

void subscriber::impl::on_message(const message_view& m, goose::detail::clock::time_point now) {
  if (m.frame.simulation() && !cfg.accept_simulation) {
    std::lock_guard lock{stats_mutex};
    ++st.simulated_ignored;
    return;
  }
  for (const auto& a : m.pdu.asdus) {
    if (!cfg.sv_id.empty() && cfg.sv_id != a.sv_id) continue;
    const auto check = tracker.on_sample(a.smp_cnt);
    const bool mismatch = cfg.conf_rev && *cfg.conf_rev != a.conf_rev;
    {
      std::lock_guard lock{stats_mutex};
      ++st.samples;
      st.lost += check.lost;
      if (check.status == continuity::duplicate) ++st.duplicates;
      if (check.status == continuity::out_of_order) ++st.out_of_order;
      if (mismatch) ++st.conf_rev_mismatches;
    }
    if (handler) {
      handler(m.frame, a, check);
      continue;
    }
    sample_event e;
    e.source = m.frame.source;
    e.app_id = m.frame.app_id;
    e.simulation = m.frame.simulation();
    e.sv_id = a.sv_id;
    if (a.dat_set) e.dat_set = std::string(*a.dat_set);
    e.smp_cnt = a.smp_cnt;
    e.conf_rev = a.conf_rev;
    e.refr_tm = a.refr_tm;
    e.smp_synch = a.smp_synch;
    e.smp_rate = a.smp_rate;
    e.smp_mod = a.smp_mod;
    e.seq_data.assign(a.seq_data.begin(), a.seq_data.end());
    e.status = check.status;
    e.lost = check.lost;
    e.conf_rev_mismatch = mismatch;
    e.received = now;
    if (queue.push(std::move(e))) {
      std::lock_guard lock{stats_mutex};
      ++st.dropped;
    }
  }
}

void subscriber::impl::close_on_strand() {
  closed = true;
  queue.close();
}

subscriber::subscriber(std::shared_ptr<impl> p) noexcept : impl_(std::move(p)) {}

subscriber::~subscriber() { close(); }

asio::awaitable<result<sample_event>> subscriber::next_sample() {
  auto self = impl_;
  auto op = [](std::shared_ptr<impl> s) -> asio::awaitable<result<sample_event>> {
    co_return co_await s->queue.pop();
  };
  co_return co_await goose::detail::on_strand(self->strand, op(self));
}

void subscriber::set_handler(
    std::function<void(const frame_view&, const asdu_view&, const smp_cnt_tracker::check&)>
        handler) {
  asio::post(impl_->strand, [self = impl_, h = std::move(handler)]() mutable {
    self->handler = std::move(h);
  });
}

void subscriber::close() {
  asio::post(impl_->strand, [self = impl_] { self->close_on_strand(); });
}

const subscriber_config& subscriber::config() const noexcept { return impl_->cfg; }

subscriber_stats subscriber::stats() const {
  std::lock_guard lock{impl_->stats_mutex};
  return impl_->st;
}

}  // namespace openiec61850::sv
