#include "openiec61850/goose/subscriber.hpp"

#include <asio/bind_executor.hpp>
#include <asio/post.hpp>

#include "subscription_impl.hpp"

namespace openiec61850::goose {

namespace {

// Serial-number difference (RFC 1982) of counters that skip 0 when they wrap (2^32-1 -> 1).
std::int64_t counter_diff(std::uint32_t now, std::uint32_t before) noexcept {
  auto d = static_cast<std::int32_t>(now - before);
  if (d > 0 && now < before && now != 0) --d;  // crossed the wrap, which skips 0
  if (d < 0 && now > before && before != 0) ++d;
  return d;
}

}  // namespace

const char* to_string(sequence_status s) noexcept {
  switch (s) {
    case sequence_status::first: return "first";
    case sequence_status::new_state: return "new_state";
    case sequence_status::retransmission: return "retransmission";
    case sequence_status::sq_gap: return "sq_gap";
    case sequence_status::st_gap: return "st_gap";
    case sequence_status::duplicate: return "duplicate";
    case sequence_status::out_of_order: return "out_of_order";
  }
  return "?";
}

sequence_check sequence_tracker::on_message(std::uint32_t st_num, std::uint32_t sq_num,
                                            std::uint32_t tal_ms,
                                            clock::time_point now) noexcept {
  sequence_check c;
  const auto adopt = [&] {
    st_num_ = st_num;
    sq_num_ = sq_num;
  };
  if (!has_state_) {
    has_state_ = true;
    adopt();
  } else if (const auto dst = counter_diff(st_num, st_num_); dst > 0) {
    c.status = dst == 1 ? sequence_status::new_state : sequence_status::st_gap;
    c.lost = static_cast<std::uint32_t>(dst - 1);
    adopt();
  } else if (dst < 0) {
    if (st_num == 1 && sq_num == 0) {  // publisher restart
      adopt();
    } else {
      c.status = sequence_status::out_of_order;
      return c;
    }
  } else if (const auto dsq = counter_diff(sq_num, sq_num_); dsq > 0) {
    c.status = dsq == 1 ? sequence_status::retransmission : sequence_status::sq_gap;
    c.lost = static_cast<std::uint32_t>(dsq - 1);
    sq_num_ = sq_num;
  } else if (dsq == 0) {
    c.status = sequence_status::duplicate;
  } else {
    c.status = sequence_status::out_of_order;
    return c;
  }
  deadline_ = now + std::chrono::milliseconds{tal_ms} + margin;
  return c;
}

bool sequence_tracker::expired(clock::time_point now) const noexcept {
  return deadline_ && now > *deadline_;
}

void sequence_tracker::reset() noexcept {
  has_state_ = false;
  st_num_ = 0;
  sq_num_ = 0;
  deadline_.reset();
}

result<message> to_message(const message_view& v) {
  message m;
  m.destination = v.frame.destination;
  m.source = v.frame.source;
  m.vlan = v.frame.vlan;
  m.app_id = v.frame.app_id;
  m.reserved1 = v.frame.reserved1;
  m.reserved2 = v.frame.reserved2;
  const auto& p = v.pdu;
  m.gocb_ref = p.gocb_ref;
  m.time_allowed_to_live = p.time_allowed_to_live;
  m.dat_set = p.dat_set;
  if (p.go_id) m.go_id = std::string(*p.go_id);
  m.t = model::timestamp{p.t};
  m.st_num = p.st_num;
  m.sq_num = p.sq_num;
  m.simulation = p.simulation;
  m.conf_rev = p.conf_rev;
  m.nds_com = p.nds_com;
  m.num_dat_set_entries = p.num_dat_set_entries;
  for (const auto& d : p.all_data) {
    auto owned = mms::data::from_view(d);
    if (!owned) return owned.error();
    m.values.push_back(std::move(*owned));
  }
  return m;
}

// ------------------------------------------------------------------ subscriber::impl

bool subscriber::impl::matches(const frame_view& f, std::string_view gocb_ref) const noexcept {
  if (closed) return false;
  if (cfg.app_id && *cfg.app_id != f.app_id) return false;
  if (cfg.destination && *cfg.destination != f.destination) return false;
  return cfg.gocb_ref.empty() || cfg.gocb_ref == gocb_ref;
}

void subscriber::impl::on_message(const message_view& m, detail::clock::time_point now) {
  const auto& p = m.pdu;
  if ((p.simulation || m.frame.simulation()) && !cfg.accept_simulation) {
    std::lock_guard lock{stats_mutex};
    ++st.simulated_ignored;
    return;
  }
  auto msg = to_message(m);
  if (!msg) return;  // values were validated by the decoder; only a non-copyable float format

  event e;
  if (cfg.dat_set && *cfg.dat_set != p.dat_set) {
    e.reason = mismatch_reason::dat_set;
  } else if (cfg.go_id && (!p.go_id || *cfg.go_id != *p.go_id)) {
    e.reason = mismatch_reason::go_id;
  } else if (cfg.conf_rev && *cfg.conf_rev != p.conf_rev) {
    e.reason = mismatch_reason::conf_rev;
  } else if ((cfg.num_entries && *cfg.num_entries != p.num_dat_set_entries) ||
             msg->values.size() != p.num_dat_set_entries) {
    e.reason = mismatch_reason::num_entries;
  } else if (p.nds_com) {
    e.reason = mismatch_reason::nds_com;
  }
  e.kind = e.reason == mismatch_reason::none ? event_kind::message : event_kind::mismatch;

  msg->sequence = tracker.on_message(p.st_num, p.sq_num, p.time_allowed_to_live, now);
  msg->received = now;
  {
    std::lock_guard lock{stats_mutex};
    ++st.messages;
    st.lost += msg->sequence.lost;
    if (msg->sequence.status == sequence_status::duplicate) ++st.duplicates;
    if (msg->sequence.status == sequence_status::out_of_order) ++st.out_of_order;
    if (e.kind == event_kind::mismatch) ++st.mismatches;
  }
  if (msg->sequence.status != sequence_status::out_of_order) {
    last = *msg;
    last->values.clear();
  }
  e.msg = std::move(*msg);
  push(std::move(e));
  arm_timer();
}

void subscriber::impl::push(event e) {
  if (queue.push(std::move(e))) {
    std::lock_guard lock{stats_mutex};
    ++st.dropped;
  }
}

void subscriber::impl::arm_timer() {
  const auto deadline = tracker.deadline();
  if (!deadline) return;
  timer.expires_at(*deadline + std::chrono::milliseconds{1});
  timer.async_wait(asio::bind_executor(strand, [w = weak_from_this()](const asio::error_code& ec) {
    auto self = w.lock();
    if (ec || !self || self->closed) return;
    const auto now = detail::clock::now();
    if (!self->tracker.expired(now)) {
      self->arm_timer();
      return;
    }
    self->tracker.reset();
    {
      std::lock_guard lock{self->stats_mutex};
      ++self->st.timeouts;
    }
    event e;
    e.kind = event_kind::timeout;
    if (self->last) e.msg = *self->last;
    self->push(std::move(e));
  }));
}

void subscriber::impl::close_on_strand() {
  closed = true;
  timer.cancel();
  queue.close();
}

// ------------------------------------------------------------------ subscriber

subscriber::subscriber(std::shared_ptr<impl> p) noexcept : impl_(std::move(p)) {}

subscriber::~subscriber() { close(); }

asio::awaitable<result<event>> subscriber::next_event() {
  auto self = impl_;
  auto op = [](std::shared_ptr<impl> s) -> asio::awaitable<result<event>> {
    co_return co_await s->queue.pop();
  };
  co_return co_await detail::on_strand(self->strand, op(self));
}

void subscriber::set_handler(std::function<void(const event&)> handler) {
  asio::post(impl_->strand, [self = impl_, h = std::move(handler)]() mutable {
    self->queue.set_handler(std::move(h));
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

}  // namespace openiec61850::goose
