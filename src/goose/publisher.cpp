#include "openiec61850/goose/publisher.hpp"

#include <algorithm>
#include <mutex>

#include <asio/bind_executor.hpp>
#include <asio/post.hpp>
#include <asio/steady_timer.hpp>

#include "detail.hpp"
#include "openiec61850/goose/pdu.hpp"

namespace openiec61850::goose {

std::chrono::milliseconds retransmission_interval(std::uint32_t sq_num,
                                                  std::chrono::milliseconds min_time,
                                                  std::chrono::milliseconds max_time) noexcept {
  if (min_time.count() <= 0 || sq_num == 0) return std::max(min_time, std::chrono::milliseconds{0});
  auto v = min_time;
  for (std::uint32_t i = 1; i < sq_num && v < max_time; ++i) v *= 2;
  return std::min(v, std::max(max_time, min_time));
}

namespace {

std::uint32_t next_counter(std::uint32_t v) noexcept { return v == 0xFFFFFFFFU ? 1U : v + 1U; }

result<byte_buffer> encode_values(const std::vector<mms::data>& values) {
  byte_buffer out;
  ber::writer w{out};
  for (const auto& v : values) {
    if (auto r = v.encode(w); !r) return r.error();
  }
  return out;
}

}  // namespace

struct publisher::impl : std::enable_shared_from_this<impl> {
  impl(std::shared_ptr<link> lk, publisher_config c)
      : l(std::move(lk)),
        cfg(std::move(c)),
        strand(asio::make_strand(l->get_executor())),
        timer(strand) {}

  std::shared_ptr<link> l;
  publisher_config cfg;
  detail::strand_type strand;
  asio::steady_timer timer;

  mutable std::mutex mutex;
  std::vector<mms::data> values;
  byte_buffer all_data;
  mms::utc_time t;
  std::uint32_t st_num = 0;
  std::uint32_t sq_num = 0;
  bool running = false;
  std::uint64_t generation = 0;
  detail::clock::time_point last_sent{};
  byte_buffer frame;
  publisher_stats st;

  std::chrono::milliseconds tal_for(std::uint32_t sq) const noexcept {
    if (cfg.tal_override) return *cfg.tal_override;
    return retransmission_interval(next_counter(sq), cfg.min_time, cfg.max_time) *
           cfg.tal_multiplier;
  }

  // Requires the mutex.
  void send_locked() {
    frame_header h;
    h.destination = cfg.destination;
    h.source = cfg.source.value_or(l->address());
    h.vlan = cfg.vlan;
    h.app_id = cfg.app_id;
    h.reserved1 = cfg.simulation ? reserved1_simulation : std::uint16_t{0};
    pdu_fields f;
    f.gocb_ref = cfg.gocb_ref;
    f.time_allowed_to_live = static_cast<std::uint32_t>(tal_for(sq_num).count());
    f.dat_set = cfg.dat_set;
    f.go_id = cfg.go_id;
    f.t = t;
    f.st_num = st_num;
    f.sq_num = sq_num;
    f.simulation = cfg.simulation;
    f.conf_rev = cfg.conf_rev;
    f.nds_com = cfg.nds_com;
    frame.clear();
    h.ether_type = ethertype_goose;
    const auto start = begin_frame(frame, h);
    auto r = encode_pdu_raw(f, all_data, static_cast<std::uint32_t>(values.size()), frame);
    if (r) r = finish_frame(frame, start);
    if (r) r = l->send(frame);
    last_sent = detail::clock::now();
    if (r) {
      ++st.messages_sent;
    } else {
      ++st.send_errors;
      st.last_error = r.error();
    }
    st.st_num = st_num;
    st.sq_num = sq_num;
  }

  // Requires the mutex. A new state with the current values.
  void event_locked(std::optional<model::timestamp> when) {
    st_num = next_counter(st_num);
    sq_num = 0;
    t = when ? when->utc_time() : model::timestamp::now(cfg.time_accuracy).utc_time();
    running = true;
    const auto gen = ++generation;
    send_locked();
    asio::post(strand, [self = shared_from_this(), gen] { self->schedule(gen); });
  }

  // On the strand.
  void schedule(std::uint64_t gen) {
    detail::clock::time_point due;
    {
      std::lock_guard lock{mutex};
      if (!running || gen != generation) return;
      due = last_sent + retransmission_interval(next_counter(sq_num), cfg.min_time, cfg.max_time);
    }
    timer.expires_at(due);
    timer.async_wait(asio::bind_executor(
        strand, [w = weak_from_this(), gen](const asio::error_code& ec) {
          auto self = w.lock();
          if (ec || !self) return;
          {
            std::lock_guard lock{self->mutex};
            if (!self->running || gen != self->generation) return;
            self->sq_num = next_counter(self->sq_num);
            self->send_locked();
          }
          self->schedule(gen);
        }));
  }

  void stop() {
    {
      std::lock_guard lock{mutex};
      if (!running) return;
      running = false;
      ++generation;
    }
    asio::post(strand, [self = shared_from_this()] { self->timer.cancel(); });
  }
};

result<std::shared_ptr<publisher>> publisher::create(std::shared_ptr<link> l,
                                                     publisher_config config,
                                                     std::vector<mms::data> values) {
  if (!l || config.gocb_ref.empty() || config.dat_set.empty() || config.min_time.count() <= 0 ||
      config.max_time < config.min_time || config.tal_multiplier == 0) {
    return errc::invalid_state;
  }
  auto enc = encode_values(values);
  if (!enc) return errc::invalid_state;
  auto p = std::make_shared<impl>(std::move(l), std::move(config));
  p->values = std::move(values);
  p->all_data = std::move(*enc);
  return std::make_shared<publisher>(std::move(p));
}

publisher::publisher(std::shared_ptr<impl> p) noexcept : impl_(std::move(p)) {}

publisher::~publisher() { impl_->stop(); }

void publisher::start() {
  std::lock_guard lock{impl_->mutex};
  if (impl_->running) return;
  impl_->event_locked(std::nullopt);
}

void publisher::stop() { impl_->stop(); }

result<void> publisher::publish(std::vector<mms::data> values,
                                std::optional<model::timestamp> when) {
  auto enc = encode_values(values);
  if (!enc) return errc::invalid_state;
  std::lock_guard lock{impl_->mutex};
  impl_->values = std::move(values);
  impl_->all_data = std::move(*enc);
  impl_->event_locked(when);
  return {};
}

result<bool> publisher::update(std::vector<mms::data> values,
                               std::optional<model::timestamp> when) {
  auto enc = encode_values(values);
  if (!enc) return errc::invalid_state;
  std::lock_guard lock{impl_->mutex};
  if (*enc == impl_->all_data && impl_->values.size() == values.size()) return false;
  impl_->values = std::move(values);
  impl_->all_data = std::move(*enc);
  impl_->event_locked(when);
  return true;
}

void publisher::set_nds_com(bool on) {
  std::lock_guard lock{impl_->mutex};
  impl_->cfg.nds_com = on;
}

void publisher::set_simulation(bool on) {
  std::lock_guard lock{impl_->mutex};
  impl_->cfg.simulation = on;
}

const publisher_config& publisher::config() const noexcept { return impl_->cfg; }

publisher_stats publisher::stats() const {
  std::lock_guard lock{impl_->mutex};
  return impl_->st;
}

}  // namespace openiec61850::goose
