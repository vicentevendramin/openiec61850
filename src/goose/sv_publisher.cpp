#include "openiec61850/goose/sv_publisher.hpp"

#include <mutex>
#include <vector>

#include <asio/bind_executor.hpp>
#include <asio/post.hpp>
#include <asio/steady_timer.hpp>

#include "detail.hpp"
#include "openiec61850/model/timestamp.hpp"
#include "openiec61850/model/timestamp.hpp"

namespace openiec61850::sv {

struct publisher::impl : std::enable_shared_from_this<publisher::impl> {
  impl(std::shared_ptr<goose::link> lk, publisher_config c)
      : l(std::move(lk)),
        cfg(std::move(c)),
        strand(asio::make_strand(l->get_executor())),
        timer(strand) {
    header.destination = cfg.destination;
    header.source = cfg.source.value_or(l->address());
    header.vlan = cfg.vlan;
    header.app_id = cfg.app_id;
    header.reserved1 = cfg.simulation ? goose::reserved1_simulation : std::uint16_t{0};
    // Per-ASDU sample storage, so that ASDUs can borrow it until the frame is sent.
    samples.resize(cfg.asdus_per_frame);
    pending.reserve(cfg.asdus_per_frame);
  }

  std::shared_ptr<goose::link> l;
  publisher_config cfg;
  frame_header header;
  goose::detail::strand_type strand;
  asio::steady_timer timer;

  std::vector<byte_buffer> samples;
  std::vector<asdu> pending;
  byte_buffer frame;
  std::uint16_t next_cnt = 0;

  mutable std::mutex stats_mutex;
  publisher_stats st;

  // Timer mode (on the strand).
  bool running = false;
  std::uint64_t generation = 0;
  std::chrono::nanoseconds period{};
  goose::detail::clock::time_point next_due{};
  sample_source source;
  byte_buffer scratch;

  result<std::uint16_t> push(byte_view seq_data, std::optional<mms::utc_time> refr_tm) {
    const std::uint16_t cnt = next_cnt;
    const std::uint32_t wrap = cfg.smp_cnt_wrap == 0 ? 0x10000U : cfg.smp_cnt_wrap;
    next_cnt = static_cast<std::uint16_t>((static_cast<std::uint32_t>(cnt) + 1U) % wrap);

    auto& storage = samples[pending.size()];
    storage.assign(seq_data.begin(), seq_data.end());
    asdu a;
    a.sv_id = cfg.sv_id;
    if (cfg.dat_set) a.dat_set = *cfg.dat_set;
    a.smp_cnt = cnt;
    a.conf_rev = cfg.conf_rev;
    if (cfg.refresh_time) {
      a.refr_tm = refr_tm ? *refr_tm : model::timestamp::now().utc_time();
    }
    a.smp_synch = cfg.smp_synch;
    a.smp_rate = cfg.smp_rate;
    a.seq_data = storage;
    if (cfg.smp_mod && *cfg.smp_mod != static_cast<std::uint16_t>(sample_mode::samples_per_period)) {
      a.smp_mod = cfg.smp_mod;
    }
    pending.push_back(a);

    result<void> r;
    bool sent = false;
    if (pending.size() == cfg.asdus_per_frame) {
      frame.clear();
      r = encode(header, pending, frame);
      if (r) r = l->send(frame);
      pending.clear();
      sent = true;
    }
    {
      std::lock_guard lock{stats_mutex};
      ++st.samples;
      st.next_smp_cnt = next_cnt;
      if (sent) {
        if (r) {
          ++st.frames_sent;
        } else {
          ++st.send_errors;
        }
      }
    }
    if (!r) return r.error();
    return cnt;
  }

  void tick(std::uint64_t gen) {
    if (!running || gen != generation) return;
    const auto now = goose::detail::clock::now();
    // Catch up with the samples that are due (bounded, so a long stall does not burst forever).
    for (int i = 0; i < 1000 && next_due <= now; ++i) {
      scratch.clear();
      source(next_cnt, scratch);
      (void)push(scratch, std::nullopt);
      next_due += period;
    }
    if (next_due <= now) next_due = now + period;
    timer.expires_at(next_due);
    timer.async_wait(asio::bind_executor(strand, [w = weak_from_this(), gen](const asio::error_code& ec) {
      auto self = w.lock();
      if (!ec && self) self->tick(gen);
    }));
  }
};

result<std::shared_ptr<publisher>> publisher::create(std::shared_ptr<goose::link> l,
                                                     publisher_config config) {
  if (!l || config.sv_id.empty() || config.asdus_per_frame == 0) return errc::invalid_state;
  return std::make_shared<publisher>(std::make_shared<impl>(std::move(l), std::move(config)));
}

publisher::publisher(std::shared_ptr<impl> p) noexcept : impl_(std::move(p)) {}

publisher::~publisher() { stop(); }

result<std::uint16_t> publisher::push(byte_view seq_data, std::optional<mms::utc_time> refr_tm) {
  return impl_->push(seq_data, refr_tm);
}

result<std::uint16_t> publisher::push(const le::samples& s, std::optional<mms::utc_time> refr_tm) {
  const auto bytes = le::encode(s);
  return impl_->push(bytes, refr_tm);
}

result<void> publisher::start(std::chrono::nanoseconds period, sample_source source) {
  if (period.count() <= 0 || !source) return errc::invalid_state;
  asio::post(impl_->strand, [self = impl_, period, src = std::move(source)]() mutable {
    if (self->running) return;
    self->running = true;
    self->period = period;
    self->source = std::move(src);
    self->next_due = goose::detail::clock::now();
    self->tick(++self->generation);
  });
  return {};
}

void publisher::stop() {
  asio::post(impl_->strand, [self = impl_] {
    self->running = false;
    ++self->generation;
    self->timer.cancel();
  });
}

const publisher_config& publisher::config() const noexcept { return impl_->cfg; }

publisher_stats publisher::stats() const {
  std::lock_guard lock{impl_->stats_mutex};
  return impl_->st;
}

}  // namespace openiec61850::sv
