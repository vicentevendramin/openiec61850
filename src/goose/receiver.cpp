#include "openiec61850/goose/receiver.hpp"

#include <array>
#include <mutex>
#include <vector>

#include <asio/bind_cancellation_slot.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/co_spawn.hpp>
#include <asio/post.hpp>

#include "subscription_impl.hpp"

namespace openiec61850::goose {

struct receiver::impl : std::enable_shared_from_this<receiver::impl> {
  explicit impl(std::shared_ptr<link> lk)
      : l(std::move(lk)), strand(asio::make_strand(l->get_executor())) {}

  std::shared_ptr<link> l;
  detail::strand_type strand;
  // On the strand.
  bool running = false;
  std::uint64_t generation = 0;
  asio::cancellation_signal cancel;
  std::vector<std::shared_ptr<subscriber::impl>> goose_subs;
  std::vector<std::shared_ptr<sv::subscriber::impl>> sv_subs;

  mutable std::mutex stats_mutex;
  receiver_stats st;

  void count(std::uint64_t receiver_stats::*field) {
    std::lock_guard lock{stats_mutex};
    ++(st.*field);
  }

  void dispatch(byte_view frame) {
    count(&receiver_stats::frames);
    const auto now = detail::clock::now();
    const auto type = peek_ether_type(frame);
    if (type == ethertype_goose) {
      std::erase_if(goose_subs, [](const auto& s) { return s->closed.load(); });
      auto m = decode(frame);
      if (!m) {
        count(&receiver_stats::malformed);
        return;
      }
      bool matched = false;
      for (const auto& s : goose_subs) {
        if (s->matches(m->frame, m->pdu.gocb_ref)) {
          matched = true;
          s->on_message(*m, now);
        }
      }
      if (!matched) count(&receiver_stats::unmatched);
    } else if (type == ethertype_sv) {
      std::erase_if(sv_subs, [](const auto& s) { return s->closed.load(); });
      auto m = sv::decode(frame);
      if (!m) {
        count(&receiver_stats::malformed);
        return;
      }
      bool matched = false;
      for (const auto& s : sv_subs) {
        if (s->matches(m->frame)) {
          matched = true;
          s->on_message(*m, now);
        }
      }
      if (!matched) count(&receiver_stats::unmatched);
    } else {
      count(&receiver_stats::other);
    }
  }

  static asio::awaitable<void> loop(std::shared_ptr<impl> self, std::uint64_t gen) {
    co_await asio::this_coro::throw_if_cancelled(false);
    std::vector<std::uint8_t> buffer(9216);  // jumbo frame
    while (self->running && self->generation == gen) {
      auto n = co_await self->l->receive(buffer);
      if (!self->running || self->generation != gen) break;
      if (!n) {
        if (n.error() == asio::error::operation_aborted ||
            n.error() == make_error_code(errc::invalid_state)) {
          break;  // link closed
        }
        continue;
      }
      self->dispatch(byte_view{buffer.data(), *n});
    }
  }

  void start_on_strand() {
    if (running) return;
    running = true;
    const auto gen = ++generation;
    asio::co_spawn(strand, loop(shared_from_this(), gen),
                   asio::bind_cancellation_slot(cancel.slot(), [](std::exception_ptr) {}));
  }

  void stop_on_strand() {
    if (running) {
      running = false;
      ++generation;
      cancel.emit(asio::cancellation_type::terminal);
    }
    for (auto& s : goose_subs) s->close_on_strand();
    for (auto& s : sv_subs) s->close_on_strand();
    goose_subs.clear();
    sv_subs.clear();
  }
};

std::shared_ptr<receiver> receiver::create(std::shared_ptr<link> l) {
  return std::make_shared<receiver>(std::make_shared<impl>(std::move(l)));
}

receiver::receiver(std::shared_ptr<impl> p) noexcept : impl_(std::move(p)) {}

receiver::~receiver() { stop(); }

void receiver::start() {
  asio::post(impl_->strand, [self = impl_] { self->start_on_strand(); });
}

void receiver::stop() {
  asio::post(impl_->strand, [self = impl_] { self->stop_on_strand(); });
}

std::shared_ptr<subscriber> receiver::subscribe(subscriber_config config) {
  auto s = std::make_shared<subscriber::impl>(impl_->strand, std::move(config));
  asio::post(impl_->strand, [self = impl_, s] { self->goose_subs.push_back(s); });
  return std::make_shared<subscriber>(std::move(s));
}

std::shared_ptr<sv::subscriber> receiver::subscribe(sv::subscriber_config config) {
  auto s = std::make_shared<sv::subscriber::impl>(impl_->strand, std::move(config));
  asio::post(impl_->strand, [self = impl_, s] { self->sv_subs.push_back(s); });
  return std::make_shared<sv::subscriber>(std::move(s));
}

receiver_stats receiver::stats() const {
  std::lock_guard lock{impl_->stats_mutex};
  return impl_->st;
}

asio::any_io_executor receiver::get_executor() const { return impl_->strand; }

}  // namespace openiec61850::goose
