#include "openiec61850/association/client_association.hpp"

#include <deque>
#include <utility>
#include <variant>

#include <asio/dispatch.hpp>

#include "core.hpp"
#include "handshake.hpp"

namespace openiec61850::association {
namespace detail {

namespace acse = iso::acse;
using asio::awaitable;

struct queued_unconfirmed {
  received_pdu message;
  std::size_t lost_before = 0;
};

enum class conclude_state : std::uint8_t { idle, waiting, accepted, refused };

struct client_state final : core {
  client_state(transport::cotp_channel ch, association_params p)
      : core(std::move(ch), ps::role::initiator, initiator_options(p), p.decode),
        params(std::move(p)) {
    if (params.unconfirmed_queue_capacity == 0) params.unconfirmed_queue_capacity = 1;
  }

  association_params params;

  std::deque<queued_unconfirmed> unconfirmed;
  waiter* unconfirmed_consumer = nullptr;
  std::function<void(unconfirmed_message)> unconfirmed_handler;
  std::atomic<std::uint64_t> dropped{0};

  std::function<void(incoming_request)> request_handler;

  waiter* release_waiter = nullptr;
  conclude_state conclude = conclude_state::idle;

  void notify_release() {
    if (release_waiter != nullptr) release_waiter->notify();
  }

  // --- establishment

  static awaitable<result<void>> establish_op(std::shared_ptr<client_state> self) {
    byte_buffer out;
    if (auto r = connect_request(self->pres, self->params, out); !r) {
      self->terminate(r.error(), false);
      co_return r;
    }
    self->flush(out);
    auto tsdu = co_await self->receive_before(self->params.association_timeout);
    if (!tsdu) {
      self->terminate(tsdu.error(), false);
      co_return tsdu.error();
    }
    const byte_buffer buffer = std::move(*tsdu);
    auto ev = self->pres.on_tsdu(buffer, out);
    self->flush(out);
    if (!ev) {
      self->terminate(ev.error(), true);
      co_return ev.error();
    }
    auto response = parse_associate_response(*ev, self->params.initiate, self->decode);
    if (response.error) {
      if (self->pres.current_state() == ps::state::data_transfer) {
        self->abort_with(response.error);
      } else {
        self->terminate(response.error, true);
      }
      co_return response.error;
    }
    auto& n = response.negotiated;
    self->limit = static_cast<std::size_t>(n.max_serv_outstanding_calling);
    self->incoming_limit = static_cast<std::size_t>(n.max_serv_outstanding_called);
    if (n.local_detail_called && *n.local_detail_called > 0) {
      self->peer_max_pdu = static_cast<std::size_t>(*n.local_detail_called);
    }
    self->info.negotiated = n;
    self->info.peer_ap_title = response.responding_ap_title;
    self->info.peer_ae_qualifier = response.responding_ae_qualifier;
    self->start_reader();
    co_return result<void>{};
  }

  // --- unconfirmed

  void push_unconfirmed(received_pdu pdu) {
    if (unconfirmed_handler) {
      unconfirmed_handler(unconfirmed_message(std::move(pdu), 0));
      return;
    }
    std::size_t lost = 0;
    if (unconfirmed.size() >= params.unconfirmed_queue_capacity) {
      lost = unconfirmed.front().lost_before + 1;
      unconfirmed.pop_front();
      dropped.fetch_add(1);
      if (!unconfirmed.empty()) {
        unconfirmed.front().lost_before += lost;
        lost = 0;
      }
    }
    unconfirmed.push_back({std::move(pdu), lost});
    if (unconfirmed_consumer != nullptr) unconfirmed_consumer->notify();
  }

  void set_handler(std::function<void(unconfirmed_message)> handler) {
    unconfirmed_handler = std::move(handler);
    if (!unconfirmed_handler) return;
    while (!unconfirmed.empty()) {
      auto q = std::move(unconfirmed.front());
      unconfirmed.pop_front();
      unconfirmed_handler(unconfirmed_message(std::move(q.message), q.lost_before));
    }
  }

  static awaitable<result<unconfirmed_message>> next_unconfirmed_op(std::shared_ptr<client_state> self) {
    if (self->unconfirmed_consumer != nullptr) co_return openiec61850::errc::invalid_state;
    for (;;) {
      if (!self->unconfirmed.empty()) {
        auto q = std::move(self->unconfirmed.front());
        self->unconfirmed.pop_front();
        co_return unconfirmed_message(std::move(q.message), q.lost_before);
      }
      if (self->closed()) co_return self->error;
      waiter w(self->strand);
      self->unconfirmed_consumer = &w;
      struct reset {
        waiter*& slot;
        ~reset() { slot = nullptr; }
      } guard{self->unconfirmed_consumer};
      if (co_await wait(w, clock::time_point::max()) == wait_status::cancelled) {
        co_return asio::error::operation_aborted;
      }
    }
  }

  // --- release

  // Waits for `done` (re-checked after every wake-up) until the release deadline.
  template <typename Done>
  awaitable<wait_status> wait_release(clock::time_point deadline, Done done) {
    while (!closed() && !done()) {
      waiter w(strand);
      release_waiter = &w;
      const auto st = co_await wait(w, deadline);
      release_waiter = nullptr;
      if (st != wait_status::notified) co_return st;
    }
    co_return wait_status::notified;
  }

  static awaitable<result<void>> release_op(std::shared_ptr<client_state> self) {
    if (self->closed()) co_return self->error;
    if (self->current_state() != association_state::established) {
      co_return openiec61850::errc::invalid_state;
    }
    self->set_state(association_state::releasing);
    const auto deadline = deadline_after(self->params.release_timeout);
    auto fail = [&](wait_status st) -> result<void> {
      const std::error_code ec = st == wait_status::timed_out
                                     ? std::error_code(asio::error::timed_out)
                                     : std::error_code(asio::error::operation_aborted);
      self->abort_with(errc::aborted);
      return ec;
    };

    // ISO 9506-1 §8.4: Conclude requires that no request is outstanding.
    auto st = co_await self->wait_release(
        deadline, [&] { return self->requests_idle(); });
    if (self->closed()) co_return self->error;
    if (st != wait_status::notified) co_return fail(st);

    self->conclude = conclude_state::waiting;
    if (auto sent = self->send_mms(mms::conclude_request{}); !sent) {
      self->abort_with(sent.error());
      co_return sent.error();
    }
    st = co_await self->wait_release(deadline, [&] { return self->conclude != conclude_state::waiting; });
    if (self->closed()) co_return self->error;
    if (st != wait_status::notified) co_return fail(st);
    if (self->conclude == conclude_state::refused) {
      self->conclude = conclude_state::idle;
      self->set_state(association_state::established);
      co_return errc::conclude_refused;
    }

    // A-RELEASE (X.227 §7.2) on P-RELEASE.
    byte_buffer out;
    auto rlrq = encode_acse(acse::rlrq_apdu{acse::release_request_reason::normal, {}});
    if (!rlrq) co_return rlrq.error();
    const ps::pdv p{std::nullopt, self->acse_context, ps::pdv_encoding::single_asn1_type, *rlrq, 0};
    if (auto r = self->pres.release({&p, 1}, out); !r) {
      self->abort_with(r.error());
      co_return r;
    }
    self->flush(out);
    st = co_await self->wait_release(deadline, [] { return false; });
    if (self->error == errc::released) co_return result<void>{};
    if (self->closed()) co_return self->error;
    co_return fail(st);
  }

  // --- core hooks

  void on_mms(received_pdu m) override {
    const auto& pdu = m.pdu();
    switch (mms::type_of(pdu)) {
      case mms::pdu_type::confirmed_response:
      case mms::pdu_type::confirmed_error:
      case mms::pdu_type::reject:
        on_answer(std::move(m));
        break;
      case mms::pdu_type::unconfirmed:
        push_unconfirmed(std::move(m));
        break;
      case mms::pdu_type::conclude_response:
      case mms::pdu_type::conclude_error:
        if (conclude == conclude_state::waiting) {
          conclude = mms::type_of(pdu) == mms::pdu_type::conclude_response ? conclude_state::accepted
                                                                           : conclude_state::refused;
          notify_release();
        }
        break;
      case mms::pdu_type::confirmed_request: {
        const auto id = std::get<mms::confirmed_request>(pdu).invoke_id;
        if (!request_handler) {
          reject(id, mms::reject_type::confirmed_request,
                 mms::reject_code::confirmed_request::unrecognized_service);
        } else if (admit(id, conclude == conclude_state::idle)) {
          // A release only waits: the server may be reading a file for an outstanding obtainFile.
          request_handler(make_incoming(shared_from_this(), std::move(m)));
        }
        break;
      }
      case mms::pdu_type::cancel_request:
        (void)send_mms(mms::cancel_error{
            std::get<mms::cancel_request>(pdu).invoke_id,
            mms::service_error(mms::error_class::cancel, mms::error_code::cancel::cancel_not_possible)});
        break;
      case mms::pdu_type::conclude_request:
        reject(std::nullopt, mms::reject_type::conclude_request, 0);
        break;
      default:
        break;
    }
  }

  void on_requests_idle() override { notify_release(); }

  void on_terminated() override {
    if (unconfirmed_consumer != nullptr) unconfirmed_consumer->notify();
    notify_release();
  }
};

}  // namespace detail

using detail::client_state;

client_association::client_association(std::shared_ptr<client_state> state) noexcept
    : state_(std::move(state)) {}

client_association& client_association::operator=(client_association&& other) noexcept {
  if (this != &other) {
    abort();
    state_ = std::move(other.state_);
  }
  return *this;
}

client_association::~client_association() { abort(); }

asio::awaitable<result<client_association>> client_association::connect(asio::any_io_executor ex,
                                                                         association_params params) {
  auto channel =
      co_await transport::cotp_channel::connect(ex, params.host, params.port, params.transport);
  if (!channel) co_return channel.error();
  auto state = std::make_shared<client_state>(std::move(*channel), std::move(params));
  auto r = co_await detail::on_strand(state->strand, client_state::establish_op(state));
  if (!r) co_return r.error();
  co_return client_association(std::move(state));
}

asio::awaitable<request_result> client_association::request(mms::confirmed_service_request service) {
  if (!state_) return detail::ready(request_result(openiec61850::errc::invalid_state));
  return request(std::move(service), state_->params.request_timeout);
}

asio::awaitable<request_result> client_association::request(mms::confirmed_service_request service,
                                                            std::chrono::milliseconds timeout) {
  if (!state_) return detail::ready(request_result(openiec61850::errc::invalid_state));
  return detail::on_strand(state_->strand, detail::core::request_op(state_, std::move(service), timeout));
}

asio::awaitable<result<unconfirmed_message>> client_association::next_unconfirmed() {
  if (!state_) return detail::ready(result<unconfirmed_message>(openiec61850::errc::invalid_state));
  return detail::on_strand(state_->strand, client_state::next_unconfirmed_op(state_));
}

void client_association::set_unconfirmed_handler(std::function<void(unconfirmed_message)> handler) {
  if (!state_) return;
  asio::dispatch(state_->strand,
                 [s = state_, h = std::move(handler)]() mutable { s->set_handler(std::move(h)); });
}

void client_association::set_request_handler(std::function<void(incoming_request)> handler) {
  if (!state_) return;
  asio::dispatch(state_->strand,
                 [s = state_, h = std::move(handler)]() mutable { s->request_handler = std::move(h); });
}

asio::awaitable<result<void>> client_association::release() {
  if (!state_) return detail::ready(result<void>(openiec61850::errc::invalid_state));
  return detail::on_strand(state_->strand, client_state::release_op(state_));
}

void client_association::abort() noexcept {
  if (!state_) return;
  asio::dispatch(state_->strand, [s = state_] { s->abort_with(errc::aborted); });
}

asio::awaitable<std::error_code> client_association::wait_closed() {
  if (!state_) return detail::ready(openiec61850::make_error_code(openiec61850::errc::invalid_state));
  return detail::on_strand(state_->strand, detail::core::wait_closed_op(state_));
}

association_state client_association::state() const noexcept {
  return state_ ? state_->current_state() : association_state::closed;
}

std::uint64_t client_association::unconfirmed_dropped() const noexcept {
  return state_ ? state_->dropped.load() : 0;
}

const association_info& client_association::info() const noexcept { return state_->info; }

client_association::executor_type client_association::get_executor() const noexcept {
  return state_->strand;
}

}  // namespace openiec61850::association
