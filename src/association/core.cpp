#include "core.hpp"

#include <type_traits>
#include <utility>
#include <variant>

#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/dispatch.hpp>
#include <asio/use_awaitable.hpp>

#include "handshake.hpp"
#include "openiec61850/iso/acse/apdu.hpp"

namespace openiec61850::association::detail {

namespace acse = iso::acse;
using asio::awaitable;

namespace {

// Late responses to abandoned (timed out or cancelled) requests are discarded silently; this
// bounds how many invokeIDs are remembered for that.
constexpr std::size_t max_abandoned = 4096;
// An abort is not a release: the ABRT goes out if it can, a peer that does not read gets no longer.
constexpr std::chrono::seconds abort_linger{1};
// A batch goes out in groups: each one waits to be written, which gives the I/O thread to the other
// associations and keeps what a group charges to max_output_bytes small, whatever the batch.
constexpr std::size_t batch_group_pdus = 64;
constexpr std::size_t batch_group_bytes = 256 * 1024;
// The part of the limit a group may take, and what the transport charges per send at most.
constexpr std::size_t batch_limit_share = 4;
constexpr std::size_t batch_send_charge = 4096;

}  // namespace

clock::time_point deadline_after(std::chrono::milliseconds timeout) noexcept {
  if (timeout <= std::chrono::milliseconds::zero()) return clock::time_point::max();
  const auto now = clock::now();
  if (clock::time_point::max() - now <= timeout) return clock::time_point::max();
  return now + timeout;
}

awaitable<wait_status> wait(waiter& w, clock::time_point deadline) {
  if (!w.notified) {
    w.timer.expires_at(deadline);
    auto [ec] = co_await w.timer.async_wait(asio::as_tuple(asio::use_awaitable));
    const auto cs = co_await asio::this_coro::cancellation_state;
    if (cs.cancelled() != asio::cancellation_type::none) co_return wait_status::cancelled;
    if (w.notified) co_return wait_status::notified;
    co_return ec ? wait_status::cancelled : wait_status::timed_out;
  }
  co_return wait_status::notified;
}

core::core(transport::cotp_channel ch, ps::role role, const ps::connection_options& options,
           const mms::decode_options& d)
    : strand(ch.get_executor()), channel(std::move(ch)), pres(role, options), decode(d) {
  info.local_endpoint = channel.local_endpoint();
  info.remote_endpoint = channel.remote_endpoint();
  info.tls = channel.tls_session();
}

std::shared_ptr<send_completion> core::send_tsdu(byte_buffer tsdu) {
  auto c = std::make_shared<send_completion>(strand);
  channel.async_send(std::move(tsdu), [c](result<void> r) {
    c->outcome.emplace(r);
    c->done.notify();
  });
  return c;
}

void core::flush(byte_buffer& out) {
  if (out.empty()) return;
  send_tsdu(std::move(out));
  out.clear();
}

result<std::shared_ptr<send_completion>> core::send_mms_bytes(byte_view pdu) {
  if (closed()) return error;
  byte_buffer tsdu;
  if (auto r = pres.send_data(mms_context, pdu, tsdu); !r) return r.error();
  return send_tsdu(std::move(tsdu));
}

result<std::shared_ptr<send_completion>> core::send_mms(const mms::mms_pdu& pdu) {
  auto bytes = encode_mms(pdu);
  if (!bytes) return bytes.error();
  return send_mms_bytes(*bytes);
}

awaitable<result<void>> core::wait_sent(std::shared_ptr<send_completion> c) {
  (void)co_await wait(c->done, clock::time_point::max());
  if (c->outcome) co_return *c->outcome;
  co_return asio::error::operation_aborted;
}

void core::reject(std::optional<std::uint32_t> invoke_id, mms::reject_type type, std::int64_t reason) {
  (void)send_mms(mms::reject_pdu{invoke_id, type, reason});
}

void core::terminate(std::error_code reason, bool graceful, std::chrono::milliseconds linger) {
  if (closed()) return;
  error = reason;
  set_state(association_state::closed);
  (void)pres.on_transport_disconnect();
  for (auto& [id, p] : pending_) p->done.notify();
  slot_waiters.notify_all();
  on_terminated();
  closed_waiters.notify_all();
  if (graceful) {
    asio::co_spawn(
        strand,
        [](std::shared_ptr<core> self, std::chrono::milliseconds at_most) -> awaitable<void> {
          (void)co_await self->channel.shutdown(at_most);
        }(shared_from_this(), linger),
        asio::detached);
  } else {
    channel.close();
  }
}

void core::abort_with(std::error_code reason) {
  if (closed()) return;
  byte_buffer out;
  if (auto abrt = encode_acse(acse::abrt_apdu{acse::abort_source::service_user, std::nullopt, {}})) {
    const ps::pdv p{std::nullopt, acse_context, ps::pdv_encoding::single_asn1_type, *abrt, 0};
    if (!pres.abort({&p, 1}, out)) {
      out.clear();
      (void)pres.abort({}, out);
    }
  }
  flush(out);
  terminate(reason, true, abort_linger);
}

awaitable<result<byte_buffer>> core::receive_before(std::chrono::milliseconds timeout) {
  auto active = std::make_shared<bool>(true);
  auto expired = std::make_shared<bool>(false);
  asio::steady_timer timer(strand);
  if (timeout > std::chrono::milliseconds::zero()) {
    timer.expires_after(timeout);
    timer.async_wait([self = shared_from_this(), active, expired](std::error_code ec) {
      if (ec || !*active) return;
      *expired = true;
      self->channel.close();
    });
  }
  auto r = co_await channel.receive();
  *active = false;
  timer.cancel();
  if (!r && *expired) co_return asio::error::timed_out;
  co_return r;
}

void core::start_reader() { asio::co_spawn(strand, reader(shared_from_this()), asio::detached); }

awaitable<void> core::reader(std::shared_ptr<core> self) {
  while (!self->closed()) {
    auto tsdu = co_await self->channel.receive();
    if (!tsdu) {
      self->terminate(tsdu.error(), false);
      break;
    }
    self->handle_tsdu(std::move(*tsdu));
  }
}

void core::handle_tsdu(byte_buffer tsdu) {
  const auto buffer = std::make_shared<const byte_buffer>(std::move(tsdu));
  byte_buffer out;
  auto ev = pres.on_tsdu(*buffer, out);
  flush(out);
  if (!ev) {
    terminate(ev.error(), true);
    return;
  }
  std::visit(
      [&](const auto& e) {
        using T = std::decay_t<decltype(e)>;
        if constexpr (std::is_same_v<T, ps::data_indication>) {
          for (const auto& p : e.user_data) {
            if (closed()) return;
            if (p.context_id != mms_context || p.encoding != ps::pdv_encoding::single_asn1_type) {
              continue;  // nothing but MMS is expected in data transfer
            }
            auto pdu = received_pdu::decode(buffer, p.data, decode);
            if (pdu) {
              on_mms(std::move(*pdu));
            } else {
              on_bad_mms(p.data, pdu.error());
            }
          }
        } else if constexpr (std::is_same_v<T, ps::release_indication>) {
          on_release_indication(e.collision);
        } else if constexpr (std::is_same_v<T, ps::release_confirm>) {
          on_release_confirm();
        } else if constexpr (std::is_same_v<T, ps::user_abort_indication> ||
                             std::is_same_v<T, ps::provider_abort_indication>) {
          terminate(errc::peer_aborted, false);
        } else if constexpr (std::is_same_v<T, ps::provider_abort>) {
          terminate(e.error ? e.error : openiec61850::make_error_code(openiec61850::errc::protocol_violation),
                    true);
        } else if constexpr (std::is_same_v<T, ps::no_event>) {
        } else {
          abort_with(openiec61850::errc::protocol_violation);  // a second connect
        }
      },
      *ev);
}

// RejectPDU for an undecodable MMS PDU (ISO 9506-2 §7.5.5), never for a RejectPDU.
void core::on_bad_mms(byte_view encoding, std::error_code ec) {
  if (encoding.empty() || encoding[0] == 0xA4) return;
  const auto id = mms::peek_invoke_id(encoding);
  if (id) {
    switch (encoding[0]) {
      case 0xA0:
        reject(*id, mms::reject_type::confirmed_request, mms::reject_code::confirmed_request::invalid_argument);
        return;
      case 0xA1:
        reject(*id, mms::reject_type::confirmed_response, mms::reject_code::confirmed_response::invalid_result);
        return;
      case 0xA2:
        reject(*id, mms::reject_type::confirmed_error,
               mms::reject_code::confirmed_error::invalid_service_error);
        return;
      default:
        break;
    }
  }
  reject(std::nullopt, mms::reject_type::pdu_error,
         ec == openiec61850::errc::unsupported ? mms::reject_code::pdu_error::unknown_pdu_type
                                               : mms::reject_code::pdu_error::invalid_pdu);
}

void core::on_release_indication(bool collision) {
  byte_buffer out;
  if (auto rlre = encode_acse(acse::rlre_apdu{acse::release_response_reason::normal, {}})) {
    const ps::pdv p{std::nullopt, acse_context, ps::pdv_encoding::single_asn1_type, *rlre, 0};
    if (!pres.release_response({&p, 1}, out)) {
      terminate(openiec61850::errc::protocol_violation, false);
      return;
    }
  }
  flush(out);
  // After a collision the release completes with the peer's DN (on_release_confirm).
  if (!collision) terminate(errc::released, true);
}

void core::on_release_confirm() { terminate(errc::released, true); }

awaitable<std::error_code> core::wait_closed_op(std::shared_ptr<core> self) {
  while (!self->closed()) {
    waiter w(self->strand);
    registration reg(self->closed_waiters, w);
    if (co_await wait(w, clock::time_point::max()) == wait_status::cancelled) {
      co_return asio::error::operation_aborted;
    }
  }
  co_return self->error;
}

// --- confirmed requests issued by this side

std::uint32_t core::allocate_invoke_id() {
  while (pending_.contains(next_invoke_id_) || abandoned_.contains(next_invoke_id_)) ++next_invoke_id_;
  return next_invoke_id_++;
}

void core::abandon(std::uint32_t id) {
  if (abandoned_order_.size() == max_abandoned) {
    abandoned_.erase(abandoned_order_.front());
    abandoned_order_.pop_front();
  }
  abandoned_.insert(id);
  abandoned_order_.push_back(id);
}

// Hands the slot to the oldest waiter, or frees it.
void core::release_slot() {
  if (closed()) return;
  if (!slot_waiters.notify_one()) {
    --outstanding;
    if (outstanding == 0) on_requests_idle();
  }
}

awaitable<request_result> core::request_op(std::shared_ptr<core> self,
                                           mms::confirmed_service_request service,
                                           std::chrono::milliseconds timeout) {
  struct slot_guard {
    core* s;
    ~slot_guard() { s->release_slot(); }
  };
  struct pending_guard {
    core* s;
    std::uint32_t id;
    ~pending_guard() { s->pending_.erase(id); }
  };

  if (self->closed()) co_return self->error;
  if (self->current_state() != association_state::established) {
    co_return openiec61850::errc::invalid_state;
  }
  const auto deadline = deadline_after(timeout);
  if (self->outstanding >= self->limit || !self->slot_waiters.empty()) {
    waiter w(self->strand);
    registration reg(self->slot_waiters, w);
    const auto st = co_await wait(w, deadline);
    if (self->closed()) co_return self->error;
    if (st != wait_status::notified) {
      if (w.notified) self->release_slot();  // granted, but the caller is gone
      co_return st == wait_status::timed_out ? request_result(errc::request_timed_out)
                                             : request_result(asio::error::operation_aborted);
    }
  } else {
    ++self->outstanding;
  }
  const slot_guard slot{self.get()};

  const auto id = self->allocate_invoke_id();
  auto pdu = encode_mms(mms::confirmed_request{id, {}, std::move(service)});
  if (!pdu) co_return pdu.error();
  if (self->peer_max_pdu && pdu->size() > *self->peer_max_pdu) {
    co_return openiec61850::errc::length_overflow;
  }
  pending_request p(self->strand);
  self->pending_.emplace(id, &p);
  const pending_guard registered{self.get(), id};
  if (auto sent = self->send_mms_bytes(*pdu); !sent) co_return sent.error();

  const auto st = co_await wait(p.done, deadline);
  if (p.outcome) co_return std::move(*p.outcome);
  if (self->closed()) co_return self->error;
  self->abandon(id);
  co_return st == wait_status::timed_out ? request_result(errc::request_timed_out)
                                         : request_result(asio::error::operation_aborted);
}

// Completes the pending request `id`; false if there is none.
bool core::complete(std::uint32_t id, request_result outcome) {
  const auto it = pending_.find(id);
  if (it == pending_.end()) return false;
  if (!it->second->outcome) {
    it->second->outcome.emplace(std::move(outcome));
    it->second->done.notify();
  }
  return true;
}

// An answer to an unknown invokeID: discarded if it was abandoned, rejected otherwise.
void core::unmatched(std::uint32_t id, mms::reject_type type, std::int64_t reason) {
  if (abandoned_.erase(id) != 0) {
    std::erase(abandoned_order_, id);
    return;
  }
  reject(id, type, reason);
}

void core::on_answer(received_pdu m) {
  const auto& pdu = m.pdu();
  if (const auto* response = std::get_if<mms::confirmed_response>(&pdu)) {
    const auto id = response->invoke_id;
    if (!complete(id, service_response(std::move(m)))) {
      unmatched(id, mms::reject_type::confirmed_response,
                mms::reject_code::confirmed_response::invalid_invoke_id);
    }
  } else if (const auto* e = std::get_if<mms::confirmed_error>(&pdu)) {
    request_error err{errc::service_error, service_error_info::from(e->error), e->modifier_position, {}};
    if (!complete(e->invoke_id, std::move(err))) {
      unmatched(e->invoke_id, mms::reject_type::confirmed_error,
                mms::reject_code::confirmed_error::invalid_invoke_id);
    }
  } else if (const auto* r = std::get_if<mms::reject_pdu>(&pdu);
             r != nullptr && r->original_invoke_id && r->type != mms::reject_type::confirmed_response &&
             r->type != mms::reject_type::confirmed_error) {
    // A reject of one of our answers names an invokeID of the peer's, not of a request of ours.
    request_error err{errc::request_rejected, {}, {}, reject_info{r->original_invoke_id, r->type, r->reason}};
    (void)complete(*r->original_invoke_id, std::move(err));
  }
}

// --- confirmed requests received

bool core::admit(std::uint32_t id, bool open) {
  using namespace mms::reject_code;
  if (incoming.contains(id)) {
    reject(id, mms::reject_type::confirmed_request, confirmed_request::invalid_invoke_id);
  } else if (incoming.size() >= incoming_limit) {
    reject(id, mms::reject_type::confirmed_request, confirmed_request::max_serv_outstanding_exceeded);
  } else if (!open) {
    reject(id, mms::reject_type::confirmed_request, confirmed_request::other);
  } else {
    incoming.insert(id);
    return true;
  }
  return false;
}

incoming_request core::make_incoming(std::shared_ptr<core> self, received_pdu m) {
  return incoming_request(std::move(self), std::move(m));
}

awaitable<result<void>> core::answer_op(std::shared_ptr<core> self, std::uint32_t id, byte_buffer pdu) {
  if (self->closed()) co_return self->error;
  if (self->incoming.erase(id) == 0) co_return openiec61850::errc::invalid_state;
  auto sent = self->send_mms_bytes(pdu);
  if (!sent) co_return sent.error();
  co_return co_await wait_sent(std::move(*sent));
}

awaitable<result<void>> core::send_op(std::shared_ptr<core> self, byte_buffer pdu) {
  if (self->closed()) co_return self->error;
  auto sent = self->send_mms_bytes(pdu);
  if (!sent) co_return sent.error();
  co_return co_await wait_sent(std::move(*sent));
}

awaitable<result<void>> core::send_batch_op(std::shared_ptr<core> self,
                                            std::vector<outbound_pdu> batch) {
  auto group_pdus = batch_group_pdus;
  auto group_bytes = batch_group_bytes;
  if (self->max_output_bytes > 0) {
    const auto share = self->max_output_bytes / batch_limit_share;
    group_pdus = std::clamp<std::size_t>(share / batch_send_charge, 1, group_pdus);
    group_bytes = std::min(group_bytes, share);
  }
  std::shared_ptr<send_completion> last;
  std::size_t pdus = 0;
  std::size_t bytes = 0;
  for (auto& item : batch) {
    if (self->closed()) co_return self->error;
    if (item.answers && self->incoming.erase(*item.answers) == 0) {
      co_return openiec61850::errc::invalid_state;
    }
    auto sent = self->send_mms_bytes(item.pdu);
    if (!sent) co_return sent.error();
    last = std::move(*sent);
    bytes += item.pdu.size();
    byte_buffer().swap(item.pdu);
    if (++pdus >= group_pdus || bytes >= group_bytes) {
      auto written = co_await wait_sent(std::move(last));
      if (!written) co_return written;
      last.reset();
      pdus = 0;
      bytes = 0;
    }
  }
  if (last) co_return co_await wait_sent(std::move(last));
  co_return result<void>{};
}

}  // namespace openiec61850::association::detail

namespace openiec61850::association {

// --- incoming_request

incoming_request::incoming_request(std::shared_ptr<detail::core> state, received_pdu message) noexcept
    : state_(std::move(state)), message_(std::move(message)) {}

incoming_request& incoming_request::operator=(incoming_request&& other) noexcept {
  if (this != &other) {
    const incoming_request previous(std::move(*this));  // answered on destruction if needed
    state_ = std::move(other.state_);
    message_ = std::move(other.message_);
    answered_ = other.answered_;
  }
  return *this;
}

incoming_request::~incoming_request() {
  if (!state_ || answered_) return;
  auto pdu = detail::encode_mms(mms::confirmed_error{
      invoke_id(), std::nullopt, mms::service_error(mms::error_class::service, mms::error_code::service::other)});
  if (!pdu) return;
  asio::dispatch(state_->strand, [s = state_, id = invoke_id(), bytes = std::move(*pdu)]() mutable {
    if (s->closed() || s->incoming.erase(id) == 0) return;
    (void)s->send_mms_bytes(bytes);
  });
}

asio::awaitable<result<void>> incoming_request::answer(result<byte_buffer> pdu) {
  if (!state_) return detail::ready(result<void>(openiec61850::errc::invalid_state));
  if (!pdu) return detail::ready(result<void>(pdu.error()));
  return answer(std::move(*pdu));
}

asio::awaitable<result<void>> incoming_request::answer(byte_buffer pdu) {
  if (!state_) return detail::ready(result<void>(openiec61850::errc::invalid_state));
  if (answered_) return detail::ready(result<void>(openiec61850::errc::invalid_state));
  answered_ = true;
  return detail::on_strand(state_->strand, detail::core::answer_op(state_, invoke_id(), std::move(pdu)));
}

result<outbound_pdu> incoming_request::encoded_answer(byte_buffer pdu) {
  if (!state_ || answered_) return openiec61850::errc::invalid_state;
  answered_ = true;
  outbound_pdu out;
  out.answers = invoke_id();
  out.pdu = std::move(pdu);
  return out;
}

asio::awaitable<result<void>> incoming_request::respond(const mms::confirmed_service_response& response) {
  return answer(detail::encode_mms(mms::confirmed_response{invoke_id(), response}));
}

asio::awaitable<result<void>> incoming_request::respond_error(const mms::service_error& error,
                                                              std::optional<std::uint32_t> modifier_position) {
  return answer(detail::encode_mms(mms::confirmed_error{invoke_id(), modifier_position, error}));
}

asio::awaitable<result<void>> incoming_request::reject(std::int64_t reason) {
  return answer(detail::encode_mms(
      mms::reject_pdu{invoke_id(), mms::reject_type::confirmed_request, reason}));
}

}  // namespace openiec61850::association
