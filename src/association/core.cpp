#include "core.hpp"

#include <type_traits>
#include <utility>
#include <variant>

#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/use_awaitable.hpp>

#include "handshake.hpp"
#include "openiec61850/iso/acse/apdu.hpp"

namespace openiec61850::association::detail {

namespace acse = iso::acse;
using asio::awaitable;

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

void core::terminate(std::error_code reason, bool graceful) {
  if (closed()) return;
  error = reason;
  set_state(association_state::closed);
  (void)pres.on_transport_disconnect();
  on_terminated();
  closed_waiters.notify_all();
  if (graceful) {
    asio::co_spawn(
        strand,
        [](std::shared_ptr<core> self) -> awaitable<void> { (void)co_await self->channel.shutdown(); }(
            shared_from_this()),
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
  terminate(reason, true);
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

}  // namespace openiec61850::association::detail
