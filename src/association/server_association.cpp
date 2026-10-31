#include "openiec61850/association/server_association.hpp"

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

namespace {

bool authentication_diagnostic(std::int64_t d) {
  using namespace acse::service_user_diagnostic;
  return d == authentication_mechanism_name_not_recognized ||
         d == authentication_mechanism_name_required || d == authentication_failure ||
         d == authentication_required;
}

}  // namespace

struct server_state final : core {
  server_state(transport::cotp_channel ch, server_options o)
      : core(std::move(ch), ps::role::responder, responder_options(o), o.decode),
        options(std::move(o)) {
    max_output_bytes = options.transport.max_output_bytes;
  }

  server_options options;
  association_request peer;

  std::deque<received_pdu> requests;  // not yet taken by next_request()
  waiter* consumer = nullptr;

  // --- establishment

  void refuse(const associate_indication& ind, std::int64_t diagnostic) {
    byte_buffer out;
    (void)refuse_association(pres, ind, options, diagnostic, out);
    flush(out);
  }

  static awaitable<result<void>> establish_op(std::shared_ptr<server_state> self) {
    auto tsdu = co_await self->receive_before(self->options.association_timeout);
    if (!tsdu) {
      self->terminate(tsdu.error(), false);
      co_return tsdu.error();
    }
    const byte_buffer buffer = std::move(*tsdu);
    byte_buffer out;
    auto ev = self->pres.on_tsdu(buffer, out);
    self->flush(out);
    const auto* ci = ev ? std::get_if<ps::connect_indication>(&*ev) : nullptr;
    if (ci == nullptr) {
      std::error_code ec = openiec61850::errc::protocol_violation;
      if (!ev) {
        ec = ev.error();
      } else if (const auto* a = std::get_if<ps::provider_abort>(&*ev); a != nullptr && a->error) {
        ec = a->error;
      }
      self->terminate(ec, true);
      co_return ec;
    }

    const auto ind = parse_associate_request(*ci, self->decode);
    if (!ind.request) {
      self->refuse(ind, ind.diagnostic);
      const std::error_code ec = ind.initiate_failed ? make_error_code(errc::initiate_error)
                                                     : make_error_code(errc::association_rejected);
      self->terminate(ec, true);
      co_return ec;
    }
    self->peer = *ind.request;
    self->peer.remote_endpoint = self->info.remote_endpoint;
    self->peer.tls = self->info.tls;
    auto negotiated = negotiate(self->peer.initiate, self->options.limits);
    const auto decision = self->options.authorize ? self->options.authorize(self->peer, negotiated)
                                                  : association_decision::accepted();
    if (!decision.accept) {
      self->refuse(ind, decision.diagnostic);
      const std::error_code ec = authentication_diagnostic(decision.diagnostic)
                                     ? make_error_code(errc::authentication_failed)
                                     : make_error_code(errc::association_rejected);
      self->terminate(ec, true);
      co_return ec;
    }
    if (auto r = accept_association(self->pres, ind, self->options, negotiated, out); !r) {
      self->abort_with(r.error());
      co_return r;
    }
    self->flush(out);
    self->acse_context = *ind.acse_context;
    self->mms_context = *ind.mms_context;
    self->info.negotiated = to_negotiated(self->peer.initiate, negotiated);
    self->info.peer_ap_title = self->peer.calling_ap_title;
    self->info.peer_ae_qualifier = self->peer.calling_ae_qualifier;
    self->incoming_limit = static_cast<std::size_t>(self->info.negotiated.max_serv_outstanding_calling);
    self->limit = static_cast<std::size_t>(self->info.negotiated.max_serv_outstanding_called);
    if (const auto& d = self->info.negotiated.local_detail_calling; d && *d > 0) {
      self->peer_max_pdu = static_cast<std::size_t>(*d);
    }
    self->start_reader();
    co_return result<void>{};
  }

  // --- requests

  static awaitable<result<incoming_request>> next_request_op(std::shared_ptr<server_state> self) {
    if (self->consumer != nullptr) co_return openiec61850::errc::invalid_state;
    for (;;) {
      if (!self->requests.empty()) {
        auto m = std::move(self->requests.front());
        self->requests.pop_front();
        co_return make_incoming(self, std::move(m));
      }
      if (self->closed()) co_return self->error;
      waiter w(self->strand);
      self->consumer = &w;
      struct reset {
        waiter*& slot;
        ~reset() { slot = nullptr; }
      } guard{self->consumer};
      if (co_await wait(w, clock::time_point::max()) == wait_status::cancelled) {
        co_return asio::error::operation_aborted;
      }
    }
  }

  // --- core hooks

  void on_mms(received_pdu m) override {
    const auto& pdu = m.pdu();
    switch (mms::type_of(pdu)) {
      case mms::pdu_type::confirmed_request: {
        const auto id = std::get<mms::confirmed_request>(pdu).invoke_id;
        if (admit(id, current_state() == association_state::established)) {
          requests.push_back(std::move(m));
          if (consumer != nullptr) consumer->notify();
        }
        break;
      }
      case mms::pdu_type::conclude_request:
        // ISO 9506-1 §8.4: refused while requests are outstanding, in either direction.
        if (!incoming.empty() || !requests_idle()) {
          (void)send_mms(mms::conclude_error{mms::service_error(
              mms::error_class::conclude, mms::error_code::conclude::further_communication_required)});
        } else {
          set_state(association_state::releasing);
          (void)send_mms(mms::conclude_response{});
        }
        break;
      case mms::pdu_type::cancel_request:
        (void)send_mms(mms::cancel_error{
            std::get<mms::cancel_request>(pdu).invoke_id,
            mms::service_error(mms::error_class::cancel, mms::error_code::cancel::cancel_not_possible)});
        break;
      case mms::pdu_type::confirmed_response:
      case mms::pdu_type::confirmed_error:
      case mms::pdu_type::reject:
        on_answer(std::move(m));
        break;
      case mms::pdu_type::unconfirmed:
        reject(std::nullopt, mms::reject_type::unconfirmed, mms::reject_code::unconfirmed::unrecognized_service);
        break;
      default:
        break;
    }
  }

  void on_terminated() override {
    if (consumer != nullptr) consumer->notify();
  }
};

}  // namespace detail

using detail::server_state;

// --- server_association

server_association::server_association(std::shared_ptr<server_state> state) noexcept
    : state_(std::move(state)) {}

server_association& server_association::operator=(server_association&& other) noexcept {
  if (this != &other) {
    abort();
    state_ = std::move(other.state_);
  }
  return *this;
}

server_association::~server_association() { abort(); }

asio::awaitable<result<server_association>> server_association::accept(asio::ip::tcp::socket socket,
                                                                        server_options options) {
  auto channel = co_await transport::cotp_channel::accept(std::move(socket), options.transport);
  if (!channel) co_return channel.error();
  auto state = std::make_shared<server_state>(std::move(*channel), std::move(options));
  auto r = co_await detail::on_strand(state->strand, server_state::establish_op(state));
  if (!r) co_return r.error();
  co_return server_association(std::move(state));
}

asio::awaitable<result<incoming_request>> server_association::next_request() {
  if (!state_) return detail::ready(result<incoming_request>(openiec61850::errc::invalid_state));
  return detail::on_strand(state_->strand, server_state::next_request_op(state_));
}

asio::awaitable<request_result> server_association::request(mms::confirmed_service_request service) {
  if (!state_) return detail::ready(request_result(openiec61850::errc::invalid_state));
  return request(std::move(service), state_->options.request_timeout);
}

asio::awaitable<request_result> server_association::request(mms::confirmed_service_request service,
                                                            std::chrono::milliseconds timeout) {
  if (!state_) return detail::ready(request_result(openiec61850::errc::invalid_state));
  return detail::on_strand(state_->strand, detail::core::request_op(state_, std::move(service), timeout));
}

asio::awaitable<result<void>> server_association::send_unconfirmed(const mms::information_report& report) {
  return send_unconfirmed(mms::unconfirmed_service{report});
}

asio::awaitable<result<void>> server_association::send_unconfirmed(const mms::unconfirmed_service& service) {
  if (!state_) return detail::ready(result<void>(openiec61850::errc::invalid_state));
  auto pdu = detail::encode_mms(mms::unconfirmed_pdu{service});
  if (!pdu) return detail::ready(result<void>(pdu.error()));
  return detail::on_strand(state_->strand, detail::core::send_op(state_, std::move(*pdu)));
}

asio::awaitable<result<void>> server_association::send_batch(std::vector<outbound_pdu> batch) {
  if (!state_) return detail::ready(result<void>(openiec61850::errc::invalid_state));
  return detail::on_strand(state_->strand, detail::core::send_batch_op(state_, std::move(batch)));
}

void server_association::abort() noexcept {
  if (!state_) return;
  asio::dispatch(state_->strand, [s = state_] { s->abort_with(errc::aborted); });
}

void server_association::close() noexcept { close(errc::aborted); }

void server_association::close(std::error_code reason) noexcept {
  if (!state_) return;
  asio::dispatch(state_->strand, [s = state_, reason] { s->terminate(reason, false); });
}

asio::awaitable<std::error_code> server_association::wait_closed() {
  if (!state_) return detail::ready(openiec61850::make_error_code(openiec61850::errc::invalid_state));
  return detail::on_strand(state_->strand, detail::core::wait_closed_op(state_));
}

association_state server_association::state() const noexcept {
  return state_ ? state_->current_state() : association_state::closed;
}

const association_info& server_association::info() const noexcept { return state_->info; }

const association_request& server_association::peer_request() const noexcept { return state_->peer; }

server_association::executor_type server_association::get_executor() const noexcept {
  return state_->strand;
}

// --- association_listener

association_listener::association_listener(transport::cotp_listener listener,
                                           server_options options) noexcept
    : listener_(std::move(listener)), options_(std::move(options)) {}

result<association_listener> association_listener::listen(asio::any_io_executor ex,
                                                          const asio::ip::tcp::endpoint& endpoint,
                                                          server_options options) {
  auto l = transport::cotp_listener::listen(std::move(ex), endpoint);
  if (!l) return l.error();
  return association_listener(std::move(*l), std::move(options));
}

asio::awaitable<result<server_association>> association_listener::accept() {
  auto socket = co_await listener_.accept_socket();
  if (!socket) co_return socket.error();
  co_return co_await server_association::accept(std::move(*socket), options_);
}

asio::awaitable<result<asio::ip::tcp::socket>> association_listener::accept_socket() {
  return listener_.accept_socket();
}

void association_listener::close() noexcept { listener_.close(); }

const asio::ip::tcp::endpoint& association_listener::local_endpoint() const noexcept {
  return listener_.local_endpoint();
}

}  // namespace openiec61850::association
