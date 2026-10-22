#include "openiec61850/iso/session/connection.hpp"

#include <utility>

namespace openiec61850::iso::session {
namespace {

std::uint8_t highest_version(std::uint8_t versions) {
  if ((versions & version_2) != 0) return version_2;
  if ((versions & version_1) != 0) return version_1;
  return 0;
}

bool is_single_version(std::uint8_t v) { return v == version_1 || v == version_2; }

bool has_session(state s) {
  return s != state::idle && s != state::closed;
}

}  // namespace

connection::connection(role r, connection_options options)
    : role_(r), options_(std::move(options)) {}

event connection::fail(std::error_code error, byte_buffer& out) {
  if (has_session(state_)) {
    abort_spdu ab;
    ab.transport_disconnect = static_cast<std::uint8_t>(
        transport_disconnect::released | (error == errc::unsupported
                                              ? transport_disconnect::implementation_restriction
                                              : transport_disconnect::protocol_error));
    (void)encode(ab, out);  // cannot fail: no user data
  }
  state_ = state::closed;
  return provider_abort{error};
}

event connection::refuse_locally(std::error_code error, std::uint8_t reason, byte_buffer& out) {
  refuse_spdu rf;
  rf.transport_disconnect = transport_disconnect::released;
  if (reason == refuse_reason::version_not_supported) rf.version_number = options_.versions;
  rf.reason = reason;
  (void)encode(rf, out);  // cannot fail: no user data
  state_ = state::closed;
  return provider_abort{error};
}

event connection::on_connect(const connect_spdu& cn, byte_buffer& out) {
  // Version negotiation: the highest version supported by both sides.
  const auto version = highest_version(cn.version_number & options_.versions);
  if (version == 0) {
    return refuse_locally(errc::unsupported, refuse_reason::version_not_supported, out);
  }
  // Only the duplex functional unit (plus the kernel) is offered; the selected set is the
  // intersection, so a proposal without duplex leaves nothing usable.
  if ((cn.session_requirements & fu::duplex) == 0) {
    return refuse_locally(errc::unsupported, refuse_reason::implementation_restriction, out);
  }
  version_ = version;
  state_ = state::awaiting_connect_response;
  return connect_indication{cn.calling_selector, cn.called_selector, version, cn.user_data};
}

event connection::on_accept(const accept_spdu& ac, byte_buffer& out) {
  if (!is_single_version(ac.version_number) || (ac.version_number & options_.versions) == 0) {
    return fail(errc::protocol_violation, out);
  }
  // The responder may only select functional units that were proposed (duplex only).
  if (ac.session_requirements != fu::duplex) return fail(errc::protocol_violation, out);
  if (ac.enclosure && *ac.enclosure != enclosure::complete) return fail(errc::unsupported, out);
  version_ = ac.version_number;
  state_ = state::data_transfer;
  return connect_confirm{ac.responding_selector, version_, ac.user_data};
}

result<event> connection::on_tsdu(byte_view tsdu, byte_buffer& out) {
  if (state_ == state::closed) return errc::invalid_state;

  auto decoded = decode_tsdu(tsdu);
  if (!decoded) return fail(decoded.error(), out);
  const spdu& s = *decoded;

  if (const auto* ab = std::get_if<abort_spdu>(&s); ab && has_session(state_)) {
    const auto td = ab->transport_disconnect.value_or(transport_disconnect::released);
    // AA is only returned when the AB asks for the transport connection to be kept (X.225 §8.3.10).
    if ((td & transport_disconnect::released) == 0) (void)encode(abort_accept_spdu{}, out);
    state_ = state::closed;
    return event{abort_indication{td, ab->user_data}};
  }

  switch (state_) {
    case state::idle:
      if (const auto* cn = std::get_if<connect_spdu>(&s); cn && role_ == role::responder) {
        return on_connect(*cn, out);
      }
      break;

    case state::awaiting_accept:
      if (const auto* ac = std::get_if<accept_spdu>(&s)) return on_accept(*ac, out);
      if (const auto* rf = std::get_if<refuse_spdu>(&s)) {
        state_ = state::closed;
        return event{connect_refused{rf->reason, rf->user_data}};
      }
      break;

    case state::data_transfer:
    case state::awaiting_disconnect:
      if (const auto* dt = std::get_if<data_transfer_spdu>(&s)) {
        if (dt->enclosure && *dt->enclosure != enclosure::complete) {
          return fail(errc::unsupported, out);  // segmenting is not negotiated
        }
        return event{data_indication{dt->user_information}};
      }
      if (const auto* gt = std::get_if<give_tokens_spdu>(&s)) {
        // No tokens exist in a duplex-only session; an empty GT is harmless.
        if (!gt->token_item || *gt->token_item == 0) return event{no_event{}};
        break;
      }
      if (const auto* fn = std::get_if<finish_spdu>(&s)) {
        if (fn->enclosure && *fn->enclosure != enclosure::complete) {
          return fail(errc::unsupported, out);
        }
        collision_ = state_ == state::awaiting_disconnect;
        state_ = state::awaiting_release_response;
        return event{release_indication{collision_, fn->user_data}};
      }
      if (const auto* dn = std::get_if<disconnect_spdu>(&s); dn && state_ == state::awaiting_disconnect) {
        state_ = state::closed;
        return event{release_confirm{dn->user_data}};
      }
      break;

    case state::awaiting_release_response:
      if (const auto* dn = std::get_if<disconnect_spdu>(&s); dn && collision_ && !peer_disconnected_) {
        peer_disconnected_ = true;
        return event{release_confirm{dn->user_data}};
      }
      break;

    case state::awaiting_connect_response:
    case state::closed:
      break;
  }
  return fail(errc::protocol_violation, out);
}

result<void> connection::connect(byte_view user_data, byte_buffer& out) {
  if (role_ != role::initiator || state_ != state::idle) return errc::invalid_state;
  if (options_.versions == 0 || (options_.versions & ~(version_1 | version_2)) != 0) {
    return errc::unsupported;
  }
  connect_spdu cn;
  cn.version_number = options_.versions;
  cn.session_requirements = fu::duplex;
  cn.calling_selector = options_.local_selector;
  cn.called_selector = options_.remote_selector;
  cn.user_data = user_data;
  if (auto r = encode(cn, out); !r) return r;
  state_ = state::awaiting_accept;
  return {};
}

result<void> connection::accept(byte_view user_data, byte_buffer& out) {
  if (state_ != state::awaiting_connect_response) return errc::invalid_state;
  accept_spdu ac;
  ac.version_number = version_;
  ac.session_requirements = fu::duplex;
  ac.responding_selector = options_.local_selector;
  ac.user_data = user_data;
  if (auto r = encode(ac, out); !r) return r;
  state_ = state::data_transfer;
  return {};
}

result<void> connection::refuse(std::uint8_t reason, byte_view user_data, byte_buffer& out) {
  if (state_ != state::awaiting_connect_response) return errc::invalid_state;
  refuse_spdu rf;
  rf.transport_disconnect = transport_disconnect::released;
  rf.reason = reason;
  rf.user_data = user_data;
  if (auto r = encode(rf, out); !r) return r;
  state_ = state::closed;
  return {};
}

result<void> connection::send_data(byte_view user_data, byte_buffer& out) {
  if (state_ != state::data_transfer) return errc::invalid_state;
  encode_data_tsdu(user_data, out);
  return {};
}

result<void> connection::release(byte_view user_data, byte_buffer& out) {
  if (state_ != state::data_transfer) return errc::invalid_state;
  finish_spdu fn;
  fn.transport_disconnect = transport_disconnect::released;
  fn.user_data = user_data;
  if (auto r = encode(fn, out); !r) return r;
  state_ = state::awaiting_disconnect;
  return {};
}

result<void> connection::release_response(byte_view user_data, byte_buffer& out) {
  if (state_ != state::awaiting_release_response) return errc::invalid_state;
  disconnect_spdu dn;
  dn.user_data = user_data;
  if (auto r = encode(dn, out); !r) return r;
  // During a collision our own FN still awaits the peer's DN.
  state_ = collision_ && !peer_disconnected_ ? state::awaiting_disconnect : state::closed;
  collision_ = false;
  return {};
}

result<void> connection::abort(byte_view user_data, byte_buffer& out) {
  if (!has_session(state_)) return errc::invalid_state;
  abort_spdu ab;
  ab.transport_disconnect =
      static_cast<std::uint8_t>(transport_disconnect::released | transport_disconnect::user_abort);
  ab.user_data = user_data;
  if (auto r = encode(ab, out); !r) return r;
  state_ = state::closed;
  return {};
}

bool connection::on_transport_disconnect() noexcept {
  const bool expected = !has_session(state_);
  state_ = state::closed;
  return expected;
}

}  // namespace openiec61850::iso::session
