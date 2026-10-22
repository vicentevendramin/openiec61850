#include "openiec61850/iso/presentation/connection.hpp"

#include <algorithm>
#include <type_traits>
#include <utility>

namespace openiec61850::iso::presentation {
namespace {

std::uint8_t abort_reason_for(std::error_code error) {
  if (error == errc::protocol_violation) return abort_reason::invalid_ppdu_parameter_value;
  if (error == errc::unsupported) return abort_reason::not_specified;
  return abort_reason::unrecognized_ppdu;
}

bool requests_only_version_1(const std::optional<std::uint32_t>& version) {
  return !version || (*version & protocol_version_1) != 0;
}

}  // namespace

connection::connection(role r, connection_options options)
    : session_(r, options.session), options_(std::move(options)) {}

bool connection::is_accepted(std::uint32_t context_id) const noexcept {
  return std::any_of(contexts_.begin(), contexts_.end(), [&](const negotiated_context& c) {
    return c.id == context_id && c.accepted;
  });
}

// Every PDV must name a context of the defined context set: one proposed in CP when `proposed`,
// otherwise an accepted one. Only BER may be named as transfer syntax.
bool connection::usable(std::span<const pdv> pdvs, bool proposed) const noexcept {
  return std::all_of(pdvs.begin(), pdvs.end(), [&](const pdv& p) {
    if (p.transfer_syntax && *p.transfer_syntax != ber_transfer_syntax) return false;
    return std::any_of(contexts_.begin(), contexts_.end(), [&](const negotiated_context& c) {
      return c.id == p.context_id && (proposed || c.accepted);
    });
  });
}

std::vector<context_result> connection::results() const {
  std::vector<context_result> out;
  out.reserve(contexts_.size());
  for (const auto& c : contexts_) {
    if (c.accepted) {
      out.push_back({context_result_code::acceptance, ber_transfer_syntax, std::nullopt});
    } else {
      out.push_back({context_result_code::provider_rejection, std::nullopt, c.reason});
    }
  }
  return out;
}

result<void> connection::encode_data(std::span<const pdv> user_data) {
  scratch_.clear();
  if (user_data.empty()) return {};
  return encode_user_data(user_data, scratch_);
}

// P-P-ABORT (X.226 §6.4.2): an ARP-PPDU on S-U-ABORT, when a session is still there to carry it.
event connection::fail(std::error_code error, std::uint8_t ppdu, byte_buffer& out) {
  scratch_.clear();
  (void)encode(provider_abort_ppdu{abort_reason_for(error), ppdu}, scratch_);
  (void)session_.abort(scratch_, out);
  received_.clear();
  return provider_abort{error};
}

// Responder: a CP-PPDU that cannot be accepted is answered with a CPR-PPDU carrying a provider
// reason, on a negative S-CONNECT response (X.226 §6.2.4).
event connection::refuse_locally(std::error_code error, std::uint8_t reason, byte_buffer& out) {
  refuse_ppdu cpr;
  cpr.responding_selector = options_.local_selector;
  cpr.results = results();
  cpr.provider_reason = reason;
  scratch_.clear();
  (void)encode(cpr, scratch_);
  (void)session_.refuse(session::refuse_reason::rejected_by_user, scratch_, out);
  received_.clear();
  return provider_abort{error};
}

event connection::on_connect(const session::connect_indication& ind, byte_buffer& out) {
  auto cp = decode_connect(ind.user_data);
  if (!cp) return refuse_locally(cp.error(), provider_reason::not_specified, out);
  if (!requests_only_version_1(cp->protocol_version)) {
    return refuse_locally(errc::unsupported, provider_reason::protocol_version_not_supported, out);
  }
  // A default context is meaningless in normal mode with a definition list and is not supported.
  if (cp->default_context) {
    return refuse_locally(errc::unsupported, provider_reason::default_context_not_supported, out);
  }

  contexts_.clear();
  for (const auto& d : cp->contexts) {
    const bool duplicate = std::any_of(contexts_.begin(), contexts_.end(),
                                       [&](const negotiated_context& c) { return c.id == d.id; });
    if (duplicate || d.id % 2 == 0) {
      return refuse_locally(errc::protocol_violation, provider_reason::not_specified, out);
    }
    const auto& supported = options_.supported_abstract_syntaxes;
    const bool known = supported.empty() ||
                       std::find(supported.begin(), supported.end(), d.abstract_syntax) !=
                           supported.end();
    const bool ber = std::find(d.transfer_syntaxes.begin(), d.transfer_syntaxes.end(),
                               ber_transfer_syntax) != d.transfer_syntaxes.end();
    negotiated_context c{d.id, d.abstract_syntax, known && ber, context_reason::not_specified};
    if (!known) {
      c.reason = context_reason::abstract_syntax_not_supported;
    } else if (!ber) {
      c.reason = context_reason::proposed_transfer_syntaxes_not_supported;
    }
    contexts_.push_back(c);
  }
  // Presentation requirements beyond the kernel are not selected; the CPA simply omits them.

  if (!usable(cp->user_data, true)) {
    return refuse_locally(errc::protocol_violation, provider_reason::user_data_not_readable, out);
  }
  received_ = std::move(cp->user_data);
  return connect_indication{cp->calling_selector, cp->called_selector, contexts_, received_};
}

event connection::on_accept(const session::connect_confirm& conf, byte_buffer& out) {
  auto cpa = decode_accept(conf.user_data);
  if (!cpa) return fail(cpa.error(), event_id::cpa_ppdu, out);
  // Only version 1 and the kernel were proposed, and the result list must answer every context.
  if (!requests_only_version_1(cpa->protocol_version) ||
      cpa->presentation_requirements.value_or(0) != 0 ||
      cpa->results.size() != contexts_.size()) {
    return fail(errc::protocol_violation, event_id::cpa_ppdu, out);
  }
  for (std::size_t i = 0; i < contexts_.size(); ++i) {
    const auto& r = cpa->results[i];
    auto& c = contexts_[i];
    c.accepted = r.result == context_result_code::acceptance;
    if (c.accepted) {
      if (r.transfer_syntax && *r.transfer_syntax != ber_transfer_syntax) {
        return fail(errc::protocol_violation, event_id::cpa_ppdu, out);
      }
    } else {
      c.reason = r.provider_reason.value_or(context_reason::not_specified);
    }
  }
  if (!usable(cpa->user_data, false)) return fail(errc::protocol_violation, event_id::cpa_ppdu, out);
  received_ = std::move(cpa->user_data);
  return connect_confirm{cpa->responding_selector, contexts_, received_};
}

event connection::on_refuse(const session::connect_refused& ref) {
  connect_refused ev{ref.reason, std::nullopt, {}};
  if (ref.reason == session::refuse_reason::rejected_by_user && !ref.user_data.empty()) {
    auto cpr = decode_refuse(ref.user_data);
    if (cpr) {
      ev.provider_reason = cpr->provider_reason;
      received_ = std::move(cpr->user_data);
      ev.user_data = received_;
    } else {
      ev.provider_reason = provider_reason::not_specified;
    }
  }
  return ev;
}

event connection::on_abort(const session::abort_indication& ab) {
  if ((ab.transport_disconnect & session::transport_disconnect::user_abort) == 0) {
    return provider_abort_indication{};  // S-P-ABORT
  }
  if (ab.user_data.empty()) return user_abort_indication{};
  auto decoded = decode_abort(ab.user_data);
  if (!decoded) return provider_abort_indication{};
  if (auto* arp = std::get_if<provider_abort_ppdu>(&*decoded)) {
    return provider_abort_indication{arp->reason};
  }
  received_ = std::move(std::get<user_abort_ppdu>(*decoded).user_data);
  return user_abort_indication{received_};
}

// TD-PPDU (never empty) or the user data of S-RELEASE (optional), decoded into received_.
event connection::on_user_data(byte_view data, std::uint8_t ppdu, byte_buffer& out) {
  if (data.empty() && ppdu != event_id::td_ppdu) return no_event{};
  if (auto r = decode_user_data(data, received_); !r) return fail(r.error(), ppdu, out);
  if (!usable(received_, false)) return fail(errc::protocol_violation, ppdu, out);
  return no_event{};
}

result<event> connection::on_tsdu(byte_view tsdu, byte_buffer& out) {
  if (current_state() == state::closed) return errc::invalid_state;
  received_.clear();
  auto ev = session_.on_tsdu(tsdu, out);
  if (!ev) return ev.error();

  return std::visit(
      [&](const auto& e) -> event {
        using T = std::decay_t<decltype(e)>;
        if constexpr (std::is_same_v<T, session::no_event>) {
          return no_event{};
        } else if constexpr (std::is_same_v<T, session::connect_indication>) {
          return on_connect(e, out);
        } else if constexpr (std::is_same_v<T, session::connect_confirm>) {
          return on_accept(e, out);
        } else if constexpr (std::is_same_v<T, session::connect_refused>) {
          return on_refuse(e);
        } else if constexpr (std::is_same_v<T, session::data_indication>) {
          auto r = on_user_data(e.user_data, event_id::td_ppdu, out);
          if (!std::holds_alternative<no_event>(r)) return r;
          return data_indication{received_};
        } else if constexpr (std::is_same_v<T, session::release_indication>) {
          auto r = on_user_data(e.user_data, event_id::s_release_indication, out);
          if (!std::holds_alternative<no_event>(r)) return r;
          return release_indication{e.collision, received_};
        } else if constexpr (std::is_same_v<T, session::release_confirm>) {
          auto r = on_user_data(e.user_data, event_id::s_release_confirm, out);
          if (!std::holds_alternative<no_event>(r)) return r;
          return release_confirm{received_};
        } else if constexpr (std::is_same_v<T, session::abort_indication>) {
          return on_abort(e);
        } else {
          static_assert(std::is_same_v<T, session::provider_abort>);
          return provider_abort{e.error};
        }
      },
      *ev);
}

result<void> connection::connect(std::span<const pdv> user_data, byte_buffer& out) {
  if (connection_role() != role::initiator || current_state() != state::idle) {
    return errc::invalid_state;
  }
  connect_ppdu cp;
  cp.calling_selector = options_.local_selector;
  cp.called_selector = options_.remote_selector;
  std::vector<negotiated_context> proposed;
  for (const auto& c : options_.contexts) {
    const bool duplicate = std::any_of(proposed.begin(), proposed.end(),
                                       [&](const negotiated_context& n) { return n.id == c.id; });
    if (duplicate || c.id % 2 == 0 || !c.abstract_syntax.valid()) return errc::invalid_state;
    proposed.push_back({c.id, c.abstract_syntax, false, context_reason::not_specified});
    cp.contexts.push_back({c.id, c.abstract_syntax, {ber_transfer_syntax}});
  }
  contexts_ = std::move(proposed);
  if (!usable(user_data, true)) {
    contexts_.clear();
    return errc::invalid_state;
  }
  cp.user_data.assign(user_data.begin(), user_data.end());
  scratch_.clear();
  auto r = encode(cp, scratch_);
  if (r) r = session_.connect(scratch_, out);
  if (!r) contexts_.clear();
  return r;
}

result<void> connection::accept(std::span<const pdv> user_data, byte_buffer& out) {
  if (current_state() != state::awaiting_connect_response) return errc::invalid_state;
  if (!usable(user_data, false)) return errc::invalid_state;
  accept_ppdu cpa;
  cpa.responding_selector = options_.local_selector;
  cpa.results = results();
  cpa.user_data.assign(user_data.begin(), user_data.end());
  scratch_.clear();
  if (auto r = encode(cpa, scratch_); !r) return r;
  return session_.accept(scratch_, out);
}

result<void> connection::refuse(std::span<const pdv> user_data, byte_buffer& out) {
  if (current_state() != state::awaiting_connect_response) return errc::invalid_state;
  if (!usable(user_data, false)) return errc::invalid_state;
  refuse_ppdu cpr;
  cpr.responding_selector = options_.local_selector;
  cpr.results = results();
  cpr.user_data.assign(user_data.begin(), user_data.end());
  scratch_.clear();
  if (auto r = encode(cpr, scratch_); !r) return r;
  return session_.refuse(session::refuse_reason::rejected_by_user, scratch_, out);
}

result<void> connection::send_data(std::span<const pdv> user_data, byte_buffer& out) {
  if (current_state() != state::data_transfer || user_data.empty()) return errc::invalid_state;
  if (!usable(user_data, false)) return errc::invalid_state;
  if (auto r = encode_data(user_data); !r) return r;
  return session_.send_data(scratch_, out);
}

result<void> connection::send_data(std::uint32_t context_id, byte_view apdu, byte_buffer& out) {
  const pdv p{std::nullopt, context_id, pdv_encoding::single_asn1_type, apdu, 0};
  return send_data(std::span<const pdv>{&p, 1}, out);
}

result<void> connection::release(std::span<const pdv> user_data, byte_buffer& out) {
  if (current_state() != state::data_transfer) return errc::invalid_state;
  if (!usable(user_data, false)) return errc::invalid_state;
  if (auto r = encode_data(user_data); !r) return r;
  return session_.release(scratch_, out);
}

result<void> connection::release_response(std::span<const pdv> user_data, byte_buffer& out) {
  if (current_state() != state::awaiting_release_response) return errc::invalid_state;
  if (!usable(user_data, false)) return errc::invalid_state;
  if (auto r = encode_data(user_data); !r) return r;
  return session_.release_response(scratch_, out);
}

result<void> connection::abort(std::span<const pdv> user_data, byte_buffer& out) {
  const auto s = current_state();
  if (s == state::idle || s == state::closed) return errc::invalid_state;
  if (!usable(user_data, true)) return errc::invalid_state;
  user_abort_ppdu aru;
  aru.user_data.assign(user_data.begin(), user_data.end());
  scratch_.clear();
  if (auto r = encode(aru, scratch_); !r) return r;
  return session_.abort(scratch_, out);
}

}  // namespace openiec61850::iso::presentation
