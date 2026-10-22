#include "openiec61850/iso/cotp/connection.hpp"

#include <algorithm>
#include <utility>

namespace openiec61850::iso::cotp {

namespace {

constexpr std::uint8_t alternative_classes_parameter = 0xC7;  // X.224 §13.3.4 j)
constexpr std::size_t max_tsap_length = 255;
// ER variable part limit: LI (254) minus the fixed part (4) and the parameter header (2).
constexpr std::size_t max_invalid_tpdu_length = 248;

// X.224 §6.5.4: class 0 can be selected when it is preferred or listed as an alternative.
bool class0_acceptable(const connection_request& cr) {
  if (cr.protocol_class() == 0) return true;
  for (const auto& p : cr.other_parameters) {
    if (p.code != alternative_classes_parameter) continue;
    for (const std::uint8_t c : p.value) {
      if ((c >> 4) == 0) return true;
    }
  }
  return false;
}

std::size_t negotiated_size(const connect_tpdu& t) {
  return t.tpdu_size ? *tpdu_size_from_code(*t.tpdu_size) : default_tpdu_size;
}

}  // namespace

result<connection> connection::create(role r, connection_config config) {
  if (!tpdu_size_code(config.max_tpdu_size) || config.max_tpdu_size > class0_max_tpdu_size) {
    return errc::unsupported;
  }
  if ((config.calling_tsap && config.calling_tsap->size() > max_tsap_length) ||
      (config.called_tsap && config.called_tsap->size() > max_tsap_length)) {
    return errc::length_overflow;
  }
  return connection{r, std::move(config)};
}

connection::connection(role r, connection_config config)
    : role_(r),
      config_(std::move(config)),
      state_(r == role::initiator ? connection_state::idle : connection_state::awaiting_cr),
      framer_(config_.max_tpkt_size) {}

result<void> connection::connect() {
  if (role_ != role::initiator || state_ != connection_state::idle) return errc::invalid_state;
  connection_request cr;
  cr.src_ref = config_.local_reference;
  cr.class_options = 0x00;  // class 0, no options
  cr.tpdu_size = tpdu_size_code(config_.max_tpdu_size);
  cr.calling_tsap = config_.calling_tsap;
  cr.called_tsap = config_.called_tsap;
  if (auto r = encode_tpkt(tpdu{std::move(cr)}, output_); !r) return r;
  state_ = connection_state::awaiting_cc;
  return {};
}

result<void> connection::send(byte_view tsdu) {
  if (state_ != connection_state::open) return errc::invalid_state;
  // X.224 §6.9: segment the TSDU, EOT marks the last DT.
  const std::size_t max_segment = tpdu_size_ - dt_header_size;
  const std::size_t segments = tsdu.empty() ? 1 : (tsdu.size() + max_segment - 1) / max_segment;
  output_.reserve(output_.size() + tsdu.size() + segments * (tpkt_header_size + dt_header_size));
  std::size_t offset = 0;
  do {
    const std::size_t length = std::min(max_segment, tsdu.size() - offset);
    const bool eot = offset + length == tsdu.size();
    if (auto r = encode_tpkt_header(dt_header_size + length, output_); !r) return r;
    output_.push_back(static_cast<std::uint8_t>(dt_header_size - 1));
    output_.push_back(static_cast<std::uint8_t>(tpdu_kind::dt));
    output_.push_back(eot ? 0x80 : 0x00);
    const auto segment = tsdu.subspan(offset, length);
    output_.insert(output_.end(), segment.begin(), segment.end());
    offset += length;
  } while (offset < tsdu.size());
  return {};
}

void connection::feed(byte_view data, std::vector<event>& events) {
  if (state_ == connection_state::closed) return;
  framer_.feed(data);
  while (state_ != connection_state::closed) {
    auto frame = framer_.next();
    if (!frame) {
      // The stream is out of sync, an ER could not be framed reliably.
      fail(frame.error(), std::nullopt, {}, events);
      return;
    }
    if (!*frame) return;
    handle_tpdu(**frame, events);
  }
}

void connection::handle_tpdu(byte_view raw, std::vector<event>& events) {
  auto decoded = decode_tpdu(raw);
  if (!decoded) {
    const bool bad_type = decoded.error() == errc::unsupported ||
                          (raw.size() >= 2 && !tpdu_kind_of(raw[1]));
    fail(decoded.error(), bad_type ? reject_cause::invalid_tpdu_type : reject_cause::not_specified,
         raw, events);
    return;
  }
  const auto violation = [&] {
    fail(errc::protocol_violation, reject_cause::not_specified, raw, events);
  };

  if (const auto* cr = std::get_if<connection_request>(&*decoded)) {
    if (role_ == role::responder && state_ == connection_state::awaiting_cr) {
      handle_cr(*cr, events);
    } else {
      violation();
    }
  } else if (const auto* cc = std::get_if<connection_confirm>(&*decoded)) {
    if (state_ == connection_state::awaiting_cc) {
      handle_cc(*cc, raw, events);
    } else {
      violation();
    }
  } else if (const auto* dr = std::get_if<disconnect_request>(&*decoded)) {
    // X.224 §6.6: in class 0 a DR is only valid as the answer to a CR.
    if (state_ == connection_state::awaiting_cc) {
      disconnect(disconnect_origin::refused, dr->reason, events);
    } else if (state_ == connection_state::open) {
      disconnect(disconnect_origin::remote_disconnect, dr->reason, events);
    } else {
      violation();
    }
  } else if (const auto* dt = std::get_if<data_tpdu>(&*decoded)) {
    if (state_ == connection_state::open) {
      handle_dt(*dt, raw, events);
    } else {
      violation();
    }
  } else if (const auto* er = std::get_if<error_tpdu>(&*decoded)) {
    // X.224 §6.22: an ER in class 0 ends the connection.
    disconnect(disconnect_origin::remote_error, er->cause, events);
  }
}

void connection::handle_cr(const connection_request& cr, std::vector<event>& events) {
  std::optional<std::uint8_t> refusal;
  if (!class0_acceptable(cr)) {
    refusal = disconnect_reason::negotiation_failed;
  } else if (config_.accept_connection) {
    refusal = config_.accept_connection(cr);
  }
  if (refusal) {
    // X.224 §13.5.3: SRC-REF is zero when the DR answers a CR.
    disconnect_request dr;
    dr.dst_ref = cr.src_ref;
    dr.reason = *refusal;
    (void)encode_tpkt(tpdu{std::move(dr)}, output_);
    disconnect(disconnect_origin::local_refusal, *refusal, events);
    return;
  }

  // X.224 §6.5.4: the responder may only lower the proposed TPDU size.
  const std::size_t size = std::min(negotiated_size(cr), config_.max_tpdu_size);
  connection_confirm cc;
  cc.dst_ref = cr.src_ref;
  cc.src_ref = config_.local_reference;
  cc.class_options = 0x00;
  cc.tpdu_size = tpdu_size_code(size);
  cc.calling_tsap = cr.calling_tsap;
  cc.called_tsap = cr.called_tsap;
  if (auto r = encode_tpkt(tpdu{std::move(cc)}, output_); !r) {
    fail(r.error(), std::nullopt, {}, events);
    return;
  }
  enter_open(size, cr.src_ref, cr.calling_tsap, cr.called_tsap, events);
}

void connection::handle_cc(const connection_confirm& cc, byte_view raw, std::vector<event>& events) {
  const std::size_t size = negotiated_size(cc);
  if (cc.dst_ref != config_.local_reference || cc.protocol_class() != 0 ||
      size > config_.max_tpdu_size) {
    fail(errc::protocol_violation, reject_cause::invalid_parameter_value, raw, events);
    return;
  }
  enter_open(size, cc.src_ref, cc.calling_tsap, cc.called_tsap, events);
}

void connection::handle_dt(const data_tpdu& dt, byte_view raw, std::vector<event>& events) {
  if (raw.size() > tpdu_size_) {
    fail(errc::length_overflow, reject_cause::not_specified, raw, events);
    return;
  }
  if (dt.user_data.size() > config_.max_tsdu_size - reassembly_.size()) {
    // A local resource limit, not a protocol error of the peer: close without ER.
    fail(errc::length_overflow, std::nullopt, {}, events);
    return;
  }
  if (dt.eot && reassembly_.empty()) {
    events.emplace_back(data_indication{byte_buffer(dt.user_data.begin(), dt.user_data.end())});
    return;
  }
  reassembly_.insert(reassembly_.end(), dt.user_data.begin(), dt.user_data.end());
  if (dt.eot) events.emplace_back(data_indication{std::exchange(reassembly_, {})});
}

void connection::enter_open(std::size_t size, std::uint16_t remote_ref,
                            std::optional<byte_buffer> calling, std::optional<byte_buffer> called,
                            std::vector<event>& events) {
  state_ = connection_state::open;
  tpdu_size_ = size;
  remote_ref_ = remote_ref;
  events.emplace_back(connected_indication{size, remote_ref, std::move(calling), std::move(called)});
}

void connection::fail(std::error_code ec, std::optional<std::uint8_t> cause, byte_view raw,
                      std::vector<event>& events) {
  if (cause && state_ != connection_state::idle && state_ != connection_state::closed) {
    // X.224 §13.12.4: the invalid TPDU parameter carries the rejected header.
    std::size_t length = raw.empty() ? 0 : std::min(raw.size(), std::size_t{raw[0]} + 1);
    length = std::min(length, max_invalid_tpdu_length);
    error_tpdu er;
    er.dst_ref = remote_ref_;
    er.cause = *cause;
    er.invalid_tpdu = byte_buffer(raw.begin(), raw.begin() + static_cast<std::ptrdiff_t>(length));
    (void)encode_tpkt(tpdu{std::move(er)}, output_);
  }
  state_ = connection_state::closed;
  reassembly_.clear();
  events.emplace_back(disconnect_indication{disconnect_origin::protocol_error, cause.value_or(0), ec});
}

void connection::disconnect(disconnect_origin origin, std::uint8_t reason,
                            std::vector<event>& events) {
  state_ = connection_state::closed;
  reassembly_.clear();
  events.emplace_back(disconnect_indication{origin, reason, {}});
}

void connection::network_closed(std::vector<event>& events) {
  if (state_ == connection_state::closed) return;
  disconnect(disconnect_origin::network_closed, 0, events);
}

void connection::close() noexcept {
  state_ = connection_state::closed;
  reassembly_.clear();
}

byte_buffer connection::take_output() noexcept { return std::exchange(output_, {}); }

}  // namespace openiec61850::iso::cotp
