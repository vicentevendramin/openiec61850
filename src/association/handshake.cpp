#include "handshake.hpp"

#include <algorithm>
#include <span>
#include <string>
#include <variant>

namespace openiec61850::association::detail {
namespace {

ps::pdv single(std::uint32_t context, byte_view data) {
  return {std::nullopt, context, ps::pdv_encoding::single_asn1_type, data, 0};
}

std::optional<acse::ap_title> title(const std::optional<ber::oid>& t) {
  if (!t) return std::nullopt;
  return acse::ap_title{*t};
}
std::optional<acse::ae_qualifier> qualifier(const std::optional<std::int64_t>& q) {
  if (!q) return std::nullopt;
  return acse::ae_qualifier{*q};
}
std::optional<ber::oid> title_of(const std::optional<acse::ap_title>& t) {
  if (!t) return std::nullopt;
  if (const auto* o = std::get_if<ber::oid>(&*t)) return *o;
  return std::nullopt;
}
std::optional<std::int64_t> qualifier_of(const std::optional<acse::ae_qualifier>& q) {
  if (!q) return std::nullopt;
  if (const auto* v = std::get_if<std::int64_t>(&*q)) return *v;
  return std::nullopt;
}

template <typename T>
T clamp_to(T proposed, T response) {
  return std::max<T>(1, std::min(proposed, response));
}

std::optional<std::uint32_t> accepted_context(std::span<const ps::negotiated_context> contexts,
                                              const ber::oid& abstract_syntax) {
  for (const auto& c : contexts) {
    if (c.accepted && c.abstract_syntax == abstract_syntax) return c.id;
  }
  return std::nullopt;
}

const ps::pdv* find_pdv(std::span<const ps::pdv> pdvs, std::uint32_t context) {
  for (const auto& p : pdvs) {
    if (p.context_id == context && p.encoding == ps::pdv_encoding::single_asn1_type) return &p;
  }
  return nullptr;
}

// The MMS PDU in the ACSE user information: the EXTERNAL of the MMS context, or the only one.
const acse::external* mms_external(const acse::user_information& info, std::uint32_t context) {
  if (const auto* x = acse::find_by_context(info, context)) return x;
  if (info.size() == 1 && !info[0].indirect_reference) return &info[0];
  return nullptr;
}

bool authentication_diagnostic(const acse::associate_source_diagnostic& d) {
  if (d.source != acse::diagnostic_source::service_user) return false;
  using namespace acse::service_user_diagnostic;
  return d.reason == authentication_mechanism_name_not_recognized ||
         d.reason == authentication_mechanism_name_required ||
         d.reason == authentication_failure || d.reason == authentication_required;
}

// The AARE carried by a CPA or a CPR.
associate_response from_aare(std::span<const ps::pdv> user_data, bool refused,
                             const mms::initiate_request& proposed,
                             const mms::decode_options& opts) {
  associate_response r;
  const auto* p = find_pdv(user_data, acse_context_id);
  if (p == nullptr) {
    r.error = refused ? make_error_code(errc::connection_refused)
                      : openiec61850::make_error_code(openiec61850::errc::protocol_violation);
    return r;
  }
  auto apdu = acse::decode(p->data);
  if (!apdu || !std::holds_alternative<acse::aare_apdu>(*apdu)) {
    r.error = openiec61850::make_error_code(openiec61850::errc::protocol_violation);
    return r;
  }
  const auto& aare = std::get<acse::aare_apdu>(*apdu);
  r.responding_ap_title = title_of(aare.responding_ap_title);
  r.responding_ae_qualifier = qualifier_of(aare.responding_ae_qualifier);

  std::optional<mms::mms_pdu> pdu;
  if (const auto* x = mms_external(aare.user_information, mms_context_id);
      x != nullptr && x->encoding == acse::external_encoding::single_asn1_type) {
    if (auto d = mms::decode_pdu(x->data, opts)) pdu = std::move(*d);
  }
  if (pdu) {
    if (const auto* e = std::get_if<mms::initiate_error>(&*pdu)) {
      r.initiate_error = service_error_info::from(e->error);
      r.error = errc::initiate_error;
      return r;
    }
  }
  if (refused || aare.result != acse::associate_result::accepted) {
    r.error = authentication_diagnostic(aare.result_source_diagnostic)
                  ? make_error_code(errc::authentication_failed)
                  : make_error_code(errc::association_rejected);
    return r;
  }
  if (aare.application_context_name != acse::oids::mms_application_context) {
    r.error = errc::association_rejected;
    return r;
  }
  if (!pdu || !std::holds_alternative<mms::initiate_response>(*pdu)) {
    r.error = errc::initiate_error;
    return r;
  }
  r.negotiated = to_negotiated(proposed, std::get<mms::initiate_response>(*pdu));
  return r;
}

}  // namespace

result<byte_buffer> encode_mms(const mms::mms_pdu& pdu) {
  byte_buffer out;
  if (auto r = mms::encode_pdu(pdu, out); !r) return r.error();
  return out;
}

result<byte_buffer> encode_acse(const acse::apdu& apdu) {
  byte_buffer out;
  if (auto r = acse::encode(apdu, out); !r) return r.error();
  return out;
}

negotiated_parameters to_negotiated(const mms::initiate_request& proposed,
                                    const mms::initiate_response& response) noexcept {
  negotiated_parameters n;
  n.local_detail_calling = proposed.local_detail_calling;
  n.local_detail_called = response.local_detail_called;
  n.max_serv_outstanding_calling =
      clamp_to(proposed.max_serv_outstanding_calling, response.max_serv_outstanding_calling);
  n.max_serv_outstanding_called =
      clamp_to(proposed.max_serv_outstanding_called, response.max_serv_outstanding_called);
  if (proposed.data_structure_nesting_level && response.data_structure_nesting_level) {
    n.data_structure_nesting_level =
        std::min(*proposed.data_structure_nesting_level, *response.data_structure_nesting_level);
  }
  n.version_number = response.detail.version_number;
  n.parameter_cbb = response.detail.parameter_cbb;
  n.services_supported_calling = proposed.detail.services;
  n.services_supported_called = response.detail.services;
  return n;
}

ps::connection_options initiator_options(const association_params& p) {
  ps::connection_options o;
  o.session.local_selector = p.calling_session_selector;
  o.session.remote_selector = p.called_session_selector;
  o.local_selector = p.calling_presentation_selector;
  o.remote_selector = p.called_presentation_selector;
  o.contexts = {{acse_context_id, ps::acse_abstract_syntax}, {mms_context_id, ps::mms_abstract_syntax}};
  return o;
}

result<byte_buffer> encode_aarq(const association_params& p) {
  auto initiate = encode_mms(mms::mms_pdu{p.initiate});
  if (!initiate) return initiate.error();
  acse::mms_aarq_params a;
  a.called_ap_title = title(p.called_ap_title);
  a.called_ae_qualifier = qualifier(p.called_ae_qualifier);
  a.calling_ap_title = title(p.calling_ap_title);
  a.calling_ae_qualifier = qualifier(p.calling_ae_qualifier);
  if (p.password) a.password = std::string_view(*p.password);
  a.mms_context_id = mms_context_id;
  a.initiate_request = *initiate;
  return encode_acse(acse::make_mms_aarq(a));
}

result<void> connect_request(ps::connection& pc, const association_params& p, byte_buffer& out) {
  auto aarq = encode_aarq(p);
  if (!aarq) return aarq.error();
  const auto pdv = single(acse_context_id, *aarq);
  return pc.connect({&pdv, 1}, out);
}

associate_response parse_associate_response(const ps::event& ev,
                                             const mms::initiate_request& proposed,
                                             const mms::decode_options& opts) {
  associate_response r;
  if (const auto* c = std::get_if<ps::connect_confirm>(&ev)) {
    r = from_aare(c->user_data, false, proposed, opts);
    if (!r.error && !accepted_context(c->contexts, ps::mms_abstract_syntax)) {
      r.error = errc::association_rejected;
    }
  } else if (const auto* f = std::get_if<ps::connect_refused>(&ev)) {
    if (f->user_data.empty()) {
      r.error = errc::connection_refused;
    } else {
      r = from_aare(f->user_data, true, proposed, opts);
    }
  } else if (std::holds_alternative<ps::user_abort_indication>(ev) ||
             std::holds_alternative<ps::provider_abort_indication>(ev)) {
    r.error = errc::peer_aborted;
  } else if (const auto* a = std::get_if<ps::provider_abort>(&ev)) {
    r.error = a->error ? a->error : openiec61850::make_error_code(openiec61850::errc::protocol_violation);
  } else {
    r.error = openiec61850::make_error_code(openiec61850::errc::protocol_violation);
  }
  return r;
}

ps::connection_options responder_options(const server_options& o) {
  ps::connection_options c;
  c.session.local_selector = o.session_selector;
  c.local_selector = o.presentation_selector;
  c.supported_abstract_syntaxes = {ps::acse_abstract_syntax, ps::mms_abstract_syntax};
  return c;
}

associate_indication parse_associate_request(const ps::connect_indication& ind,
                                             const mms::decode_options& opts) {
  associate_indication r;
  r.acse_context = accepted_context(ind.contexts, ps::acse_abstract_syntax);
  r.mms_context = accepted_context(ind.contexts, ps::mms_abstract_syntax);
  if (!r.acse_context) return r;
  const auto* p = find_pdv(ind.user_data, *r.acse_context);
  if (p == nullptr) return r;
  auto apdu = acse::decode(p->data);
  if (!apdu || !std::holds_alternative<acse::aarq_apdu>(*apdu)) return r;
  const auto& aarq = std::get<acse::aarq_apdu>(*apdu);
  if (aarq.application_context_name != acse::oids::mms_application_context) {
    r.diagnostic = acse::service_user_diagnostic::application_context_name_not_supported;
    return r;
  }
  if (!r.mms_context) return r;

  association_request q;
  q.calling_presentation_selector.assign(ind.calling_selector.begin(), ind.calling_selector.end());
  q.called_presentation_selector.assign(ind.called_selector.begin(), ind.called_selector.end());
  q.calling_ap_title = title_of(aarq.calling_ap_title);
  q.calling_ae_qualifier = qualifier_of(aarq.calling_ae_qualifier);
  q.called_ap_title = title_of(aarq.called_ap_title);
  q.called_ae_qualifier = qualifier_of(aarq.called_ae_qualifier);
  q.mechanism_name = aarq.mechanism_name;
  if (aarq.authentication) {
    if (const auto* c = std::get_if<acse::auth_charstring>(&*aarq.authentication)) {
      q.password = std::string(c->value);
    }
  }
  const auto* x = mms_external(aarq.user_information, *r.mms_context);
  if (x == nullptr || x->encoding != acse::external_encoding::single_asn1_type) {
    r.initiate_failed = true;
    return r;
  }
  auto pdu = mms::decode_pdu(x->data, opts);
  if (!pdu || !std::holds_alternative<mms::initiate_request>(*pdu)) {
    r.initiate_failed = true;
    return r;
  }
  q.initiate = std::get<mms::initiate_request>(*pdu);
  r.request = std::move(q);
  r.diagnostic = acse::service_user_diagnostic::null;
  return r;
}

result<void> accept_association(ps::connection& pc, const associate_indication& ind,
                                const server_options& o, const mms::initiate_response& negotiated,
                                byte_buffer& out) {
  if (!ind.acse_context || !ind.mms_context) return openiec61850::errc::invalid_state;
  auto response = encode_mms(mms::mms_pdu{negotiated});
  if (!response) return response.error();
  auto aare = acse::make_mms_aare(*ind.mms_context, *response);
  aare.responding_ap_title = title(o.ap_title);
  aare.responding_ae_qualifier = qualifier(o.ae_qualifier);
  auto encoded = encode_acse(aare);
  if (!encoded) return encoded.error();
  const auto pdv = single(*ind.acse_context, *encoded);
  return pc.accept({&pdv, 1}, out);
}

result<void> refuse_association(ps::connection& pc, const associate_indication& ind,
                                const server_options& o, std::int64_t diagnostic,
                                byte_buffer& out) {
  if (!ind.acse_context) return pc.refuse({}, out);
  acse::aare_apdu aare;
  aare.protocol_version = acse::protocol_version::version1;
  aare.application_context_name = acse::oids::mms_application_context;
  aare.result = acse::associate_result::rejected_permanent;
  aare.result_source_diagnostic = {acse::diagnostic_source::service_user, diagnostic};
  aare.responding_ap_title = title(o.ap_title);
  aare.responding_ae_qualifier = qualifier(o.ae_qualifier);
  byte_buffer initiate_error;
  if (ind.initiate_failed && ind.mms_context) {
    // ISO 9506-2: a negative Initiate is an Initiate-ErrorPDU in a rejected AARE.
    auto e = encode_mms(mms::mms_pdu{mms::initiate_error{
        mms::service_error(mms::error_class::initiate, mms::error_code::initiate::other)}});
    if (!e) return e.error();
    initiate_error = std::move(*e);
    aare.user_information.push_back(acse::single_asn1_external(*ind.mms_context, initiate_error));
  }
  auto encoded = encode_acse(aare);
  if (!encoded) return encoded.error();
  const auto pdv = single(*ind.acse_context, *encoded);
  return pc.refuse({&pdv, 1}, out);
}

}  // namespace openiec61850::association::detail
