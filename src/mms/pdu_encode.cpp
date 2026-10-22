#include <type_traits>

#include "detail.hpp"
#include "openiec61850/ber/writer.hpp"
#include "openiec61850/mms/pdu.hpp"

namespace openiec61850::mms {
namespace {

using ber::context;

// SEQUENCE OF: encoded-mode lists are copied verbatim.
template <typename T, typename F>
result<void> write_list(ber::writer& w, ber::tag t, const list_view<T>& list, F&& element) {
  if (list.is_encoded()) {
    w.write_tlv(t.as_constructed(), list.encoded_contents());
    return {};
  }
  const auto m = w.begin(t);
  for (const auto& x : list) {
    if (auto r = element(x); !r) return r;
  }
  w.end(m);
  return {};
}

void write_object_name(ber::writer& w, const object_name& n) {
  switch (n.scope) {
    case object_scope::vmd_specific:
      w.write_visible_string(n.item_id, context(0));
      return;
    case object_scope::domain_specific: {
      const auto m = w.begin(context(1, true));
      w.write_visible_string(n.domain_id);
      w.write_visible_string(n.item_id);
      w.end(m);
      return;
    }
    case object_scope::aa_specific:
      w.write_visible_string(n.item_id, context(2));
      return;
  }
}

void write_wrapped_name(ber::writer& w, ber::tag t, const object_name& n) {
  const auto m = w.begin(t);
  write_object_name(w, n);
  w.end(m);
}

result<void> write_variable_specs(ber::writer& w, ber::tag t, const list_view<variable_spec>& l) {
  return write_list(w, t, l, [&](const variable_spec& v) -> result<void> {
    const auto seq = w.begin(ber::tags::sequence);
    write_wrapped_name(w, context(0, true), v.name);
    if (!v.alternate_access.empty()) w.write_tlv(context(5, true), v.alternate_access);
    w.end(seq);
    return {};
  });
}

result<void> write_vas(ber::writer& w, const variable_access_specification& s) {
  if (s.type == variable_access_specification::kind::variable_list_name) {
    write_wrapped_name(w, context(1, true), s.list_name);
    return {};
  }
  return write_variable_specs(w, context(0, true), s.variables);
}

result<void> write_access_results(ber::writer& w, ber::tag t, const list_view<access_result>& l) {
  return write_list(w, t, l, [&](const access_result& r) -> result<void> {
    if (r.failure) {
      w.write_integer(static_cast<std::int64_t>(*r.failure), context(0));
      return {};
    }
    return r.value.encode(w);
  });
}

void write_service_error(ber::writer& w, ber::tag t, const service_error& e) {
  const auto m = w.begin(t);
  const auto cls = w.begin(context(0, true));
  w.write_integer(e.code, context(static_cast<std::uint32_t>(e.cls)));
  w.end(cls);
  if (e.additional_code) w.write_integer(*e.additional_code, context(1));
  if (e.additional_description) w.write_visible_string(*e.additional_description, context(2));
  if (!e.service_specific_info.empty()) w.write_tlv(context(3, true), e.service_specific_info);
  w.end(m);
}

// ----- confirmed services -----

constexpr ber::tag service(confirmed_service s, bool constructed = true) noexcept {
  return context(static_cast<std::uint32_t>(s), constructed);
}

result<void> put_request(ber::writer& w, const identify_request&) {
  w.write_null(service(confirmed_service::identify, false));
  return {};
}

result<void> put_request(ber::writer& w, const get_name_list_request& r) {
  const auto m = w.begin(service(confirmed_service::get_name_list));
  const auto oc = w.begin(context(0, true));
  w.write_integer(static_cast<std::int64_t>(r.cls), context(0));
  w.end(oc);
  const auto scope = w.begin(context(1, true));
  if (r.scope == object_scope::domain_specific) {
    w.write_visible_string(r.domain_id, context(1));
  } else {
    w.write_null(context(static_cast<std::uint32_t>(r.scope)));
  }
  w.end(scope);
  if (r.continue_after) w.write_visible_string(*r.continue_after, context(2));
  w.end(m);
  return {};
}

result<void> put_request(ber::writer& w, const read_request& r) {
  const auto m = w.begin(service(confirmed_service::read));
  if (r.specification_with_result) w.write_boolean(true, context(0));
  const auto spec = w.begin(context(1, true));
  if (auto e = write_vas(w, r.spec); !e) return e;
  w.end(spec);
  w.end(m);
  return {};
}

result<void> put_request(ber::writer& w, const write_request& r) {
  const auto m = w.begin(service(confirmed_service::write));
  if (auto e = write_vas(w, r.spec); !e) return e;
  auto e = write_list(w, context(0, true), r.values, [&](const data_ref& d) { return d.encode(w); });
  if (!e) return e;
  w.end(m);
  return {};
}

result<void> put_request(ber::writer& w, const get_variable_access_attributes_request& r) {
  const auto m = w.begin(service(confirmed_service::get_variable_access_attributes));
  write_wrapped_name(w, context(0, true), r.name);
  w.end(m);
  return {};
}

result<void> put_request(ber::writer& w, const get_named_variable_list_attributes_request& r) {
  write_wrapped_name(w, service(confirmed_service::get_named_variable_list_attributes), r.name);
  return {};
}

result<void> put_request(ber::writer& w, const define_named_variable_list_request& r) {
  const auto m = w.begin(service(confirmed_service::define_named_variable_list));
  write_object_name(w, r.name);
  if (auto e = write_variable_specs(w, context(0, true), r.variables); !e) return e;
  w.end(m);
  return {};
}

result<void> put_request(ber::writer& w, const delete_named_variable_list_request& r) {
  const auto m = w.begin(service(confirmed_service::delete_named_variable_list));
  if (r.scope != delete_scope::specific) {
    w.write_integer(static_cast<std::int64_t>(r.scope), context(0));
  }
  if (!r.names.empty()) {
    auto e = write_list(w, context(1, true), r.names, [&](const object_name& n) -> result<void> {
      write_object_name(w, n);
      return {};
    });
    if (!e) return e;
  }
  if (r.domain_name) w.write_visible_string(*r.domain_name, context(2));
  w.end(m);
  return {};
}

result<void> put_request(ber::writer& w, const other_service& s) {
  w.write_raw(s.encoding);
  return {};
}

result<void> put_response(ber::writer& w, const identify_response& r) {
  const auto m = w.begin(service(confirmed_service::identify));
  w.write_utf8_string(r.vendor_name, context(0));
  w.write_utf8_string(r.model_name, context(1));
  w.write_utf8_string(r.revision, context(2));
  if (!r.abstract_syntaxes.empty()) {
    auto e = write_list(w, context(3, true), r.abstract_syntaxes,
                        [&](const ber::oid& o) -> result<void> {
                          if (!w.write_oid(o)) return errc::invalid_state;
                          return {};
                        });
    if (!e) return e;
  }
  w.end(m);
  return {};
}

result<void> put_response(ber::writer& w, const get_name_list_response& r) {
  const auto m = w.begin(service(confirmed_service::get_name_list));
  auto e = write_list(w, context(0, true), r.identifiers, [&](std::string_view id) -> result<void> {
    w.write_visible_string(id);
    return {};
  });
  if (!e) return e;
  if (!r.more_follows) w.write_boolean(false, context(1));
  w.end(m);
  return {};
}

result<void> put_response(ber::writer& w, const read_response& r) {
  const auto m = w.begin(service(confirmed_service::read));
  if (r.spec) {
    const auto spec = w.begin(context(0, true));
    if (auto e = write_vas(w, *r.spec); !e) return e;
    w.end(spec);
  }
  if (auto e = write_access_results(w, context(1, true), r.results); !e) return e;
  w.end(m);
  return {};
}

result<void> put_response(ber::writer& w, const write_response& r) {
  return write_list(w, service(confirmed_service::write), r.results,
                    [&](const write_result& x) -> result<void> {
                      if (x.failure) {
                        w.write_integer(static_cast<std::int64_t>(*x.failure), context(0));
                      } else {
                        w.write_null(context(1));
                      }
                      return {};
                    });
}

result<void> put_response(ber::writer& w, const get_variable_access_attributes_response& r) {
  const auto m = w.begin(service(confirmed_service::get_variable_access_attributes));
  w.write_boolean(r.mms_deletable, context(0));
  const auto td = w.begin(context(2, true));
  if (auto e = r.type.encode(w); !e) return e;
  w.end(td);
  w.end(m);
  return {};
}

result<void> put_response(ber::writer& w, const get_named_variable_list_attributes_response& r) {
  const auto m = w.begin(service(confirmed_service::get_named_variable_list_attributes));
  w.write_boolean(r.mms_deletable, context(0));
  if (auto e = write_variable_specs(w, context(1, true), r.variables); !e) return e;
  w.end(m);
  return {};
}

result<void> put_response(ber::writer& w, const define_named_variable_list_response&) {
  w.write_null(service(confirmed_service::define_named_variable_list, false));
  return {};
}

result<void> put_response(ber::writer& w, const delete_named_variable_list_response& r) {
  const auto m = w.begin(service(confirmed_service::delete_named_variable_list));
  w.write_unsigned(r.number_matched, context(0));
  w.write_unsigned(r.number_deleted, context(1));
  w.end(m);
  return {};
}

result<void> put_response(ber::writer& w, const other_service& s) {
  w.write_raw(s.encoding);
  return {};
}

// ----- PDUs -----

constexpr ber::tag pdu_tag(pdu_type t, bool constructed = true) noexcept {
  return context(static_cast<std::uint32_t>(t), constructed);
}

template <typename Pdu>
result<void> write_initiate(ber::writer& w, ber::tag t, const Pdu& p,
                            const std::optional<std::int32_t>& local_detail) {
  const auto m = w.begin(t);
  if (local_detail) w.write_integer(*local_detail, context(0));
  w.write_integer(p.max_serv_outstanding_calling, context(1));
  w.write_integer(p.max_serv_outstanding_called, context(2));
  if (p.data_structure_nesting_level) w.write_integer(*p.data_structure_nesting_level, context(3));
  const auto d = w.begin(context(4, true));
  w.write_integer(p.detail.version_number, context(0));
  if (auto e = w.write_bit_string(p.detail.parameter_cbb.bytes(),
                                  p.detail.parameter_cbb.bit_count(), context(1));
      !e) {
    return e;
  }
  if (auto e = w.write_bit_string(p.detail.services.bytes(), p.detail.services.bit_count(),
                                  context(2));
      !e) {
    return e;
  }
  w.end(d);
  w.end(m);
  return {};
}

result<void> write_pdu(ber::writer& w, const confirmed_request& p) {
  const auto m = w.begin(pdu_tag(pdu_type::confirmed_request));
  w.write_unsigned(p.invoke_id);
  if (!p.modifiers.empty()) w.write_tlv(ber::tags::sequence, p.modifiers);
  auto e = std::visit([&](const auto& s) { return put_request(w, s); }, p.service);
  if (!e) return e;
  w.end(m);
  return {};
}

result<void> write_pdu(ber::writer& w, const confirmed_response& p) {
  const auto m = w.begin(pdu_tag(pdu_type::confirmed_response));
  w.write_unsigned(p.invoke_id);
  auto e = std::visit([&](const auto& s) { return put_response(w, s); }, p.service);
  if (!e) return e;
  w.end(m);
  return {};
}

result<void> write_pdu(ber::writer& w, const confirmed_error& p) {
  const auto m = w.begin(pdu_tag(pdu_type::confirmed_error));
  w.write_unsigned(p.invoke_id, context(0));
  if (p.modifier_position) w.write_unsigned(*p.modifier_position, context(1));
  write_service_error(w, context(2, true), p.error);
  w.end(m);
  return {};
}

result<void> write_pdu(ber::writer& w, const unconfirmed_pdu& p) {
  const auto m = w.begin(pdu_tag(pdu_type::unconfirmed));
  if (const auto* report = std::get_if<information_report>(&p.service)) {
    const auto body = w.begin(context(0, true));
    if (auto e = write_vas(w, report->spec); !e) return e;
    if (auto e = write_access_results(w, context(0, true), report->results); !e) return e;
    w.end(body);
  } else {
    w.write_raw(std::get<other_service>(p.service).encoding);
  }
  w.end(m);
  return {};
}

result<void> write_pdu(ber::writer& w, const reject_pdu& p) {
  const auto m = w.begin(pdu_tag(pdu_type::reject));
  if (p.original_invoke_id) w.write_unsigned(*p.original_invoke_id, context(0));
  w.write_integer(p.reason, context(static_cast<std::uint32_t>(p.type)));
  w.end(m);
  return {};
}

result<void> write_pdu(ber::writer& w, const cancel_request& p) {
  w.write_unsigned(p.invoke_id, pdu_tag(pdu_type::cancel_request, false));
  return {};
}

result<void> write_pdu(ber::writer& w, const cancel_response& p) {
  w.write_unsigned(p.invoke_id, pdu_tag(pdu_type::cancel_response, false));
  return {};
}

result<void> write_pdu(ber::writer& w, const cancel_error& p) {
  const auto m = w.begin(pdu_tag(pdu_type::cancel_error));
  w.write_unsigned(p.invoke_id, context(0));
  write_service_error(w, context(1, true), p.error);
  w.end(m);
  return {};
}

result<void> write_pdu(ber::writer& w, const initiate_request& p) {
  return write_initiate(w, pdu_tag(pdu_type::initiate_request), p, p.local_detail_calling);
}

result<void> write_pdu(ber::writer& w, const initiate_response& p) {
  return write_initiate(w, pdu_tag(pdu_type::initiate_response), p, p.local_detail_called);
}

result<void> write_pdu(ber::writer& w, const initiate_error& p) {
  write_service_error(w, pdu_tag(pdu_type::initiate_error), p.error);
  return {};
}

result<void> write_pdu(ber::writer& w, const conclude_request&) {
  w.write_null(pdu_tag(pdu_type::conclude_request, false));
  return {};
}

result<void> write_pdu(ber::writer& w, const conclude_response&) {
  w.write_null(pdu_tag(pdu_type::conclude_response, false));
  return {};
}

result<void> write_pdu(ber::writer& w, const conclude_error& p) {
  write_service_error(w, pdu_tag(pdu_type::conclude_error), p.error);
  return {};
}

constexpr std::uint32_t service_tags[] = {2, 1, 4, 5, 6, 12, 11, 13};

}  // namespace

result<void> encode_pdu(const mms_pdu& pdu, byte_buffer& out) {
  const std::size_t original = out.size();
  ber::writer w{out};
  auto r = std::visit([&](const auto& p) { return write_pdu(w, p); }, pdu);
  if (!r) out.resize(original);
  return r;
}

std::uint32_t service_tag(const confirmed_service_request& s) noexcept {
  if (const auto* o = std::get_if<other_service>(&s)) return o->tag;
  return service_tags[s.index()];
}

std::uint32_t service_tag(const confirmed_service_response& s) noexcept {
  if (const auto* o = std::get_if<other_service>(&s)) return o->tag;
  return service_tags[s.index()];
}

std::optional<std::uint32_t> invoke_id(const mms_pdu& pdu) noexcept {
  return std::visit(
      [](const auto& p) -> std::optional<std::uint32_t> {
        using T = std::decay_t<decltype(p)>;
        if constexpr (std::is_same_v<T, confirmed_request> || std::is_same_v<T, confirmed_response> ||
                      std::is_same_v<T, confirmed_error> || std::is_same_v<T, cancel_request> ||
                      std::is_same_v<T, cancel_response> || std::is_same_v<T, cancel_error>) {
          return p.invoke_id;
        } else if constexpr (std::is_same_v<T, reject_pdu>) {
          return p.original_invoke_id;
        } else {
          return std::nullopt;
        }
      },
      pdu);
}

}  // namespace openiec61850::mms
