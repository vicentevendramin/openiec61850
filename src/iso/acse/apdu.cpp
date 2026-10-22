#include "openiec61850/iso/acse/apdu.hpp"

#include <array>
#include <bit>
#include <utility>

#include "openiec61850/ber/reader.hpp"
#include "openiec61850/ber/tag.hpp"
#include "openiec61850/ber/writer.hpp"

namespace openiec61850::iso::acse {
namespace {

using ber::context;

constexpr std::uint32_t tag_implementation_information = 29;
constexpr std::uint32_t tag_user_information = 30;
constexpr ber::tag object_descriptor = ber::universal(7);

byte_view as_bytes(std::string_view s) noexcept {
  return {reinterpret_cast<const std::uint8_t*>(s.data()), s.size()};
}

// ---------------------------------------------------------------------------------------------
// Decoding

// Walks the components of an APDU SEQUENCE. `handle` returns true for a known (context-specific)
// field and false for an unknown one, which is skipped. Known fields must be in ascending order.
template <typename F>
result<void> for_each_field(ber::reader seq, F&& handle) {
  std::int64_t last = -1;
  while (!seq.empty()) {
    auto e = seq.next();
    if (!e) return e.error();
    if (e->tag.cls != ber::tag_class::context) continue;
    auto known = handle(*e, seq);
    if (!known) return known.error();
    if (!*known) continue;
    const auto n = static_cast<std::int64_t>(e->tag.number);
    if (n <= last) return errc::malformed_encoding;
    last = n;
  }
  return {};
}

// The single element inside an explicit tag.
result<ber::tlv> explicit_inner(const ber::tlv& e, const ber::reader& parent) {
  auto inner = parent.enter(e);
  if (!inner) return inner.error();
  auto v = inner->next();
  if (!v) return v.error();
  if (auto end = inner->expect_end(); !end) return end.error();
  return v;
}

result<ber::oid> explicit_oid(const ber::tlv& e, const ber::reader& parent) {
  auto v = explicit_inner(e, parent);
  if (!v) return v.error();
  if (v->tag.as_primitive() != ber::tags::object_identifier) return errc::malformed_encoding;
  return ber::decode_oid(*v);
}

result<std::int64_t> explicit_integer(const ber::tlv& e, const ber::reader& parent) {
  auto v = explicit_inner(e, parent);
  if (!v) return v.error();
  if (v->tag.as_primitive() != ber::tags::integer) return errc::malformed_encoding;
  return ber::decode_integer(*v);
}

result<std::uint32_t> named_bits(const ber::tlv& e) {
  auto bits = ber::decode_bit_string(e);
  if (!bits) return bits.error();
  std::uint32_t mask = 0;
  for (std::size_t i = 0; i < bits->bit_count && i < 32; ++i) {
    if (bits->test(i)) mask |= 1U << i;
  }
  return mask;
}

result<std::string_view> graphic_string(const ber::tlv& e) { return ber::decode_visible_string(e); }

result<ap_title> decode_ap_title(const ber::tlv& e, const ber::reader& parent) {
  auto v = explicit_inner(e, parent);
  if (!v) return v.error();
  if (v->tag.as_primitive() == ber::tags::object_identifier) {
    auto o = ber::decode_oid(*v);
    if (!o) return o.error();
    return ap_title{*o};
  }
  return ap_title{raw_form{v->encoding}};
}

result<ae_qualifier> decode_ae_qualifier(const ber::tlv& e, const ber::reader& parent) {
  auto v = explicit_inner(e, parent);
  if (!v) return v.error();
  if (v->tag.as_primitive() == ber::tags::integer) {
    auto i = ber::decode_integer(*v);
    if (!i) return i.error();
    return ae_qualifier{*i};
  }
  return ae_qualifier{raw_form{v->encoding}};
}

// Contents of an EXTERNAL (X.690 §8.18.1).
result<external> decode_external(const ber::tlv& e, const ber::reader& parent) {
  auto rd = parent.enter(e);
  if (!rd) return rd.error();
  external x;
  if (rd->next_is(ber::tags::object_identifier)) {
    auto o = rd->read_oid();
    if (!o) return o.error();
    x.direct_reference = *o;
  }
  if (rd->next_is(ber::tags::integer)) {
    auto i = rd->read_integer();
    if (!i) return i.error();
    x.indirect_reference = *i;
  }
  if (auto t = rd->peek_tag(); t && t->same_id(object_descriptor)) {
    auto d = rd->next();
    if (!d) return d.error();
    auto s = graphic_string(*d);
    if (!s) return s.error();
    x.data_value_descriptor = *s;
  }
  auto enc = rd->next();
  if (!enc) return enc.error() == errc::truncated_input ? errc::malformed_encoding : enc.error();
  if (enc->tag == context(0, true)) {
    auto v = explicit_inner(*enc, *rd);
    if (!v) return v.error();
    x.encoding = external_encoding::single_asn1_type;
    x.data = v->encoding;
  } else if (enc->tag.same_id(context(1))) {
    auto v = ber::decode_octet_string(*enc);
    if (!v) return v.error();
    x.encoding = external_encoding::octet_aligned;
    x.data = *v;
  } else if (enc->tag.same_id(context(2))) {
    auto v = ber::decode_bit_string(*enc);
    if (!v) return v.error();
    x.encoding = external_encoding::arbitrary;
    x.data = v->bytes;
    x.bit_count = v->bit_count;
  } else {
    return errc::malformed_encoding;
  }
  if (auto end = rd->expect_end(); !end) return end.error();
  return x;
}

result<user_information> decode_user_information(const ber::tlv& e, const ber::reader& parent) {
  auto rd = parent.enter(e);
  if (!rd) return rd.error();
  user_information info;
  while (!rd->empty()) {
    auto x = rd->expect(ber::tags::external);
    if (!x) return x.error();
    auto ext = decode_external(*x, *rd);
    if (!ext) return ext.error();
    info.push_back(std::move(*ext));
  }
  return info;
}

result<authentication_value> decode_authentication(const ber::tlv& e, const ber::reader& parent) {
  auto v = explicit_inner(e, parent);
  if (!v) return v.error();
  if (v->tag.cls != ber::tag_class::context) return errc::malformed_encoding;
  switch (v->tag.number) {
    case 0: {
      auto s = graphic_string(*v);
      if (!s) return s.error();
      return authentication_value{auth_charstring{*s}};
    }
    case 1: {
      auto b = ber::decode_bit_string(*v);
      if (!b) return b.error();
      return authentication_value{auth_bitstring{b->bytes, b->bit_count}};
    }
    case 2: {
      if (!v->constructed()) return errc::malformed_encoding;
      // The reader over the explicit tag's contents is only needed for the depth bound.
      auto outer = parent.enter(e);
      if (!outer) return outer.error();
      auto x = decode_external(*v, *outer);
      if (!x) return x.error();
      return authentication_value{auth_external{std::move(*x)}};
    }
    case 3: {
      auto outer = parent.enter(e);
      if (!outer) return outer.error();
      auto rd = outer->enter(*v);
      if (!rd) return rd.error();
      auto name = rd->read_oid();
      if (!name) return name.error();
      auto value = rd->next();
      if (!value) return value.error();
      if (auto end = rd->expect_end(); !end) return end.error();
      return authentication_value{auth_other{*name, value->encoding}};
    }
    default:
      return errc::malformed_encoding;
  }
}

template <typename T, typename R>
result<bool> assign(std::optional<T>& dst, R&& r) {
  if (!r) return r.error();
  dst = std::move(*r);
  return true;
}

template <typename T, typename R>
result<bool> assign_value(T& dst, R&& r) {
  if (!r) return r.error();
  dst = std::move(*r);
  return true;
}

// Fields shared by AARQ and AARE that are tagged identically.
template <typename A>
result<bool> common_field(A& a, const ber::tlv& e, const ber::reader& seq) {
  switch (e.tag.number) {
    case 0:
      return assign(a.protocol_version, named_bits(e));
    case 1:
      if (!e.constructed()) return errc::malformed_encoding;
      return assign_value(a.application_context_name, explicit_oid(e, seq));
    case tag_implementation_information:
      return assign(a.implementation_information, graphic_string(e));
    case tag_user_information:
      if (!e.constructed()) return errc::malformed_encoding;
      return assign_value(a.user_information, decode_user_information(e, seq));
    default:
      return false;
  }
}

result<bool> explicit_check(const ber::tlv& e) {
  if (!e.constructed()) return errc::malformed_encoding;
  return true;
}

result<aarq_apdu> decode_aarq(ber::reader seq) {
  aarq_apdu a;
  bool has_context = false;
  auto r = for_each_field(seq, [&](const ber::tlv& e, const ber::reader& rd) -> result<bool> {
    const auto n = e.tag.number;
    if (n == 1) has_context = true;
    if (n == 0 || n == 1 || n == tag_implementation_information || n == tag_user_information) {
      return common_field(a, e, rd);
    }
    if ((n >= 2 && n <= 9) || n == 12) {
      if (auto c = explicit_check(e); !c) return c;
    }
    switch (n) {
      case 2: return assign(a.called_ap_title, decode_ap_title(e, rd));
      case 3: return assign(a.called_ae_qualifier, decode_ae_qualifier(e, rd));
      case 4: return assign(a.called_ap_invocation_id, explicit_integer(e, rd));
      case 5: return assign(a.called_ae_invocation_id, explicit_integer(e, rd));
      case 6: return assign(a.calling_ap_title, decode_ap_title(e, rd));
      case 7: return assign(a.calling_ae_qualifier, decode_ae_qualifier(e, rd));
      case 8: return assign(a.calling_ap_invocation_id, explicit_integer(e, rd));
      case 9: return assign(a.calling_ae_invocation_id, explicit_integer(e, rd));
      case 10: return assign(a.acse_requirements, named_bits(e));
      case 11: return assign(a.mechanism_name, ber::decode_oid(e));
      case 12: return assign(a.authentication, decode_authentication(e, rd));
      case 13:
        if (!e.constructed()) return errc::malformed_encoding;
        a.application_context_name_list = e.value;
        return true;
      default: return false;
    }
  });
  if (!r) return r.error();
  if (!has_context) return errc::malformed_encoding;
  return a;
}

result<associate_source_diagnostic> decode_source_diagnostic(const ber::tlv& e,
                                                             const ber::reader& parent) {
  auto v = explicit_inner(e, parent);
  if (!v) return v.error();
  if (v->tag != context(1, true) && v->tag != context(2, true)) return errc::malformed_encoding;
  auto outer = parent.enter(e);
  if (!outer) return outer.error();
  auto reason = explicit_integer(*v, *outer);
  if (!reason) return reason.error();
  return associate_source_diagnostic{static_cast<diagnostic_source>(v->tag.number), *reason};
}

result<aare_apdu> decode_aare(ber::reader seq) {
  aare_apdu a;
  bool has_context = false, has_result = false, has_diagnostic = false;
  auto r = for_each_field(seq, [&](const ber::tlv& e, const ber::reader& rd) -> result<bool> {
    const auto n = e.tag.number;
    if (n == 1) has_context = true;
    if (n == 0 || n == 1 || n == tag_implementation_information || n == tag_user_information) {
      return common_field(a, e, rd);
    }
    if ((n >= 2 && n <= 7) || n == 10) {
      if (auto c = explicit_check(e); !c) return c;
    }
    switch (n) {
      case 2: has_result = true; return assign_value(a.result, explicit_integer(e, rd));
      case 3:
        has_diagnostic = true;
        return assign_value(a.result_source_diagnostic, decode_source_diagnostic(e, rd));
      case 4: return assign(a.responding_ap_title, decode_ap_title(e, rd));
      case 5: return assign(a.responding_ae_qualifier, decode_ae_qualifier(e, rd));
      case 6: return assign(a.responding_ap_invocation_id, explicit_integer(e, rd));
      case 7: return assign(a.responding_ae_invocation_id, explicit_integer(e, rd));
      case 8: return assign(a.acse_requirements, named_bits(e));
      case 9: return assign(a.mechanism_name, ber::decode_oid(e));
      case 10: return assign(a.authentication, decode_authentication(e, rd));
      case 11:
        if (!e.constructed()) return errc::malformed_encoding;
        a.application_context_name_list = e.value;
        return true;
      default: return false;
    }
  });
  if (!r) return r.error();
  if (!has_context || !has_result || !has_diagnostic) return errc::malformed_encoding;
  return a;
}

template <typename A>
result<A> decode_release(ber::reader seq) {
  A a;
  auto r = for_each_field(seq, [&](const ber::tlv& e, const ber::reader& rd) -> result<bool> {
    switch (e.tag.number) {
      case 0: return assign(a.reason, ber::decode_integer(e));
      case tag_user_information:
        if (!e.constructed()) return errc::malformed_encoding;
        return assign_value(a.user_information, decode_user_information(e, rd));
      default: return false;
    }
  });
  if (!r) return r.error();
  return a;
}

result<abrt_apdu> decode_abrt(ber::reader seq) {
  abrt_apdu a;
  bool has_source = false;
  auto r = for_each_field(seq, [&](const ber::tlv& e, const ber::reader& rd) -> result<bool> {
    switch (e.tag.number) {
      case 0: has_source = true; return assign_value(a.source, ber::decode_integer(e));
      case 1: return assign(a.diagnostic, ber::decode_enumerated(e));
      case tag_user_information:
        if (!e.constructed()) return errc::malformed_encoding;
        return assign_value(a.user_information, decode_user_information(e, rd));
      default: return false;
    }
  });
  if (!r) return r.error();
  if (!has_source) return errc::malformed_encoding;
  return a;
}

// ---------------------------------------------------------------------------------------------
// Encoding

using marker = ber::writer::marker;

result<void> put_oid(ber::writer& w, const ber::oid& o, ber::tag t = ber::tags::object_identifier) {
  if (!w.write_oid(o, t)) return errc::invalid_state;
  return {};
}

result<void> put_named_bits(ber::writer& w, std::uint32_t mask, ber::tag t) {
  // X.690 §11.2.2: trailing zero bits of a named bit list are removed.
  const auto bit_count = static_cast<std::size_t>(32 - std::countl_zero(mask));
  std::array<std::uint8_t, 4> bytes{};
  for (std::size_t i = 0; i < bit_count; ++i) {
    if ((mask >> i) & 1U) bytes[i / 8] = static_cast<std::uint8_t>(bytes[i / 8] | (0x80U >> (i % 8)));
  }
  if (!w.write_bit_string(byte_view{bytes.data(), (bit_count + 7) / 8}, bit_count, t)) {
    return errc::invalid_state;
  }
  return {};
}

// A raw field must be exactly one TLV.
result<void> put_raw(ber::writer& w, byte_view encoding) {
  auto e = ber::decode_tlv(encoding);
  if (!e || e->encoding.size() != encoding.size()) return errc::invalid_state;
  w.write_raw(encoding);
  return {};
}

result<void> put_explicit_oid(ber::writer& w, std::uint32_t n, const ber::oid& o) {
  const marker m = w.begin(context(n, true));
  if (auto r = put_oid(w, o); !r) return r;
  w.end(m);
  return {};
}

void put_explicit_integer(ber::writer& w, std::uint32_t n, std::int64_t v) {
  w.constructed(context(n, true), [&] { w.write_integer(v); });
}

result<void> put_ap_title(ber::writer& w, std::uint32_t n, const ap_title& t) {
  const marker m = w.begin(context(n, true));
  if (const auto* o = std::get_if<ber::oid>(&t)) {
    if (auto r = put_oid(w, *o); !r) return r;
  } else if (auto r = put_raw(w, std::get<raw_form>(t).encoding); !r) {
    return r;
  }
  w.end(m);
  return {};
}

result<void> put_ae_qualifier(ber::writer& w, std::uint32_t n, const ae_qualifier& q) {
  const marker m = w.begin(context(n, true));
  if (const auto* i = std::get_if<std::int64_t>(&q)) {
    w.write_integer(*i);
  } else if (auto r = put_raw(w, std::get<raw_form>(q).encoding); !r) {
    return r;
  }
  w.end(m);
  return {};
}

result<void> put_external_contents(ber::writer& w, const external& x) {
  if (x.direct_reference) {
    if (auto r = put_oid(w, *x.direct_reference); !r) return r;
  }
  if (x.indirect_reference) w.write_integer(*x.indirect_reference);
  if (x.data_value_descriptor) w.write_tlv(object_descriptor, as_bytes(*x.data_value_descriptor));
  switch (x.encoding) {
    case external_encoding::single_asn1_type: {
      const marker m = w.begin(context(0, true));
      if (auto r = put_raw(w, x.data); !r) return r;
      w.end(m);
      return {};
    }
    case external_encoding::octet_aligned:
      w.write_octet_string(x.data, context(1));
      return {};
    case external_encoding::arbitrary:
      if (!w.write_bit_string(x.data, x.bit_count, context(2))) return errc::invalid_state;
      return {};
  }
  return errc::invalid_state;
}

result<void> put_user_information(ber::writer& w, const user_information& info) {
  if (info.empty()) return {};
  const marker m = w.begin(context(tag_user_information, true));
  for (const auto& x : info) {
    const marker mx = w.begin(ber::tags::external);
    if (auto r = put_external_contents(w, x); !r) return r;
    w.end(mx);
  }
  w.end(m);
  return {};
}

result<void> put_authentication(ber::writer& w, std::uint32_t n, const authentication_value& v) {
  const marker m = w.begin(context(n, true));
  if (const auto* c = std::get_if<auth_charstring>(&v)) {
    w.write_tlv(context(0), as_bytes(c->value));
  } else if (const auto* b = std::get_if<auth_bitstring>(&v)) {
    if (!w.write_bit_string(b->bytes, b->bit_count, context(1))) return errc::invalid_state;
  } else if (const auto* x = std::get_if<auth_external>(&v)) {
    const marker mx = w.begin(context(2, true));
    if (auto r = put_external_contents(w, x->value); !r) return r;
    w.end(mx);
  } else {
    const auto& o = std::get<auth_other>(v);
    const marker mo = w.begin(context(3, true));
    if (auto r = put_oid(w, o.mechanism); !r) return r;
    if (auto r = put_raw(w, o.value); !r) return r;
    w.end(mo);
  }
  w.end(m);
  return {};
}

// Runs `body` on a writer over `out`; on failure `out` is restored.
template <typename F>
result<void> encode_into(byte_buffer& out, std::uint32_t application_tag, F&& body) {
  const auto start = out.size();
  ber::writer w{out};
  const marker m = w.begin(ber::application(application_tag, true));
  if (auto r = body(w); !r) {
    out.resize(start);
    return r;
  }
  w.end(m);
  return {};
}

#define OPENIEC61850_TRY(expr) \
  do {                         \
    if (auto r_ = (expr); !r_) return r_; \
  } while (false)

template <typename A>
result<void> put_tail(ber::writer& w, const A& a, std::uint32_t list_tag) {
  if (!a.application_context_name_list.empty()) {
    w.write_tlv(context(list_tag, true), a.application_context_name_list);
  }
  if (a.implementation_information) {
    w.write_tlv(context(tag_implementation_information), as_bytes(*a.implementation_information));
  }
  return put_user_information(w, a.user_information);
}

}  // namespace

result<apdu> decode(byte_view data, const ber::decode_options& opts) {
  ber::reader top{data, opts};
  auto e = top.next();
  if (!e) return e.error();
  if (auto end = top.expect_end(); !end) return end.error();
  if (e->tag.cls != ber::tag_class::application || !e->constructed()) {
    return errc::malformed_encoding;
  }
  auto seq = top.enter(*e);
  if (!seq) return seq.error();
  switch (e->tag.number) {
    case 0: {
      auto a = decode_aarq(*seq);
      if (!a) return a.error();
      return apdu{std::move(*a)};
    }
    case 1: {
      auto a = decode_aare(*seq);
      if (!a) return a.error();
      return apdu{std::move(*a)};
    }
    case 2: {
      auto a = decode_release<rlrq_apdu>(*seq);
      if (!a) return a.error();
      return apdu{std::move(*a)};
    }
    case 3: {
      auto a = decode_release<rlre_apdu>(*seq);
      if (!a) return a.error();
      return apdu{std::move(*a)};
    }
    case 4: {
      auto a = decode_abrt(*seq);
      if (!a) return a.error();
      return apdu{std::move(*a)};
    }
    case 5:
    case 6:
    case 7:
      return errc::unsupported;
    default:
      return errc::malformed_encoding;
  }
}

result<void> encode(const aarq_apdu& a, byte_buffer& out) {
  return encode_into(out, 0, [&](ber::writer& w) -> result<void> {
    if (a.protocol_version) OPENIEC61850_TRY(put_named_bits(w, *a.protocol_version, context(0)));
    OPENIEC61850_TRY(put_explicit_oid(w, 1, a.application_context_name));
    if (a.called_ap_title) OPENIEC61850_TRY(put_ap_title(w, 2, *a.called_ap_title));
    if (a.called_ae_qualifier) OPENIEC61850_TRY(put_ae_qualifier(w, 3, *a.called_ae_qualifier));
    if (a.called_ap_invocation_id) put_explicit_integer(w, 4, *a.called_ap_invocation_id);
    if (a.called_ae_invocation_id) put_explicit_integer(w, 5, *a.called_ae_invocation_id);
    if (a.calling_ap_title) OPENIEC61850_TRY(put_ap_title(w, 6, *a.calling_ap_title));
    if (a.calling_ae_qualifier) OPENIEC61850_TRY(put_ae_qualifier(w, 7, *a.calling_ae_qualifier));
    if (a.calling_ap_invocation_id) put_explicit_integer(w, 8, *a.calling_ap_invocation_id);
    if (a.calling_ae_invocation_id) put_explicit_integer(w, 9, *a.calling_ae_invocation_id);
    if (a.acse_requirements) OPENIEC61850_TRY(put_named_bits(w, *a.acse_requirements, context(10)));
    if (a.mechanism_name) OPENIEC61850_TRY(put_oid(w, *a.mechanism_name, context(11)));
    if (a.authentication) OPENIEC61850_TRY(put_authentication(w, 12, *a.authentication));
    return put_tail(w, a, 13);
  });
}

result<void> encode(const aare_apdu& a, byte_buffer& out) {
  return encode_into(out, 1, [&](ber::writer& w) -> result<void> {
    if (a.protocol_version) OPENIEC61850_TRY(put_named_bits(w, *a.protocol_version, context(0)));
    OPENIEC61850_TRY(put_explicit_oid(w, 1, a.application_context_name));
    put_explicit_integer(w, 2, a.result);
    const auto& d = a.result_source_diagnostic;
    if (d.source != diagnostic_source::service_user && d.source != diagnostic_source::service_provider) {
      return errc::invalid_state;
    }
    w.constructed(context(3, true),
                  [&] { put_explicit_integer(w, static_cast<std::uint32_t>(d.source), d.reason); });
    if (a.responding_ap_title) OPENIEC61850_TRY(put_ap_title(w, 4, *a.responding_ap_title));
    if (a.responding_ae_qualifier) {
      OPENIEC61850_TRY(put_ae_qualifier(w, 5, *a.responding_ae_qualifier));
    }
    if (a.responding_ap_invocation_id) put_explicit_integer(w, 6, *a.responding_ap_invocation_id);
    if (a.responding_ae_invocation_id) put_explicit_integer(w, 7, *a.responding_ae_invocation_id);
    if (a.acse_requirements) OPENIEC61850_TRY(put_named_bits(w, *a.acse_requirements, context(8)));
    if (a.mechanism_name) OPENIEC61850_TRY(put_oid(w, *a.mechanism_name, context(9)));
    if (a.authentication) OPENIEC61850_TRY(put_authentication(w, 10, *a.authentication));
    return put_tail(w, a, 11);
  });
}

result<void> encode(const rlrq_apdu& a, byte_buffer& out) {
  return encode_into(out, 2, [&](ber::writer& w) -> result<void> {
    if (a.reason) w.write_integer(*a.reason, context(0));
    return put_user_information(w, a.user_information);
  });
}

result<void> encode(const rlre_apdu& a, byte_buffer& out) {
  return encode_into(out, 3, [&](ber::writer& w) -> result<void> {
    if (a.reason) w.write_integer(*a.reason, context(0));
    return put_user_information(w, a.user_information);
  });
}

result<void> encode(const abrt_apdu& a, byte_buffer& out) {
  return encode_into(out, 4, [&](ber::writer& w) -> result<void> {
    w.write_integer(a.source, context(0));
    if (a.diagnostic) w.write_enumerated(*a.diagnostic, context(1));
    return put_user_information(w, a.user_information);
  });
}

result<void> encode(const apdu& a, byte_buffer& out) {
  return std::visit([&](const auto& x) { return encode(x, out); }, a);
}

const external* find_by_context(std::span<const external> info, std::int64_t context_id) noexcept {
  for (const auto& x : info) {
    if (x.indirect_reference == context_id) return &x;
  }
  return nullptr;
}

external single_asn1_external(std::int64_t context_id, byte_view value) {
  external x;
  x.indirect_reference = context_id;
  x.encoding = external_encoding::single_asn1_type;
  x.data = value;
  return x;
}

aarq_apdu make_mms_aarq(const mms_aarq_params& p) {
  aarq_apdu a;
  a.protocol_version = protocol_version::version1;
  a.application_context_name = oids::mms_application_context;
  a.called_ap_title = p.called_ap_title;
  a.called_ae_qualifier = p.called_ae_qualifier;
  a.calling_ap_title = p.calling_ap_title;
  a.calling_ae_qualifier = p.calling_ae_qualifier;
  if (p.password) {
    a.acse_requirements = acse_requirements::authentication;
    a.mechanism_name = oids::password_mechanism;
    a.authentication = auth_charstring{*p.password};
  }
  a.user_information.push_back(single_asn1_external(p.mms_context_id, p.initiate_request));
  return a;
}

aare_apdu make_mms_aare(std::int64_t mms_context_id, byte_view initiate_response) {
  aare_apdu a;
  a.protocol_version = protocol_version::version1;
  a.application_context_name = oids::mms_application_context;
  a.result = associate_result::accepted;
  a.result_source_diagnostic = {diagnostic_source::service_user, service_user_diagnostic::null};
  a.user_information.push_back(single_asn1_external(mms_context_id, initiate_response));
  return a;
}

}  // namespace openiec61850::iso::acse
