#include "openiec61850/iso/presentation/ppdu.hpp"

#include <array>
#include <limits>

#include "openiec61850/ber/reader.hpp"
#include "openiec61850/ber/writer.hpp"

namespace openiec61850::iso::presentation {
namespace {

using ber::context;
using ber::reader;
using ber::tlv;
namespace tags = ber::tags;

constexpr ber::tag user_data_tag = ber::application(1, true);  // fully-encoded-data

// ---------------------------------------------------------------------------------------------
// Decoding

result<std::uint32_t> bits_of(const tlv& e) {
  auto bits = ber::decode_bit_string(e);
  if (!bits) return bits.error();
  std::uint32_t mask = 0;
  const std::size_t n = bits->bit_count < 32 ? bits->bit_count : 32;
  for (std::size_t i = 0; i < n; ++i) {
    if (bits->test(i)) mask |= std::uint32_t{1} << i;
  }
  return mask;
}

result<std::uint8_t> u8_of(const tlv& e) {
  auto v = ber::decode_unsigned(e);
  if (!v) return v.error();
  if (*v > std::numeric_limits<std::uint8_t>::max()) return errc::value_out_of_range;
  return static_cast<std::uint8_t>(*v);
}

result<context_result_code> result_code_of(const tlv& e) {
  auto v = ber::decode_integer(e);
  if (!v) return v.error();
  if (*v < 0 || *v > 2) return errc::malformed_encoding;
  return static_cast<context_result_code>(*v);
}

// Presentation-context-identifier ::= INTEGER (1..127, ..., 128..MAX)
result<std::uint32_t> context_id_of(const tlv& e) {
  auto v = ber::decode_unsigned(e);
  if (!v) return v.error();
  if (*v == 0) return errc::malformed_encoding;
  if (*v > std::numeric_limits<std::uint32_t>::max()) return errc::value_out_of_range;
  return static_cast<std::uint32_t>(*v);
}

result<std::uint32_t> read_context_id(reader& rd) {
  auto e = rd.expect(tags::integer);
  if (!e) return e.error();
  return context_id_of(*e);
}

result<void> read_mode(const reader& parent, const tlv& e) {
  auto set = parent.enter(e);
  if (!set) return set.error();
  auto value = set->read_integer(context(0));
  if (!value) return value.error();
  if (auto r = set->expect_end(); !r) return r;
  if (*value == mode::x410_1984) return errc::unsupported;
  if (*value != mode::normal) return errc::malformed_encoding;
  return {};
}

result<void> read_user_data(const reader& parent, const tlv& e, std::vector<pdv>& out) {
  if (e.tag.same_id(ber::application(0))) return errc::unsupported;  // simply-encoded-data
  if (e.tag != user_data_tag) return errc::malformed_encoding;
  auto list = parent.enter(e);
  if (!list) return list.error();
  if (list->empty()) return errc::malformed_encoding;  // SIZE (1..MAX)
  while (!list->empty()) {
    auto item = list->enter(tags::sequence);
    if (!item) return item.error();
    pdv p;
    if (item->next_is(tags::object_identifier)) {
      auto ts = item->read_oid();
      if (!ts) return ts.error();
      p.transfer_syntax = *ts;
    }
    auto id = read_context_id(*item);
    if (!id) return id.error();
    p.context_id = *id;
    auto v = item->next();
    if (!v) return v.error();
    if (v->tag == context(0, true)) {
      // The open type holds exactly one value of the abstract syntax.
      auto inner = ber::decode_tlv(v->value, item->options(), item->depth() + 1);
      if (!inner) return inner.error();
      if (inner->encoding.size() != v->value.size()) return errc::malformed_encoding;
      p.encoding = pdv_encoding::single_asn1_type;
      p.data = v->value;
    } else if (v->tag.same_id(context(1))) {
      auto octets = ber::decode_octet_string(*v);
      if (!octets) return octets.error();
      p.encoding = pdv_encoding::octet_aligned;
      p.data = *octets;
    } else if (v->tag.same_id(context(2))) {
      auto bits = ber::decode_bit_string(*v);
      if (!bits) return bits.error();
      p.encoding = pdv_encoding::arbitrary;
      p.data = bits->bytes;
      p.unused_bits = bits->unused_bits();
    } else {
      return errc::malformed_encoding;
    }
    if (auto r = item->expect_end(); !r) return r;
    out.push_back(p);
  }
  return {};
}

result<void> read_context_list(const reader& parent, const tlv& e,
                               std::vector<context_definition>& out) {
  auto list = parent.enter(e);
  if (!list) return list.error();
  while (!list->empty()) {
    auto item = list->enter(tags::sequence);
    if (!item) return item.error();
    context_definition d;
    auto id = read_context_id(*item);
    if (!id) return id.error();
    d.id = *id;
    auto as = item->read_oid();
    if (!as) return as.error();
    d.abstract_syntax = *as;
    auto ts_list = item->enter(tags::sequence);
    if (!ts_list) return ts_list.error();
    while (!ts_list->empty()) {
      auto ts = ts_list->read_oid();
      if (!ts) return ts.error();
      d.transfer_syntaxes.push_back(*ts);
    }
    if (d.transfer_syntaxes.empty()) return errc::malformed_encoding;
    if (auto r = item->expect_end(); !r) return r;
    out.push_back(std::move(d));
  }
  return {};
}

result<void> read_result_list(const reader& parent, const tlv& e,
                              std::vector<context_result>& out) {
  auto list = parent.enter(e);
  if (!list) return list.error();
  while (!list->empty()) {
    auto item = list->enter(tags::sequence);
    if (!item) return item.error();
    context_result c;
    auto code = item->expect(context(0));
    if (!code) return code.error();
    auto value = result_code_of(*code);
    if (!value) return value.error();
    c.result = *value;
    if (item->next_is(context(1))) {
      auto ts = item->read_oid(context(1));
      if (!ts) return ts.error();
      c.transfer_syntax = *ts;
    }
    if (item->next_is(context(2))) {
      auto reason = item->expect(context(2));
      if (!reason) return reason.error();
      auto v = u8_of(*reason);
      if (!v) return v.error();
      c.provider_reason = *v;
    }
    if (auto r = item->expect_end(); !r) return r;
    out.push_back(c);
  }
  return {};
}

// Walks the elements of a normal-mode-parameters SEQUENCE: context-specific elements in
// increasing tag order, then an optional User-data, which must be last. `field` handles the
// context-specific elements it knows and returns success for the others, which are skipped.
template <typename F>
result<void> walk_parameters(reader rd, std::vector<pdv>& user_data, F&& field) {
  std::int64_t last = -1;
  while (!rd.empty()) {
    auto e = rd.next();
    if (!e) return e.error();
    if (e->tag.cls == ber::tag_class::application) {
      if (auto r = read_user_data(rd, *e, user_data); !r) return r;
      return rd.expect_end();
    }
    if (e->tag.cls != ber::tag_class::context) return errc::malformed_encoding;
    if (static_cast<std::int64_t>(e->tag.number) <= last) return errc::malformed_encoding;
    last = e->tag.number;
    if (auto r = field(rd, *e); !r) return r;
  }
  return {};
}

result<void> read_selector(const tlv& e, byte_view& out) {
  auto v = ber::decode_octet_string(e);
  if (!v) return v.error();
  out = *v;
  return {};
}

result<void> read_bits_into(const tlv& e, std::optional<std::uint32_t>& out) {
  auto v = bits_of(e);
  if (!v) return v.error();
  out = *v;
  return {};
}

// Elements from [11] on (protocol-options, nominated contexts, extensions) are skipped; lower tags
// not defined for the PPDU at hand are rejected.
result<void> skip_extension(const tlv& e) {
  if (e.tag.number < 11) return errc::malformed_encoding;
  return {};
}

// CP-type and CPA-PPDU: SET { mode-selector [0], x410-mode-parameters [1], normal-mode-parameters
// [2] } in any order.
template <typename F>
result<void> walk_set(byte_view data, F&& normal) {
  reader top{data};
  auto set = top.enter(tags::set);
  if (!set) return set.error();
  if (auto r = top.expect_end(); !r) return r;
  bool mode_seen = false;
  bool normal_seen = false;
  while (!set->empty()) {
    auto e = set->next();
    if (!e) return e.error();
    if (e->tag.same_id(context(0))) {
      if (mode_seen) return errc::malformed_encoding;
      mode_seen = true;
      if (auto r = read_mode(*set, *e); !r) return r;
    } else if (e->tag.same_id(context(1))) {
      return errc::unsupported;  // x410-mode-parameters
    } else if (e->tag.same_id(context(2))) {
      if (normal_seen) return errc::malformed_encoding;
      normal_seen = true;
      auto params = set->enter(*e);
      if (!params) return params.error();
      if (auto r = normal(*params); !r) return r;
    } else {
      return errc::malformed_encoding;
    }
  }
  if (!mode_seen) return errc::malformed_encoding;
  return {};
}

// ---------------------------------------------------------------------------------------------
// Encoding

void write_bits(ber::writer& w, std::uint32_t mask, ber::tag t) {
  // Named bit lists are encoded without trailing zero bits (X.680 §22.7, X.690 §11.2.2).
  std::size_t count = 0;
  for (std::size_t i = 0; i < 32; ++i) {
    if (((mask >> i) & 1U) != 0) count = i + 1;
  }
  std::array<std::uint8_t, 4> bytes{};
  for (std::size_t i = 0; i < count; ++i) {
    if (((mask >> i) & 1U) != 0) bytes[i / 8] |= static_cast<std::uint8_t>(0x80U >> (i % 8));
  }
  (void)w.write_bit_string(byte_view{bytes.data(), (count + 7) / 8}, count, t);
}

void write_mode(ber::writer& w) {
  const auto m = w.begin(context(0, true));
  w.write_integer(mode::normal, context(0));
  w.end(m);
}

result<void> write_user_data(ber::writer& w, std::span<const pdv> pdvs) {
  if (pdvs.empty()) return errc::malformed_encoding;
  const auto list = w.begin(user_data_tag);
  for (const auto& p : pdvs) {
    if (p.context_id == 0) return errc::malformed_encoding;
    const auto item = w.begin(tags::sequence);
    if (p.transfer_syntax) {
      if (auto r = w.write_oid(*p.transfer_syntax); !r) return r;
    }
    w.write_unsigned(p.context_id);
    switch (p.encoding) {
      case pdv_encoding::single_asn1_type:
        w.write_tlv(context(0, true), p.data);
        break;
      case pdv_encoding::octet_aligned:
        w.write_octet_string(p.data, context(1));
        break;
      case pdv_encoding::arbitrary: {
        if (p.unused_bits > 7 || (p.data.empty() && p.unused_bits != 0)) {
          return errc::malformed_encoding;
        }
        const std::size_t bits = p.data.size() * 8 - p.unused_bits;
        if (auto r = w.write_bit_string(p.data, bits, context(2)); !r) return r;
        break;
      }
    }
    w.end(item);
  }
  w.end(list);
  return {};
}

result<void> write_result_list(ber::writer& w, const std::vector<context_result>& results) {
  if (results.empty()) return {};
  const auto list = w.begin(context(5, true));
  for (const auto& c : results) {
    const auto item = w.begin(tags::sequence);
    w.write_integer(static_cast<std::int64_t>(c.result), context(0));
    if (c.transfer_syntax) {
      if (auto r = w.write_oid(*c.transfer_syntax, context(1)); !r) return r;
    }
    if (c.provider_reason) w.write_unsigned(*c.provider_reason, context(2));
    w.end(item);
  }
  w.end(list);
  return {};
}

// Runs `body` on a writer appending to `out`, and truncates `out` back on failure.
template <typename F>
result<void> encode_into(byte_buffer& out, F&& body) {
  const std::size_t start = out.size();
  ber::writer w{out};
  result<void> r = body(w);
  if (!r) out.resize(start);
  return r;
}

}  // namespace

result<connect_ppdu> decode_connect(byte_view data) {
  connect_ppdu p;
  auto r = walk_set(data, [&](reader params) {
    return walk_parameters(params, p.user_data, [&](const reader& rd, const tlv& e) -> result<void> {
      switch (e.tag.number) {
        case 0: return read_bits_into(e, p.protocol_version);
        case 1: return read_selector(e, p.calling_selector);
        case 2: return read_selector(e, p.called_selector);
        case 4: return read_context_list(rd, e, p.contexts);
        case 6: {
          auto seq = rd.enter(e);
          if (!seq) return seq.error();
          auto as = seq->read_oid(context(0));
          if (!as) return as.error();
          auto ts = seq->read_oid(context(1));
          if (!ts) return ts.error();
          if (auto end = seq->expect_end(); !end) return end;
          p.default_context = default_context_name{*as, *ts};
          return {};
        }
        case 8: return read_bits_into(e, p.presentation_requirements);
        case 9: return read_bits_into(e, p.user_session_requirements);
        default: return skip_extension(e);
      }
    });
  });
  if (!r) return r.error();
  return p;
}

result<accept_ppdu> decode_accept(byte_view data) {
  accept_ppdu p;
  auto r = walk_set(data, [&](reader params) {
    return walk_parameters(params, p.user_data, [&](const reader& rd, const tlv& e) -> result<void> {
      switch (e.tag.number) {
        case 0: return read_bits_into(e, p.protocol_version);
        case 3: return read_selector(e, p.responding_selector);
        case 5: return read_result_list(rd, e, p.results);
        case 8: return read_bits_into(e, p.presentation_requirements);
        case 9: return read_bits_into(e, p.user_session_requirements);
        default: return skip_extension(e);
      }
    });
  });
  if (!r) return r.error();
  return p;
}

result<refuse_ppdu> decode_refuse(byte_view data) {
  refuse_ppdu p;
  reader top{data};
  auto first = top.peek_tag();
  if (!first) return first.error();
  if (*first == tags::set) return errc::unsupported;  // x400-mode-parameters
  auto params = top.enter(tags::sequence);
  if (!params) return params.error();
  if (auto end = top.expect_end(); !end) return end.error();
  auto r = walk_parameters(*params, p.user_data, [&](const reader& rd, const tlv& e) -> result<void> {
    switch (e.tag.number) {
      case 0: return read_bits_into(e, p.protocol_version);
      case 3: return read_selector(e, p.responding_selector);
      case 5: return read_result_list(rd, e, p.results);
      case 7: {
        auto v = result_code_of(e);
        if (!v) return v.error();
        p.default_context_result = *v;
        return {};
      }
      case 10: {
        auto v = u8_of(e);
        if (!v) return v.error();
        p.provider_reason = *v;
        return {};
      }
      default: return skip_extension(e);
    }
  });
  if (!r) return r.error();
  return p;
}

result<abort_ppdu> decode_abort(byte_view data) {
  reader top{data};
  auto first = top.peek_tag();
  if (!first) return first.error();

  if (*first == tags::sequence) {  // ARP-PPDU
    provider_abort_ppdu p;
    auto seq = top.enter(tags::sequence);
    if (!seq) return seq.error();
    if (seq->next_is(context(0))) {
      auto e = seq->expect(context(0));
      if (!e) return e.error();
      auto v = u8_of(*e);
      if (!v) return v.error();
      p.reason = *v;
    }
    if (seq->next_is(context(1))) {
      auto e = seq->expect(context(1));
      if (!e) return e.error();
      auto v = u8_of(*e);
      if (!v) return v.error();
      p.event = *v;
    }
    if (auto r = seq->expect_end(); !r) return r.error();
    if (auto r = top.expect_end(); !r) return r.error();
    return abort_ppdu{p};
  }
  if (*first == tags::set) return errc::unsupported;  // x400-mode-parameters (RTABapdu)
  if (*first != context(0, true)) return errc::malformed_encoding;

  user_abort_ppdu p;
  auto seq = top.enter(context(0, true));
  if (!seq) return seq.error();
  if (auto r = top.expect_end(); !r) return r.error();
  if (seq->next_is(context(0, true))) {
    auto list = seq->enter(context(0, true));
    if (!list) return list.error();
    while (!list->empty()) {
      auto item = list->enter(tags::sequence);
      if (!item) return item.error();
      context_identifier c;
      auto id = read_context_id(*item);
      if (!id) return id.error();
      c.id = *id;
      auto ts = item->read_oid();
      if (!ts) return ts.error();
      c.transfer_syntax = *ts;
      if (auto r = item->expect_end(); !r) return r.error();
      p.context_ids.push_back(c);
    }
  }
  if (!seq->empty()) {
    auto e = seq->next();
    if (!e) return e.error();
    if (auto r = read_user_data(*seq, *e, p.user_data); !r) return r.error();
    if (auto r = seq->expect_end(); !r) return r.error();
  }
  return abort_ppdu{std::move(p)};
}

result<void> decode_user_data(byte_view data, std::vector<pdv>& out) {
  out.clear();
  reader top{data};
  auto e = top.next();
  if (!e) return e.error();
  if (auto r = top.expect_end(); !r) return r;
  if (auto r = read_user_data(top, *e, out); !r) {
    out.clear();
    return r;
  }
  return {};
}

result<void> encode(const connect_ppdu& p, byte_buffer& out) {
  return encode_into(out, [&](ber::writer& w) -> result<void> {
    const auto set = w.begin(tags::set);
    write_mode(w);
    const auto params = w.begin(context(2, true));
    if (p.protocol_version) write_bits(w, *p.protocol_version, context(0));
    if (!p.calling_selector.empty()) w.write_octet_string(p.calling_selector, context(1));
    if (!p.called_selector.empty()) w.write_octet_string(p.called_selector, context(2));
    if (!p.contexts.empty()) {
      const auto list = w.begin(context(4, true));
      for (const auto& d : p.contexts) {
        if (d.id == 0 || d.transfer_syntaxes.empty()) return errc::malformed_encoding;
        const auto item = w.begin(tags::sequence);
        w.write_unsigned(d.id);
        if (auto r = w.write_oid(d.abstract_syntax); !r) return r;
        const auto ts_list = w.begin(tags::sequence);
        for (const auto& ts : d.transfer_syntaxes) {
          if (auto r = w.write_oid(ts); !r) return r;
        }
        w.end(ts_list);
        w.end(item);
      }
      w.end(list);
    }
    if (p.default_context) {
      const auto seq = w.begin(context(6, true));
      if (auto r = w.write_oid(p.default_context->abstract_syntax, context(0)); !r) return r;
      if (auto r = w.write_oid(p.default_context->transfer_syntax, context(1)); !r) return r;
      w.end(seq);
    }
    if (p.presentation_requirements) write_bits(w, *p.presentation_requirements, context(8));
    if (p.user_session_requirements) write_bits(w, *p.user_session_requirements, context(9));
    if (!p.user_data.empty()) {
      if (auto r = write_user_data(w, p.user_data); !r) return r;
    }
    w.end(params);
    w.end(set);
    return {};
  });
}

result<void> encode(const accept_ppdu& p, byte_buffer& out) {
  return encode_into(out, [&](ber::writer& w) -> result<void> {
    const auto set = w.begin(tags::set);
    write_mode(w);
    const auto params = w.begin(context(2, true));
    if (p.protocol_version) write_bits(w, *p.protocol_version, context(0));
    if (!p.responding_selector.empty()) w.write_octet_string(p.responding_selector, context(3));
    if (auto r = write_result_list(w, p.results); !r) return r;
    if (p.presentation_requirements) write_bits(w, *p.presentation_requirements, context(8));
    if (p.user_session_requirements) write_bits(w, *p.user_session_requirements, context(9));
    if (!p.user_data.empty()) {
      if (auto r = write_user_data(w, p.user_data); !r) return r;
    }
    w.end(params);
    w.end(set);
    return {};
  });
}

result<void> encode(const refuse_ppdu& p, byte_buffer& out) {
  return encode_into(out, [&](ber::writer& w) -> result<void> {
    const auto seq = w.begin(tags::sequence);
    if (p.protocol_version) write_bits(w, *p.protocol_version, context(0));
    if (!p.responding_selector.empty()) w.write_octet_string(p.responding_selector, context(3));
    if (auto r = write_result_list(w, p.results); !r) return r;
    if (p.default_context_result) {
      w.write_integer(static_cast<std::int64_t>(*p.default_context_result), context(7));
    }
    if (p.provider_reason) w.write_unsigned(*p.provider_reason, context(10));
    if (!p.user_data.empty()) {
      if (auto r = write_user_data(w, p.user_data); !r) return r;
    }
    w.end(seq);
    return {};
  });
}

result<void> encode(const user_abort_ppdu& p, byte_buffer& out) {
  return encode_into(out, [&](ber::writer& w) -> result<void> {
    const auto seq = w.begin(context(0, true));
    if (!p.context_ids.empty()) {
      const auto list = w.begin(context(0, true));
      for (const auto& c : p.context_ids) {
        if (c.id == 0) return errc::malformed_encoding;
        const auto item = w.begin(tags::sequence);
        w.write_unsigned(c.id);
        if (auto r = w.write_oid(c.transfer_syntax); !r) return r;
        w.end(item);
      }
      w.end(list);
    }
    if (!p.user_data.empty()) {
      if (auto r = write_user_data(w, p.user_data); !r) return r;
    }
    w.end(seq);
    return {};
  });
}

result<void> encode(const provider_abort_ppdu& p, byte_buffer& out) {
  return encode_into(out, [&](ber::writer& w) -> result<void> {
    const auto seq = w.begin(tags::sequence);
    if (p.reason) w.write_unsigned(*p.reason, context(0));
    if (p.event) w.write_unsigned(*p.event, context(1));
    w.end(seq);
    return {};
  });
}

result<void> encode_user_data(std::span<const pdv> pdvs, byte_buffer& out) {
  return encode_into(out, [&](ber::writer& w) { return write_user_data(w, pdvs); });
}

}  // namespace openiec61850::iso::presentation
