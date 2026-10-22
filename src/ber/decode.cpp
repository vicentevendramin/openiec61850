#include "openiec61850/ber/decode.hpp"

#include <limits>

namespace openiec61850::ber {
namespace {

constexpr std::uint64_t max_tag_number = std::numeric_limits<std::uint32_t>::max();

struct identifier {
  ber::tag tag;
  std::size_t size;
};

struct header {
  ber::tag tag;
  std::size_t size;  // identifier + length octets
  bool indefinite;
  std::size_t length;
};

// X.690 §8.1.2
result<identifier> parse_identifier(byte_view d) noexcept {
  if (d.empty()) return errc::truncated_input;
  const std::uint8_t first = d[0];
  ber::tag t{static_cast<tag_class>(first >> 6), (first & 0x20U) != 0, first & 0x1FU};
  if (t.number != 0x1F) return identifier{t, 1};

  // High-tag-number form, §8.1.2.4
  std::uint64_t number = 0;
  std::size_t pos = 1;
  for (;;) {
    if (pos >= d.size()) return errc::truncated_input;
    const std::uint8_t b = d[pos++];
    if (pos == 2 && b == 0x80) return errc::malformed_encoding;  // §8.1.2.4.2 c
    number = (number << 7) | (b & 0x7FU);
    if (number > max_tag_number) return errc::unsupported;
    if ((b & 0x80U) == 0) break;
  }
  if (number < 31) return errc::malformed_encoding;  // §8.1.2.2: must use the low form
  t.number = static_cast<std::uint32_t>(number);
  return identifier{t, pos};
}

// X.690 §8.1.3
result<header> parse_header(byte_view d) noexcept {
  const auto id = parse_identifier(d);
  if (!id) return id.error();
  std::size_t pos = id->size;
  if (pos >= d.size()) return errc::truncated_input;
  const std::uint8_t first = d[pos++];
  header h{id->tag, 0, false, 0};
  if (first < 0x80) {
    h.length = first;
  } else if (first == 0x80) {
    if (!h.tag.constructed) return errc::malformed_encoding;  // §8.1.3.2 a
    h.indefinite = true;
  } else if (first == 0xFF) {
    return errc::malformed_encoding;  // §8.1.3.5 c
  } else {
    const std::size_t n = first & 0x7FU;
    if (n > d.size() - pos) return errc::truncated_input;
    std::size_t length = 0;
    for (std::size_t i = 0; i < n; ++i) {
      // Leading zero octets are allowed in BER and simply keep `length` at zero.
      if (length > (std::numeric_limits<std::size_t>::max() >> 8)) return errc::length_overflow;
      length = (length << 8) | d[pos + i];
    }
    pos += n;
    h.length = length;
  }
  h.size = pos;
  return h;
}

bool is_universal_zero(ber::tag t) noexcept {
  return t.cls == tag_class::universal && t.number == 0;
}

// Returns the offset just past the end-of-contents that closes the indefinite-length element
// whose header occupies d[0, header_size). Iterative, so the stack does not grow with nesting.
result<std::size_t> scan_indefinite(byte_view d, std::size_t header_size,
                                    const decode_options& opts, std::size_t depth) noexcept {
  std::size_t open = 1;
  if (depth + open > opts.max_depth) return errc::nesting_too_deep;
  std::size_t pos = header_size;
  for (;;) {
    const byte_view rest = d.subspan(pos);
    if (rest.empty()) return errc::truncated_input;
    const auto h = parse_header(rest);
    if (!h) return h.error();
    if (is_universal_zero(h->tag)) {
      // §8.1.5: end-of-contents is exactly two zero octets.
      if (h->tag.constructed || h->indefinite || h->length != 0 || h->size != 2) {
        return errc::malformed_encoding;
      }
      pos += 2;
      if (--open == 0) return pos;
      continue;
    }
    if (h->indefinite) {
      ++open;
      if (depth + open > opts.max_depth) return errc::nesting_too_deep;
      pos += h->size;
      continue;
    }
    if (h->length > rest.size() - h->size) return errc::length_overflow;
    pos += h->size + h->length;
  }
}

result<void> require_primitive(const tlv& e) noexcept {
  if (e.tag.constructed) return errc::malformed_encoding;
  return {};
}

// §8.6.1, §8.7.1, §8.23.1: these may be segmented into a constructed encoding.
result<void> require_unsegmented(const tlv& e) noexcept {
  if (e.tag.constructed) return errc::unsupported;
  return {};
}

std::string_view as_chars(byte_view v) noexcept {
  return {reinterpret_cast<const char*>(v.data()), v.size()};
}

// §8.3.2: the first nine bits shall not be all ones or all zeros.
bool non_minimal_integer(byte_view c) noexcept {
  if (c.size() < 2) return false;
  return (c[0] == 0x00 && (c[1] & 0x80U) == 0) || (c[0] == 0xFF && (c[1] & 0x80U) != 0);
}

template <typename T, typename F>
result<T> with_primitive(const tlv& e, F decode) noexcept {
  if (auto r = require_primitive(e); !r) return r.error();
  return decode(e.value);
}

template <typename T, typename F>
result<T> with_unsegmented(const tlv& e, F decode) noexcept {
  if (auto r = require_unsegmented(e); !r) return r.error();
  return decode(e.value);
}

}  // namespace

result<tag> decode_tag(byte_view data) noexcept {
  const auto id = parse_identifier(data);
  if (!id) return id.error();
  return id->tag;
}

result<tlv> decode_tlv(byte_view data, const decode_options& opts, std::size_t depth) noexcept {
  const auto h = parse_header(data);
  if (!h) return h.error();
  // UNIVERSAL 0 is reserved for end-of-contents (X.680 §8.6), which never starts an element.
  if (is_universal_zero(h->tag)) return errc::malformed_encoding;
  if (!h->indefinite) {
    if (h->length > data.size() - h->size) return errc::length_overflow;
    return tlv{h->tag, data.subspan(h->size, h->length), data.first(h->size + h->length), false};
  }
  const auto end = scan_indefinite(data, h->size, opts, depth);
  if (!end) return end.error();
  return tlv{h->tag, data.subspan(h->size, *end - h->size - 2), data.first(*end), true};
}

// §8.2
result<bool> decode_boolean(byte_view c) noexcept {
  if (c.size() != 1) return errc::malformed_encoding;
  return c[0] != 0;
}

// §8.3
result<std::int64_t> decode_integer(byte_view c) noexcept {
  if (c.empty() || non_minimal_integer(c)) return errc::malformed_encoding;
  if (c.size() > 8) return value_out_of_range;
  std::uint64_t v = (c[0] & 0x80U) != 0 ? ~std::uint64_t{0} : 0;
  for (const auto b : c) v = (v << 8) | b;
  return static_cast<std::int64_t>(v);
}

result<std::uint64_t> decode_unsigned(byte_view c) noexcept {
  if (c.empty() || non_minimal_integer(c)) return errc::malformed_encoding;
  if ((c[0] & 0x80U) != 0) return value_out_of_range;
  if (c.size() > 9 || (c.size() == 9 && c[0] != 0)) return value_out_of_range;
  std::uint64_t v = 0;
  for (const auto b : c) v = (v << 8) | b;
  return v;
}

// §8.4
result<std::int64_t> decode_enumerated(byte_view c) noexcept { return decode_integer(c); }

// §8.8
result<void> decode_null(byte_view c) noexcept {
  if (!c.empty()) return errc::malformed_encoding;
  return {};
}

// §8.6.2
result<bit_string_view> decode_bit_string(byte_view c) noexcept {
  if (c.empty()) return errc::malformed_encoding;
  const std::uint8_t unused = c[0];
  if (unused > 7) return errc::malformed_encoding;
  if (c.size() == 1 && unused != 0) return errc::malformed_encoding;  // §8.6.2.3
  const byte_view bytes = c.subspan(1);
  return bit_string_view{bytes, bytes.size() * 8 - unused};
}

// §8.7
result<byte_view> decode_octet_string(byte_view c) noexcept { return c; }

// §8.19
result<oid> decode_oid(byte_view c) noexcept {
  if (c.empty()) return errc::malformed_encoding;
  oid out;
  std::size_t pos = 0;
  bool first = true;
  while (pos < c.size()) {
    if (c[pos] == 0x80) return errc::malformed_encoding;  // §8.19.2: no leading 0x80 octet
    // The first subidentifier combines two arcs (§8.19.4), so it may exceed 32 bits by 80.
    const std::uint64_t limit = first ? max_tag_number + 80 : max_tag_number;
    std::uint64_t v = 0;
    for (;;) {
      if (pos >= c.size()) return errc::malformed_encoding;  // last octet had bit 8 set
      const std::uint8_t b = c[pos++];
      v = (v << 7) | (b & 0x7FU);
      if (v > limit) return errc::unsupported;
      if ((b & 0x80U) == 0) break;
    }
    if (first) {
      const std::uint32_t root = v < 40 ? 0U : (v < 80 ? 1U : 2U);
      out.push_back(root);
      out.push_back(static_cast<std::uint32_t>(v - root * 40U));
      first = false;
    } else if (!out.push_back(static_cast<std::uint32_t>(v))) {
      return errc::unsupported;
    }
  }
  return out;
}

result<std::string_view> decode_visible_string(byte_view c) noexcept { return as_chars(c); }
result<std::string_view> decode_utf8_string(byte_view c) noexcept { return as_chars(c); }
result<std::string_view> decode_generalized_time(byte_view c) noexcept { return as_chars(c); }

result<bool> decode_boolean(const tlv& e) noexcept {
  return with_primitive<bool>(e, [](byte_view c) { return decode_boolean(c); });
}
result<std::int64_t> decode_integer(const tlv& e) noexcept {
  return with_primitive<std::int64_t>(e, [](byte_view c) { return decode_integer(c); });
}
result<std::uint64_t> decode_unsigned(const tlv& e) noexcept {
  return with_primitive<std::uint64_t>(e, [](byte_view c) { return decode_unsigned(c); });
}
result<std::int64_t> decode_enumerated(const tlv& e) noexcept {
  return with_primitive<std::int64_t>(e, [](byte_view c) { return decode_enumerated(c); });
}
result<void> decode_null(const tlv& e) noexcept {
  return with_primitive<void>(e, [](byte_view c) { return decode_null(c); });
}
result<bit_string_view> decode_bit_string(const tlv& e) noexcept {
  return with_unsegmented<bit_string_view>(e, [](byte_view c) { return decode_bit_string(c); });
}
result<byte_view> decode_octet_string(const tlv& e) noexcept {
  return with_unsegmented<byte_view>(e, [](byte_view c) { return decode_octet_string(c); });
}
result<oid> decode_oid(const tlv& e) noexcept {
  return with_primitive<oid>(e, [](byte_view c) { return decode_oid(c); });
}
result<std::string_view> decode_visible_string(const tlv& e) noexcept {
  return with_unsegmented<std::string_view>(e,
                                            [](byte_view c) { return decode_visible_string(c); });
}
result<std::string_view> decode_utf8_string(const tlv& e) noexcept {
  return with_unsegmented<std::string_view>(e, [](byte_view c) { return decode_utf8_string(c); });
}
result<std::string_view> decode_generalized_time(const tlv& e) noexcept {
  return with_unsegmented<std::string_view>(
      e, [](byte_view c) { return decode_generalized_time(c); });
}

}  // namespace openiec61850::ber
